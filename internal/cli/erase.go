package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// defaultErasureReason is recorded in the chain when the operator gives no
// reason of their own. Destroying content always names a cause, the same way
// deleting a segment does.
const defaultErasureReason = "erasure request under GDPR Article 17"

// Erase destroys the stored content of a session by destroying the keys that
// decrypt it, and appends a record of having done so.
//
// The records themselves are not touched. That is the point: the chain hashes
// each event as the bytes that were written, so rewriting a record to remove
// text would break every hash after it and leave a log that no longer verifies,
// which is exactly the evidence Article 19 asks an operator to keep. Erasing
// the key leaves the chain intact and makes the text unreadable, and the
// erasure itself becomes another record in the same chain.
func Erase(args []string) error {
	fs := flag.NewFlagSet("erase", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber erase [flags]

Destroys the stored prompts and completions of one session by destroying the
content-encryption keys that decrypt them. Without --confirm it says exactly
what would be destroyed and changes nothing.

  flugschreiber erase --dir DIR --session S              what would be destroyed
  flugschreiber erase --dir DIR --session S --confirm    destroy it
  flugschreiber erase --dir DIR --request-id R --confirm destroy one record's key

No record is rewritten and no segment is deleted, so the hash chain is
untouched and still verifies afterwards. The sha256 and byte count of each
request and response stay in the log; with the content destroyed they are a
claim about bytes nobody can produce again rather than a digest anyone can
re-check.

The erasure is appended to the chain as a system_event naming what was
destroyed, when, and on whose request, so the log documents its own erasures
instead of quietly having fewer readable records than it used to.

This reaches only content written while content encryption was on. Records
captured before that hold their text in the clear and no key destroys it; the
command counts them and says so, along with any key a matching record names
that this keystore does not hold. Stop the server first: appending to the chain
and rewriting the keystore are both single-writer operations, and a running
server puts the keys it holds in memory back when it issues the next one.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "evidence directory (or FLUGSCHREIBER_DATA_DIR)")
		session   = fs.String("session", "", "session id whose content is to be destroyed")
		requestID = fs.String("request-id", "", "request id whose content is to be destroyed")
		requester = fs.String("requester", "", "who asked for the erasure, recorded in the chain")
		reason    = fs.String("reason", defaultErasureReason, "why, recorded in the chain")
		keystore  = fs.String("keystore", "", "content keystore path (default DIR/"+evidence.ContentKeystoreFile+")")
		confirm   = fs.Bool("confirm", false, "carry out the erasure; it cannot be undone")
		asJSON    = fs.Bool("json", false, "emit the result as JSON")
	)
	fs.StringVar(requestID, "request", "", "alias of --request-id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "erase", dir); err != nil {
		return err
	}
	if *session == "" && *requestID == "" {
		fs.Usage()
		return errors.New("erase: one of --session or --request-id is required; this command never erases everything")
	}
	if *session != "" && *requestID != "" {
		return errors.New("erase: --session and --request-id are mutually exclusive")
	}

	hold, err := evidence.ReadLegalHold(*dir)
	if err != nil {
		return err
	}
	if hold.InForce {
		return fmt.Errorf(
			"erase: a legal hold is in force and requires this content to be kept: %s\n"+
				"       lift it first with: flugschreiber retention --dir %s --release-hold",
			strings.TrimSpace(hold.Reason), *dir)
	}

	path := *keystore
	if path == "" {
		path = evidence.ContentKeystorePath(*dir)
	}
	// A writer that is running holds the whole keystore in memory and rewrites
	// the file every time it issues a key, so an erasure carried out beside it
	// is undone by the next request it records. The keystore's own directory is
	// checked as well as --dir, because a keystore under some other evidence
	// directory belongs to whatever is writing there.
	if *confirm {
		if err := refuseWhileAWriterHolds(*dir, path); err != nil {
			return err
		}
	}

	ks, err := openKeystoreForErasure(path)
	if err != nil {
		return fmt.Errorf("erase: %w", err)
	}

	scan, err := scanForErasure(*dir, *session, *requestID)
	if err != nil {
		return err
	}

	// With no keystore there is nothing to destroy, and every key the records
	// name is one this run cannot reach. Saying that is the whole job here;
	// creating a keystore instead would leave a fresh master key in an evidence
	// directory that had none.
	res := &evidence.ContentErasureResult{
		Keystore:  path,
		DryRun:    !*confirm,
		SessionID: *session,
		Unknown:   scan.keyIDs(),
	}
	if ks != nil {
		res, err = ks.Erase(evidence.ContentErasureRequest{
			// Only an explicit --session widens the erasure to a whole session.
			// Selecting by request id destroys the keys those records name and
			// nothing else, even though a session key takes the rest of its
			// session with it, which the output states before it happens.
			SessionID: *session,
			KeyIDs:    scan.keyIDs(),
			Requester: *requester,
			Reason:    *reason,
			DryRun:    !*confirm,
		})
		if err != nil {
			return fmt.Errorf("erase: %w", err)
		}
	}

	out := eraseReport{
		Dir:             *dir,
		Keystore:        path,
		KeystoreMissing: ks == nil,
		SessionID:       firstNonEmpty(*session, scan.session),
		RequestID:       *requestID,
		Requester:       *requester,
		Reason:          *reason,
		Confirmed:       *confirm,
		Destroyed:       res.Destroyed,
		AlreadyErased:   res.AlreadyErased,
		Unknown:         res.Unknown,
		Keys:            scan.usageFor(res),
		Plaintext:       scan.plaintext,
		NoContent:       scan.noContent,
	}

	if *confirm && len(res.Pending) > 0 {
		seq, verified, err := recordErasure(*dir, &out, res)
		if err != nil {
			return fmt.Errorf(
				"erase: the keys were destroyed and the content is gone, but the system_event recording it could not be appended: %w\n"+
					"       run the same command again to append it; the destruction is not repeated",
				err)
		}
		out.RecordSeq = seq
		out.ChainVerified = verified
		if err := ks.MarkRecorded(pendingKeyIDs(res)); err != nil {
			return fmt.Errorf(
				"erase: the erasure is recorded in the chain at seq %d but %s could not be updated to say so: %w",
				seq, path, err)
		}
	}

	if *asJSON {
		return emitJSON(out)
	}
	printErasure(out)
	return nil
}

// eraseReport is the whole result of one run. It carries no key material: the
// keystore hands out ids and dates, never wrapped keys, so --json is safe to
// paste into a ticket about the erasure request.
type eraseReport struct {
	Dir      string `json:"dir"`
	Keystore string `json:"keystore"`

	// KeystoreMissing says there is no keystore at all where one was expected,
	// which reads very differently from a keystore that holds none of the keys
	// these records name.
	KeystoreMissing bool `json:"keystore_missing,omitempty"`

	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Requester string `json:"requester,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Confirmed bool   `json:"confirmed"`

	Destroyed     []evidence.ContentKeyInfo   `json:"destroyed,omitempty"`
	AlreadyErased []evidence.ErasedContentKey `json:"already_erased,omitempty"`
	Unknown       []string                    `json:"unknown_key_ids,omitempty"`

	// Keys reports how much of the log each key covers, which is the number
	// that matters before anything is destroyed: a session key erased for one
	// request takes every other record of that session with it.
	Keys []contentKeyUsage `json:"keys,omitempty"`

	// Plaintext counts matching records whose text is under no key at all, and
	// which this command therefore cannot destroy.
	Plaintext int `json:"plaintext_records,omitempty"`

	// NoContent counts matching records that never held text, which is every
	// record in the default hash mode.
	NoContent int `json:"records_without_content,omitempty"`

	// RecordSeq is where the chain documents this erasure, and ChainVerified
	// is the state of the chain immediately afterwards. Both are zero and
	// false when nothing was destroyed and nothing was appended.
	RecordSeq     uint64 `json:"record_seq,omitempty"`
	ChainVerified bool   `json:"chain_verified_after_erasure,omitempty"`
}

// contentKeyUsage is one content key and the part of the log it covers.
type contentKeyUsage struct {
	KeyID   string `json:"key_id"`
	Records int    `json:"records"`
	First   string `json:"first,omitempty"`
	Last    string `json:"last,omitempty"`

	// Sessions lists every session whose records used this key. More than one
	// would mean key issuance had gone wrong, and an operator about to destroy
	// it should see that before they do rather than after.
	Sessions []string `json:"sessions,omitempty"`
}

// openKeystoreForErasure opens an existing keystore and never creates one.
//
// There is nothing to erase in a directory that was never written with content
// encryption, and a command that changes nothing without --confirm must not
// leave a fresh master key behind in one. A missing keystore is reported, not
// repaired: whoever ran this either has the wrong path or the wrong directory.
func openKeystoreForErasure(path string) (*evidence.ContentKeystore, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return evidence.OpenContentKeystore(path)
}

func refuseWhileAWriterHolds(dir, keystorePath string) error {
	dirs := []string{filepath.Clean(dir)}
	if ksDir := filepath.Clean(filepath.Dir(keystorePath)); ksDir != dirs[0] {
		dirs = append(dirs, ksDir)
	}
	for _, d := range dirs {
		if lock := evidence.ReadWriterLock(d); lock != nil {
			return fmt.Errorf(
				"erase: refusing to erase while %s holds %s: an erasure appends to the chain and rewrites the keystore, and one writer is the whole ordering guarantee; stop the server first",
				lock, d)
		}
	}
	return nil
}

// eraseScan is what one pass over the log found out about a selector.
type eraseScan struct {
	session   string
	targeted  map[string]bool
	usage     map[string]*contentKeyUsage
	plaintext int
	noContent int
}

// scanForErasure reads the log once and works out which content keys the
// selector names and how much of the log each of them covers.
//
// The log is the authority on which records used which key, not the keystore.
// The keystore knows which keys exist; only the records say what was sealed
// under them, and the number an operator has to see before they destroy
// anything is how many records go dark.
func scanForErasure(dir, sessionID, requestID string) (*eraseScan, error) {
	scan := &eraseScan{
		session:  sessionID,
		targeted: map[string]bool{},
		usage:    map[string]*contentKeyUsage{},
	}

	err := evidence.Walk(dir, func(e evidence.Entry) error {
		ev := e.Event
		selected := (sessionID != "" && ev.SessionID == sessionID) ||
			(requestID != "" && ev.RequestID == requestID)

		if ev.Content != nil && ev.Content.Encryption != nil {
			id := ev.Content.Encryption.KeyID
			u := scan.usage[id]
			if u == nil {
				u = &contentKeyUsage{KeyID: id, First: e.Record.Timestamp}
				scan.usage[id] = u
			}
			u.Records++
			u.Last = e.Record.Timestamp
			if ev.SessionID != "" && !listHas(u.Sessions, ev.SessionID) {
				u.Sessions = append(u.Sessions, ev.SessionID)
			}
			if selected {
				scan.targeted[id] = true
				if scan.session == "" {
					scan.session = ev.SessionID
				}
			}
			return nil
		}

		if !selected {
			return nil
		}
		if recordHoldsText(ev) {
			scan.plaintext++
			return nil
		}
		scan.noContent++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("erase: read %s: %w", dir, err)
	}
	return scan, nil
}

func (s *eraseScan) keyIDs() []string {
	out := make([]string, 0, len(s.targeted))
	for id := range s.targeted {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// usageFor reports the coverage of every key the erasure touched, including
// keys an earlier run destroyed, so that the "already erased" case still says
// how much of the log is dark.
func (s *eraseScan) usageFor(res *evidence.ContentErasureResult) []contentKeyUsage {
	seen := map[string]bool{}
	var out []contentKeyUsage
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		if u := s.usage[id]; u != nil {
			out = append(out, *u)
			return
		}
		out = append(out, contentKeyUsage{KeyID: id})
	}
	for _, k := range res.Destroyed {
		add(k.KeyID)
	}
	for _, k := range res.AlreadyErased {
		add(k.KeyID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

// recordHoldsText reports whether an event carries text that no key covers.
// Tool arguments and tool results count: they carry what the caller sent as
// surely as a prompt does.
func recordHoldsText(ev evidence.Event) bool {
	if ev.Content != nil {
		for _, p := range []*evidence.Payload{ev.Content.Input, ev.Content.Output} {
			if p != nil && (p.Text != "" || len(p.Messages) > 0) {
				return true
			}
		}
	}
	for _, tc := range ev.ToolCalls {
		if tc.Arguments != "" {
			return true
		}
	}
	for _, tr := range ev.ToolResults {
		if tr.Content != "" {
			return true
		}
	}
	return false
}

func listHas(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func pendingKeyIDs(res *evidence.ContentErasureResult) []string {
	out := make([]string, 0, len(res.Pending))
	for _, t := range res.Pending {
		out = append(out, t.KeyID)
	}
	return out
}

// recordErasure appends the system_event documenting the erasure, and returns
// its sequence number together with the state of the chain immediately after.
//
// It runs after the keys are gone, never before. An event claiming an erasure
// that then failed would be a lie in the chain, and the chain is the one thing
// here that must never say something that did not happen. A destruction the
// chain has not caught up with is recoverable instead: the keystore remembers
// which tombstones are unrecorded, and the next run appends the event for them.
func recordErasure(dir string, out *eraseReport, res *evidence.ContentErasureResult) (uint64, bool, error) {
	// Signing is best effort, as it is for a prune anchor: an unsigned erasure
	// record is still in the chain, and refusing to record the erasure because
	// no key is present would be the wrong trade.
	var keys *evidence.KeyPair
	if kp, err := evidence.LoadOrCreateKeyPair(dir); err == nil {
		keys = kp
	}
	store, err := evidence.Open(evidence.Options{Dir: dir, Keys: keys})
	if err != nil {
		return 0, false, err
	}

	appendErr := store.Append(&evidence.Event{
		EventType:    evidence.EventSystemEvent,
		RequestID:    "content-erasure-" + erasureSubject(out),
		SessionID:    out.SessionID,
		RefRequestID: out.RequestID,
		Actor:        out.Requester,
		Note:         erasureNote(out, res),
	})
	closeErr := store.Close()
	if appendErr != nil {
		return 0, false, appendErr
	}
	if closeErr != nil {
		return 0, false, closeErr
	}

	// Verifying here is the claim the command makes checked at the moment it
	// is made, rather than an assurance the operator has to take on trust.
	verified, err := evidence.Verify(dir)
	if err != nil {
		return 0, false, err
	}
	return verified.LastSeq, verified.OK(), nil
}

func erasureSubject(out *eraseReport) string {
	if out.RequestID != "" {
		return out.RequestID
	}
	return out.SessionID
}

// erasureNote is the sentence the chain carries about this erasure from now
// on. It says what was destroyed, how much of the log it covers, on whose
// request, and what the surviving digests are still worth, because whoever
// reads it will not have this command's output in front of them.
func erasureNote(out *eraseReport, res *evidence.ContentErasureResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "stored content erased: %d content key(s) destroyed", len(res.Pending))
	if out.SessionID != "" {
		fmt.Fprintf(&b, " for session %s", out.SessionID)
	}
	if out.RequestID != "" {
		fmt.Fprintf(&b, ", selected by request %s", out.RequestID)
	}
	fmt.Fprintf(&b, ", covering %d record(s)", erasureRecordCount(out))
	if first, last := erasureWindow(out); first != "" {
		fmt.Fprintf(&b, " between %s and %s", first, last)
	}
	if out.Requester != "" {
		fmt.Fprintf(&b, "; requested by %s", out.Requester)
	}
	if out.Reason != "" {
		fmt.Fprintf(&b, "; reason: %s", out.Reason)
	}
	b.WriteString(". The records are unchanged and the chain over them still verifies. ")

	// An erasure that reached only part of what was selected has to say so
	// here. This sentence is the only place a later reader, holding the log and
	// nothing else, can learn that the request was answered in part.
	var missed []string
	if out.Plaintext > 0 {
		missed = append(missed, fmt.Sprintf("%d record(s) hold text under no key", out.Plaintext))
	}
	if len(out.Unknown) > 0 {
		missed = append(missed, fmt.Sprintf("%d key id(s) named by matching records are not in this keystore", len(out.Unknown)))
	}
	if len(missed) > 0 {
		fmt.Fprintf(&b, "This erasure did not reach everything the selector matched: %s. ", strings.Join(missed, ", and "))
	}
	b.WriteString(evidence.ErasedDigestCaveat)
	return b.String()
}

func erasureRecordCount(out *eraseReport) int {
	n := 0
	for _, k := range out.Keys {
		n += k.Records
	}
	return n
}

func erasureWindow(out *eraseReport) (first, last string) {
	for _, k := range out.Keys {
		if k.First != "" && (first == "" || k.First < first) {
			first = k.First
		}
		if k.Last > last {
			last = k.Last
		}
	}
	return first, last
}

func printErasure(out eraseReport) {
	switch {
	case out.Confirmed && len(out.Destroyed) > 0:
		fmt.Printf("content erased\n\n")
	case out.RecordSeq > 0:
		fmt.Printf("erasure recorded in the chain\n\n")
	case len(out.Destroyed) > 0:
		fmt.Printf("erase plan (dry run, nothing has been destroyed)\n\n")
	default:
		fmt.Printf("erase\n\n")
	}

	fmt.Printf("  directory   %s\n", out.Dir)
	fmt.Printf("  keystore    %s\n", out.Keystore)
	if out.SessionID != "" {
		fmt.Printf("  session     %s\n", out.SessionID)
	}
	if out.RequestID != "" {
		fmt.Printf("  request     %s\n", out.RequestID)
	}
	if out.Confirmed && len(out.Destroyed) > 0 {
		if out.Requester != "" {
			fmt.Printf("  requester   %s\n", out.Requester)
		}
		fmt.Printf("  reason      %s\n", out.Reason)
	}

	printKeyCoverage(out)

	switch {
	case out.Confirmed && (len(out.Destroyed) > 0 || out.RecordSeq > 0):
		printErasureDone(out)
	case len(out.AlreadyErased) > 0 && len(out.Destroyed) == 0:
		fmt.Printf("\nThe content was already erased. Nothing was destroyed by this command\n")
		fmt.Printf("and nothing was appended to the chain.\n")
	case len(out.Destroyed) > 0:
		printErasurePlan(out)
	default:
		printNothingToErase()
	}

	// Both of these are printed whatever else happened. Content this command
	// could not reach is exactly what an operator must not learn about later,
	// and it is easiest to miss in the run that did destroy something and
	// therefore reads as a success.
	printUnknownKeys(out)
	printUnerasableText(out)
}

func printKeyCoverage(out eraseReport) {
	if len(out.Keys) == 0 {
		return
	}
	erasedAt := map[string]string{}
	for _, k := range out.AlreadyErased {
		erasedAt[k.KeyID] = k.ErasedAt
	}

	fmt.Printf("\n  %-34s %8s  %s\n", "content key", "records", "state")
	for _, k := range out.Keys {
		state := "readable"
		switch {
		case erasedAt[k.KeyID] != "":
			state = "erased " + erasedAt[k.KeyID]
		case out.Confirmed:
			state = "destroyed"
		}
		fmt.Printf("  %-34s %8d  %s\n", k.KeyID, k.Records, state)
		if k.First != "" {
			fmt.Printf("  %-34s %8s  %s to %s\n", "", "", k.First, k.Last)
		}
		if len(k.Sessions) > 1 {
			fmt.Printf("  %-34s %8s  covers sessions %s\n", "", "", strings.Join(k.Sessions, ", "))
		}
	}
}

func printErasureDone(out eraseReport) {
	if len(out.Destroyed) == 0 {
		// An earlier run destroyed the keys and could not append the record
		// that says so. This run finished the job, and must not report a
		// destruction it did not carry out.
		fmt.Printf("\n  destroyed   nothing; an earlier run had already destroyed these key(s)\n")
		fmt.Printf("              and could not append the record of it. That record is\n")
		fmt.Printf("              now in the chain.\n")
	} else {
		fmt.Printf("\n  destroyed   %d content key(s) covering %d record(s)\n",
			len(out.Destroyed), erasureRecordCount(&out))
	}
	if out.RecordSeq > 0 {
		fmt.Printf("  recorded    system_event at seq %d\n", out.RecordSeq)
	}
	if out.ChainVerified {
		fmt.Printf("  chain       verified intact after the erasure\n")
	} else {
		fmt.Printf("  chain       DID NOT VERIFY after the erasure; run verify and read the problems\n")
	}
	fmt.Printf("\nThe records and their digests are unchanged. To see for yourself:\n")
	fmt.Printf("  flugschreiber verify --dir %s\n", out.Dir)
}

func printErasurePlan(out eraseReport) {
	fmt.Printf("\nDestroying %d key(s) makes the stored prompts and completions of %d record(s)\n",
		len(out.Destroyed), erasureRecordCount(&out))
	fmt.Printf("permanently unreadable. The records themselves stay exactly as they were\n")
	fmt.Printf("written: nothing is rewritten, the hash chain is untouched, and an erasure\n")
	fmt.Printf("event is appended saying what was destroyed and on whose request.\n\n")
	fmt.Printf("%s\n\n", wrapParagraph(evidence.ErasedDigestCaveat, 74))
	fmt.Printf("This cannot be undone. There is no second copy of the key, no recovery\n")
	fmt.Printf("path and no support that gets the content back.\n\n")
	fmt.Printf("To carry it out:\n")
	fmt.Printf("  flugschreiber erase --dir %s%s --confirm\n", out.Dir, eraseSelectorFlag(out))
}

func printNothingToErase() {
	fmt.Printf("\nNothing to erase: no record matching this selector holds content under a\n")
	fmt.Printf("content-encryption key this keystore holds.\n")
}

// printUnknownKeys names the keys the selected records rely on that this
// keystore does not have.
//
// A run that destroys one key and cannot reach another has erased part of a
// session, and saying so is the difference between an operator answering an
// Article 17 request truthfully and answering it wrongly.
func printUnknownKeys(out eraseReport) {
	if len(out.Unknown) == 0 {
		return
	}
	fmt.Printf("\n  %d key id(s) named by matching records are not in this keystore, so\n", len(out.Unknown))
	fmt.Printf("  this command did not destroy them and the content under them is still\n")
	fmt.Printf("  readable to whoever holds them:\n")
	for _, id := range out.Unknown {
		fmt.Printf("    %s\n", id)
	}
	if out.KeystoreMissing {
		fmt.Printf("  There is no keystore at %s at all. Point --keystore at the file\n", out.Keystore)
		fmt.Printf("  that belongs with this log.\n")
		return
	}
	fmt.Printf("  Those records were written against a different keystore than %s.\n", out.Keystore)
	fmt.Printf("  Point --keystore at the file that belongs with this log.\n")
}

func printUnerasableText(out eraseReport) {
	if out.Plaintext == 0 {
		return
	}
	fmt.Printf("\n  %d matching record(s) hold text that is under no key.\n", out.Plaintext)
	fmt.Printf("  They were captured before content encryption was switched on, so this\n")
	fmt.Printf("  command cannot destroy their content. Removing that text means deleting\n")
	fmt.Printf("  the segments that hold it, under retention, which removes the records too.\n")
}

func eraseSelectorFlag(out eraseReport) string {
	if out.RequestID != "" {
		return " --request-id " + out.RequestID
	}
	return " --session " + out.SessionID
}

// wrapParagraph breaks text at word boundaries, so that a sentence shared by
// the chain, the documentation and this terminal output can be written once
// rather than reworded for each.
func wrapParagraph(s string, width int) string {
	var b strings.Builder
	line := 0
	for i, word := range strings.Fields(s) {
		switch {
		case i == 0:
			b.WriteString(word)
			line = len(word)
		case line+1+len(word) > width:
			b.WriteString("\n")
			b.WriteString(word)
			line = len(word)
		default:
			b.WriteString(" ")
			b.WriteString(word)
			line += 1 + len(word)
		}
	}
	return b.String()
}
