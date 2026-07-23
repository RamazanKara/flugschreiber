package cli

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/content"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

const (
	testPrompt = "my customer number is 4711 and my name is Alice Schmidt"
	testAnswer = "Thank you Alice, your order ships tomorrow."
)

// erasureFixture is an evidence directory holding real encrypted records,
// written through the same encryptor the proxy uses. Testing the command
// against hand-built ciphertext would prove only that the command can delete a
// line from a JSON file.
type erasureFixture struct {
	dir      string
	keystore *evidence.ContentKeystore
}

func newErasureFixture(t *testing.T) *erasureFixture {
	t.Helper()
	dir := t.TempDir()

	ks, err := evidence.OpenContentKeystore(evidence.ContentKeystorePath(dir))
	if err != nil {
		t.Fatalf("open keystore: %v", err)
	}
	enc := content.NewEncryptor(ks)

	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	f := &erasureFixture{dir: dir, keystore: ks}
	for _, req := range []string{"req-1", "req-2"} {
		if err := store.Append(encryptedEvent(t, enc, "sess-1", req)); err != nil {
			t.Fatal(err)
		}
	}
	// A second session, which no erasure of the first may touch.
	if err := store.Append(encryptedEvent(t, enc, "sess-2", "req-3")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

func encryptedEvent(t *testing.T, enc *content.Encryptor, session, request string) *evidence.Event {
	t.Helper()
	ev := &evidence.Event{
		EventType: evidence.EventInference,
		RequestID: request,
		SessionID: session,
		Status:    200,
		Content: &evidence.Content{
			Mode: evidence.ModeStore,
			Input: &evidence.Payload{
				SHA256:   "1111",
				Bytes:    len(testPrompt),
				Text:     testPrompt,
				Messages: []evidence.Message{{Role: "user", Content: testPrompt}},
			},
			Output: &evidence.Payload{SHA256: "2222", Bytes: len(testAnswer), Text: testAnswer},
		},
	}
	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// readable reports whether the stored content of a request can still be read.
//
// It opens the keystore afresh every time, which is what the next process sees:
// an erasure that only happened in one program's memory has erased nothing.
func (f *erasureFixture) readable(t *testing.T, requestID string) bool {
	t.Helper()
	ks, err := evidence.OpenContentKeystore(f.keystore.Path())
	if err != nil {
		t.Fatal(err)
	}
	ev := f.record(t, requestID)
	err = content.NewEncryptor(ks).DecryptEvent(ev)
	switch {
	case err == nil:
		if !strings.Contains(ev.Content.Input.Text, "Alice Schmidt") {
			t.Fatalf("request %s decrypted to %q, which is not what was captured", requestID, ev.Content.Input.Text)
		}
		return true
	case errors.Is(err, evidence.ErrContentKeyErased):
		if ev.Content.Input.Text != "" {
			t.Fatalf("request %s produced text after a failed decryption: %q", requestID, ev.Content.Input.Text)
		}
		return false
	default:
		t.Fatalf("request %s: %v", requestID, err)
		return false
	}
}

func (f *erasureFixture) record(t *testing.T, requestID string) *evidence.Event {
	t.Helper()
	var found *evidence.Event
	err := evidence.Walk(f.dir, func(e evidence.Entry) error {
		if e.Event.RequestID == requestID {
			ev := e.Event
			found = &ev
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatalf("no record for request %s", requestID)
	}
	return found
}

func (f *erasureFixture) segments(t *testing.T) string {
	t.Helper()
	segs, err := evidence.Segments(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, s := range segs {
		body, err := os.ReadFile(s.Path)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(body)
	}
	return b.String()
}

func (f *erasureFixture) records(t *testing.T) uint64 {
	t.Helper()
	res, err := evidence.Verify(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("the chain does not verify: %+v", res.Problems)
	}
	return res.Records
}

// A command that destroys evidence content on a typo would be indefensible, so
// without --confirm it must change nothing at all.
func TestEraseWithoutConfirmDestroysNothing(t *testing.T) {
	f := newErasureFixture(t)
	keystoreBefore := eraseTestRead(t, f.keystore.Path())
	recordsBefore := f.records(t)

	out := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--session", "sess-1"}); err != nil {
			t.Fatal(err)
		}
	})

	if !f.readable(t, "req-1") {
		t.Fatal("a dry run destroyed the content")
	}
	if got := eraseTestRead(t, f.keystore.Path()); got != keystoreBefore {
		t.Error("a dry run rewrote the keystore")
	}
	if got := f.records(t); got != recordsBefore {
		t.Errorf("a dry run appended to the chain: %d records, was %d", got, recordsBefore)
	}

	for _, want := range []string{
		"dry run",
		"nothing has been destroyed",
		"cannot be undone",
		"--confirm",
		"2 record(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan does not mention %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "re-proven") {
		t.Errorf("the plan does not say what happens to the digests:\n%s", out)
	}
}

// The claim the whole feature makes: after an erasure the content is gone, the
// records are exactly as they were, and the chain still verifies.
func TestEraseMakesStoredContentUnreadableAndLeavesTheChainIntact(t *testing.T) {
	f := newErasureFixture(t)
	segmentsBefore := f.segments(t)
	recordsBefore := f.records(t)

	if !f.readable(t, "req-1") {
		t.Fatal("the fixture is not readable to begin with")
	}

	out := captureErase(t, func() {
		if err := Erase([]string{
			"--dir", f.dir, "--session", "sess-1", "--confirm",
			"--requester", "dpo@example.org", "--reason", "erasure request 2026-13",
		}); err != nil {
			t.Fatal(err)
		}
	})

	if f.readable(t, "req-1") || f.readable(t, "req-2") {
		t.Fatal("the content of the erased session can still be read")
	}
	if !f.readable(t, "req-3") {
		t.Error("erasing session sess-1 destroyed the content of session sess-2")
	}

	// Nothing was rewritten: the segments still start with exactly the bytes
	// they held before, and only the erasure record was added.
	after := f.segments(t)
	if !strings.HasPrefix(after, segmentsBefore) {
		t.Fatal("the erasure rewrote records that were already in the log")
	}
	if !strings.Contains(after, f.record(t, "req-1").Content.Input.Ciphertext) {
		t.Error("the ciphertext was removed from the record; erasure must destroy the key, not the evidence")
	}
	if got := f.records(t); got != recordsBefore+1 {
		t.Errorf("the log holds %d records, want %d: one erasure event and nothing else", got, recordsBefore+1)
	}
	if !strings.Contains(out, "verified intact after the erasure") {
		t.Errorf("the command does not state that the chain still verifies:\n%s", out)
	}
}

// The log has to document its own erasures, or an auditor comparing two
// exports sees content vanish with no explanation in between.
func TestEraseRecordsWhatItDestroyed(t *testing.T) {
	f := newErasureFixture(t)
	captureErase(t, func() {
		if err := Erase([]string{
			"--dir", f.dir, "--session", "sess-1", "--confirm",
			"--requester", "dpo@example.org", "--reason", "erasure request 2026-13",
		}); err != nil {
			t.Fatal(err)
		}
	})

	var erasure *evidence.Event
	if err := evidence.Walk(f.dir, func(e evidence.Entry) error {
		if e.Event.EventType == evidence.EventSystemEvent {
			ev := e.Event
			erasure = &ev
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if erasure == nil {
		t.Fatal("the erasure was not appended to the chain")
	}
	if erasure.SessionID != "sess-1" {
		t.Errorf("the erasure record names session %q", erasure.SessionID)
	}
	if erasure.Actor != "dpo@example.org" {
		t.Errorf("the erasure record names actor %q", erasure.Actor)
	}
	for _, want := range []string{
		"erased",
		"sess-1",
		"2 record(s)",
		"erasure request 2026-13",
		"dpo@example.org",
		"re-proven",
	} {
		if !strings.Contains(erasure.Note, want) {
			t.Errorf("the erasure record does not mention %q:\n%s", want, erasure.Note)
		}
	}
	if erasure.Content != nil {
		t.Error("the erasure record carries content of its own")
	}
}

// A data subject asking twice, or a ticket replayed by hand, must not be an
// error and must not write a second erasure into the chain.
func TestEraseIsIdempotent(t *testing.T) {
	f := newErasureFixture(t)
	args := []string{"--dir", f.dir, "--session", "sess-1", "--confirm"}

	captureErase(t, func() {
		if err := Erase(args); err != nil {
			t.Fatal(err)
		}
	})
	recordsAfterFirst := f.records(t)

	out := captureErase(t, func() {
		if err := Erase(args); err != nil {
			t.Fatalf("erasing an already erased session failed: %v", err)
		}
	})

	if got := f.records(t); got != recordsAfterFirst {
		t.Errorf("the second erasure appended to the chain: %d records, was %d", got, recordsAfterFirst)
	}
	if !strings.Contains(out, "already erased") {
		t.Errorf("the second run does not say the content was already erased:\n%s", out)
	}
	if !strings.Contains(out, "erased 2") {
		t.Errorf("the second run does not say when the content was erased:\n%s", out)
	}
}

// A run that destroyed the keys and then died before appending the record
// leaves the chain silent about content that is gone. The next run has to
// finish the job, and must not claim to have destroyed anything itself.
func TestEraseFinishesAnErasureThatWasNeverRecorded(t *testing.T) {
	f := newErasureFixture(t)

	interrupted, err := evidence.OpenContentKeystore(f.keystore.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := interrupted.Erase(evidence.ContentErasureRequest{
		SessionID: "sess-1",
		Reason:    "erasure request 2026-13",
	}); err != nil {
		t.Fatal(err)
	}
	if f.readable(t, "req-1") {
		t.Fatal("the fixture is wrong: the content should already be gone")
	}
	recordsBefore := f.records(t)

	out := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm"}); err != nil {
			t.Fatal(err)
		}
	})

	if got := f.records(t); got != recordsBefore+1 {
		t.Errorf("the log holds %d records, want %d: the missing erasure record", got, recordsBefore+1)
	}
	if strings.Contains(out, "content erased\n") {
		t.Errorf("the run claims to have destroyed content it did not destroy:\n%s", out)
	}
	if !strings.Contains(out, "erasure recorded in the chain") {
		t.Errorf("the run does not say what it actually did:\n%s", out)
	}

	// And now that the chain documents it, running again does nothing at all.
	again := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm"}); err != nil {
			t.Fatal(err)
		}
	})
	if got := f.records(t); got != recordsBefore+1 {
		t.Error("a third run appended a second erasure record")
	}
	if !strings.Contains(again, "already erased") {
		t.Errorf("the third run does not report the erasure as done:\n%s", again)
	}
}

// A legal hold outranks an erasure request. The refusal has to name the reason,
// because whoever is holding the erasure ticket needs to know what to escalate.
func TestEraseRefusesUnderALegalHold(t *testing.T) {
	f := newErasureFixture(t)
	if err := os.WriteFile(filepath.Join(f.dir, evidence.LegalHoldFile),
		[]byte("regulator inquiry 2026-13, retain everything\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm"})
	if err == nil {
		t.Fatal("the erasure went ahead under a legal hold")
	}
	if !strings.Contains(err.Error(), "regulator inquiry 2026-13") {
		t.Errorf("the refusal does not name the hold's reason: %v", err)
	}
	if !f.readable(t, "req-1") {
		t.Error("the content was destroyed despite the refusal")
	}
}

// Appending to the chain is a single-writer operation, so an erasure while the
// proxy is running is refused rather than racing it.
func TestEraseRefusesWhileAWriterHoldsTheDirectory(t *testing.T) {
	f := newErasureFixture(t)
	store, err := evidence.Open(evidence.Options{Dir: f.dir})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	err = Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm"})
	if err == nil {
		t.Fatal("the erasure went ahead while a writer held the directory")
	}
	if !strings.Contains(err.Error(), "stop the server") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
	if !f.readable(t, "req-1") {
		t.Error("the content was destroyed despite the refusal")
	}
}

// A running writer holds the whole keystore in memory and rewrites the file
// whenever it issues a key, so an erasure carried out beside it is undone by the
// next request it records: the erasure would report success and the content
// would still be readable. Pointing --keystore at a directory somebody else is
// writing is refused for that reason, not only the directory being erased from.
func TestEraseRefusesWhileAWriterHoldsTheKeystoreDirectory(t *testing.T) {
	f := newErasureFixture(t)
	store, err := evidence.Open(evidence.Options{Dir: f.dir})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	elsewhere := t.TempDir()
	err = Erase([]string{
		"--dir", elsewhere, "--session", "sess-1",
		"--keystore", f.keystore.Path(), "--confirm",
	})
	if err == nil {
		t.Fatal("the erasure went ahead while a writer held the keystore's directory")
	}
	if !strings.Contains(err.Error(), f.dir) {
		t.Errorf("the refusal does not name the directory that is being written: %v", err)
	}
	if !f.readable(t, "req-1") {
		t.Error("the content was destroyed despite the refusal")
	}
}

func TestEraseRequiresExactlyOneSelector(t *testing.T) {
	f := newErasureFixture(t)

	if err := Erase([]string{"--dir", f.dir, "--confirm"}); err == nil {
		t.Error("erase with no selector was accepted, which would erase everything")
	}
	if err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--request-id", "req-1"}); err == nil {
		t.Error("erase with two selectors was accepted")
	}
	if !f.readable(t, "req-1") {
		t.Error("a refused erasure destroyed content anyway")
	}
}

// Erasing by request id destroys the key that record names. That key covers the
// rest of its session, and the operator has to be told so before they confirm.
func TestEraseByRequestIDSaysWhatElseTheKeyCovers(t *testing.T) {
	f := newErasureFixture(t)

	out := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--request-id", "req-1"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "2 record(s)") {
		t.Errorf("the plan does not say the key covers the whole session:\n%s", out)
	}

	captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--request-id", "req-1", "--confirm"}); err != nil {
			t.Fatal(err)
		}
	})
	if f.readable(t, "req-2") {
		t.Error("the session key survived an erasure that named one of its records")
	}
	if !f.readable(t, "req-3") {
		t.Error("erasing one request destroyed an unrelated session")
	}
}

// Content captured before encryption was switched on is not under any key, and
// no key destroys it. Saying nothing about those records would let an operator
// report an erasure as complete when it was not.
func TestEraseReportsContentItCannotDestroy(t *testing.T) {
	f := newErasureFixture(t)

	store, err := evidence.Open(evidence.Options{Dir: f.dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-0",
		SessionID: "sess-1",
		Content: &evidence.Content{
			Mode:  evidence.ModeStore,
			Input: &evidence.Payload{SHA256: "0000", Text: testPrompt},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	out := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm"}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "1 matching record(s) hold text that is under no key") {
		t.Errorf("the command does not report the content it cannot destroy:\n%s", out)
	}
	if !strings.Contains(f.segments(t), testPrompt) {
		t.Fatal("the fixture is wrong: the plaintext record should still be readable in the segment")
	}
}

// A run that destroys one key and cannot reach another has erased part of a
// session. Reporting that as a plain success is how an operator comes to answer
// an Article 17 request wrongly, so it has to be said in the output and in the
// chain, in the run that did destroy something as much as in the run that did
// not.
func TestEraseNamesTheKeysItCouldNotDestroy(t *testing.T) {
	f := newErasureFixture(t)

	const foreignKey = "00112233445566778899aabbccddeeff"
	store, err := evidence.Open(evidence.Options{Dir: f.dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-elsewhere",
		SessionID: "sess-1",
		Content: &evidence.Content{
			Mode:       evidence.ModeStore,
			Encryption: &evidence.ContentEncryption{Algorithm: evidence.ContentKeyAlgorithm, KeyID: foreignKey},
			Input:      &evidence.Payload{SHA256: "3333", Bytes: 12, Ciphertext: "c2VhbGVkIHNvbWV3aGVyZSBlbHNl"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	out := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm"}); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, foreignKey) {
		t.Errorf("the run does not name the key it could not destroy:\n%s", out)
	}
	if !strings.Contains(out, "did not destroy") {
		t.Errorf("the run does not say that content it selected is still readable:\n%s", out)
	}

	note := lastSystemEventNote(t, f.dir)
	if !strings.Contains(note, "did not reach everything") {
		t.Errorf("the chain does not record that the erasure was partial:\n%s", note)
	}
}

// Running erase against a directory that never had content encryption must not
// leave a fresh master key in it. Without --confirm the command promises to
// change nothing, and with it there is still nothing to destroy.
func TestEraseDoesNotCreateAKeystoreThatIsNotThere(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-1",
		SessionID: "sess-1",
		Content: &evidence.Content{
			Mode:  evidence.ModeStore,
			Input: &evidence.Payload{SHA256: "1111", Bytes: len(testPrompt), Text: testPrompt},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"--dir", dir, "--session", "sess-1"},
		{"--dir", dir, "--session", "sess-1", "--confirm"},
	} {
		out := captureErase(t, func() {
			if err := Erase(args); err != nil {
				t.Fatalf("%v: %v", args, err)
			}
		})
		if _, err := os.Stat(evidence.ContentKeystorePath(dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%v created %s, leaving a master key in a directory that had none",
				args, evidence.ContentKeystoreFile)
		}
		if !strings.Contains(out, "under no key") {
			t.Errorf("%v does not report the plaintext it cannot destroy:\n%s", args, out)
		}
	}
}

// The JSON form goes into ticketing systems, so it must be free of anything
// that could reconstruct what was erased.
func TestEraseJSONCarriesNoKeyMaterial(t *testing.T) {
	f := newErasureFixture(t)
	wrapped := wrappedKeyMaterial(t, f.keystore.Path())

	out := captureErase(t, func() {
		if err := Erase([]string{"--dir", f.dir, "--session", "sess-1", "--confirm", "--json"}); err != nil {
			t.Fatal(err)
		}
	})

	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json did not emit JSON: %v\n%s", err, out)
	}
	if report["session_id"] != "sess-1" {
		t.Errorf("the JSON does not name the session: %v", report["session_id"])
	}
	for _, secret := range wrapped {
		if strings.Contains(out, secret) {
			t.Error("the JSON output contains wrapped key material")
		}
	}
	if strings.Contains(out, "Alice Schmidt") {
		t.Error("the JSON output contains the content that was erased")
	}
}

func TestEraseThroughMainDispatches(t *testing.T) {
	f := newErasureFixture(t)
	_, code := captureEraseExit(t, func() int {
		return Main([]string{"erase", "--dir", f.dir, "--session", "sess-1"})
	})
	if code != 0 {
		t.Errorf("erase through Main exited %d", code)
	}
}

func lastSystemEventNote(t *testing.T, dir string) string {
	t.Helper()
	note := ""
	if err := evidence.Walk(dir, func(e evidence.Entry) error {
		if e.Event.EventType == evidence.EventSystemEvent {
			note = e.Event.Note
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if note == "" {
		t.Fatal("the chain holds no system_event")
	}
	return note
}

func wrappedKeyMaterial(t *testing.T, path string) []string {
	t.Helper()
	var f struct {
		MasterKey string `json:"master_key"`
		Keys      map[string]struct {
			Wrapped string `json:"wrapped_key"`
		} `json:"keys"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	out := []string{f.MasterKey}
	for _, e := range f.Keys {
		out = append(out, e.Wrapped)
	}
	if len(out) < 2 {
		t.Fatal("the keystore holds no wrapped key to check against")
	}
	return out
}

func eraseTestRead(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// captureErase collects what the command printed. It writes to stdout directly,
// which is what an operator sees, so that is what these tests read.
func captureErase(t *testing.T, fn func()) string {
	t.Helper()
	out, _ := captureEraseExit(t, func() int {
		fn()
		return 0
	})
	return out
}

func captureEraseExit(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		body, _ := io.ReadAll(r)
		done <- string(body)
	}()

	code := fn()

	os.Stdout = saved
	w.Close()
	out := <-done
	r.Close()
	return out, code
}
