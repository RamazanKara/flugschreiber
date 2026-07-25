package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Problem is one integrity failure, located precisely enough to be actionable.
type Problem struct {
	Segment  string `json:"segment"`
	Line     int    `json:"line"`
	Seq      uint64 `json:"seq,omitempty"`
	Kind     string `json:"kind"`
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail"`
}

func (p Problem) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", p.Segment, p.Line, p.Kind, p.Detail)
}

// anchorWatch resolves an ambiguity that cannot be settled at the first record.
//
// When a log still contains records that pruned.json says were deleted, there
// are two explanations. The benign one is a prune interrupted between two
// unlinks: the anchor is written and fsynced before anything is removed, so a
// crash mid-loop leaves the anchor ahead of the log. The alarming one is that
// the log was replaced wholesale and the anchor was left behind.
//
// Both look identical at the first surviving record. They are told apart at
// exactly one point: the record whose sequence the anchor attests to must hash
// to the value the anchor recorded. So the interrupted-prune diagnosis is
// entered provisionally and upgraded to a high-severity mismatch if that record
// disagrees, or never arrives at all.
type anchorWatch struct {
	armed      bool
	seq        uint64
	wantHash   string
	resolved   bool
	problemIdx int
}

func (w *anchorWatch) arm(res *VerifyResult, seq uint64, wantHash string) {
	w.armed = true
	w.seq = seq
	w.wantHash = wantHash
	w.problemIdx = len(res.Problems) - 1
}

func (w *anchorWatch) observe(res *VerifyResult, segment string, line int, rec Record) {
	if !w.armed || w.resolved || rec.Seq != w.seq {
		return
	}
	w.resolved = true
	if rec.RecordHash == w.wantHash {
		// The anchor describes this log, so the interrupted-prune diagnosis
		// holds and the provisional problem stands as recorded.
		return
	}
	res.Problems[w.problemIdx] = Problem{
		Segment:  segment,
		Line:     line,
		Seq:      rec.Seq,
		Kind:     ProblemAnchorMismatch,
		Severity: SeverityHigh,
		Detail: fmt.Sprintf(
			"%s attests that the record at seq %d hashed to %s, but this log's record at seq %d hashes to %s; the log has been replaced, or this anchor does not belong to it",
			PruneAnchorFile, w.seq, short(w.wantHash), rec.Seq, short(rec.RecordHash)),
	}
}

// finish upgrades the diagnosis when the attested record never appeared, which
// means the anchor describes a log longer than the one on disk.
func (w *anchorWatch) finish(res *VerifyResult, dir string) {
	if !w.armed || w.resolved {
		return
	}
	res.Problems[w.problemIdx] = Problem{
		Segment:  filepath.Base(dir),
		Seq:      w.seq,
		Kind:     ProblemAnchorMismatch,
		Severity: SeverityHigh,
		Detail: fmt.Sprintf(
			"%s attests to a record at seq %d, but this log ends at seq %d; the anchor does not describe this log",
			PruneAnchorFile, w.seq, res.LastSeq),
	}
}

// classifyPrunedStart decides what the first surviving record means when an
// anchor is present, and returns the linkage state the walk should continue
// with. It suppresses the generic link and sequence checks for that one record
// where it has already said something more precise.
func classifyPrunedStart(res *VerifyResult, watch *anchorWatch, anchor *PruneAnchor, segment string, line int, rec Record) (prevHash string, prevSeq uint64) {
	switch {
	case rec.Seq == anchor.LastPrunedSeq+1 && rec.PrevHash == anchor.LastPrunedHash:
		// A completed prune, linking cleanly to the anchor.
		return anchor.LastPrunedHash, anchor.LastPrunedSeq

	case rec.Seq <= anchor.LastPrunedSeq:
		res.Problems = append(res.Problems, Problem{
			Segment:  segment,
			Line:     line,
			Seq:      rec.Seq,
			Kind:     ProblemPruneIncomplete,
			Severity: SeverityMedium,
			Detail: fmt.Sprintf(
				"%s records deletion through seq %d but this log still starts at seq %d; retention enforcement was interrupted, re-run it to finish",
				PruneAnchorFile, anchor.LastPrunedSeq, rec.Seq),
		})
		watch.arm(res, anchor.LastPrunedSeq, anchor.LastPrunedHash)

		if rec.Seq == 1 && rec.PrevHash == GenesisHash {
			return GenesisHash, 0
		}
		// The predecessor of this record was deleted, so there is nothing to
		// link it to. Resume linkage from this record onwards.
		return "", rec.Seq - 1

	case rec.Seq > anchor.LastPrunedSeq+1:
		res.Problems = append(res.Problems, Problem{
			Segment:  segment,
			Line:     line,
			Seq:      rec.Seq,
			Kind:     ProblemSeqGap,
			Severity: SeverityHigh,
			Detail: fmt.Sprintf(
				"%s records deletion through seq %d, so this log should start at seq %d, but it starts at seq %d; records between them are missing from both",
				PruneAnchorFile, anchor.LastPrunedSeq, anchor.LastPrunedSeq+1, rec.Seq),
		})
		return "", rec.Seq - 1

	default:
		res.Problems = append(res.Problems, Problem{
			Segment:  segment,
			Line:     line,
			Seq:      rec.Seq,
			Kind:     ProblemBrokenLink,
			Severity: SeverityHigh,
			Detail: fmt.Sprintf(
				"the first surviving record links to %s, but %s attests that the last deleted record hashed to %s",
				short(rec.PrevHash), PruneAnchorFile, short(anchor.LastPrunedHash)),
		})
		return "", rec.Seq - 1
	}
}

// Kinds of integrity failure.
const (
	ProblemMalformed          = "malformed_record"
	ProblemHashMismatch       = "hash_mismatch"
	ProblemBrokenLink         = "broken_link"
	ProblemSeqGap             = "sequence_gap"
	ProblemEmptyDir           = "no_segments"
	ProblemBadAnchor          = "bad_prune_anchor"
	ProblemPruneIncomplete    = "prune_incomplete"
	ProblemAnchorMismatch     = "anchor_mismatch"
	ProblemBadCheckpoint      = "bad_checkpoint"
	ProblemCheckpointMismatch = "checkpoint_mismatch"
	ProblemBadSignature       = "bad_signature"
	ProblemUnknownKey         = "unknown_key"
	ProblemBadTimestamp       = "bad_timestamp"
	ProblemCheckpointGap      = "checkpoint_gap"
	ProblemAttestationsGone   = "attestations_removed"
	ProblemUnknownCheckpoint  = "unknown_checkpoint_version"
)

// Severities. High means the log cannot be relied on as it stands. Medium
// means something is missing or unverifiable, but what is present is intact.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
)

// VerifyResult summarises a verification pass.
type VerifyResult struct {
	Dir       string   `json:"dir"`
	Segments  []string `json:"segments"`
	Records   uint64   `json:"records"`
	FirstSeq  uint64   `json:"first_seq,omitempty"`
	LastSeq   uint64   `json:"last_seq,omitempty"`
	FirstTime string   `json:"first_time,omitempty"`
	LastTime  string   `json:"last_time,omitempty"`
	HeadHash  string   `json:"head_hash,omitempty"`

	// Pruned records that this log does not start at genesis. It is reported
	// separately from Problems because a pruned log is a legitimate log, but a
	// reader must never be shown a pruned chain as intact from the beginning.
	Pruned           bool     `json:"pruned"`
	PrunedThroughSeq uint64   `json:"pruned_through_seq,omitempty"`
	PrunedRecords    uint64   `json:"pruned_records,omitempty"`
	PrunedSegments   []string `json:"pruned_segments,omitempty"`
	PrunedAt         string   `json:"pruned_at,omitempty"`

	// Checkpoints counts the attestations found, CheckpointsVerified counts
	// those whose signature checked out and whose record hash matched the
	// chain. Attested is true only when at least one did both.
	Checkpoints         int    `json:"checkpoints"`
	CheckpointsVerified int    `json:"checkpoints_verified"`
	Attested            bool   `json:"attested"`
	KeyID               string `json:"key_id,omitempty"`

	// RetiredKeys lists the ids of keys that rotation has replaced and that
	// this directory still holds the public half of. A checkpoint signed under
	// any of them verifies; the list is reported so that an auditor can see
	// the custody history rather than infer it.
	RetiredKeys []string `json:"retired_keys,omitempty"`

	// Timestamps counts the RFC 3161 tokens found, TimestampedCheckpoints
	// those whose message imprint matched the checkpoint they are filed
	// against. Neither says anything about who signed a token: that is settled
	// by validating its CMS signature, which VERIFY.md documents and this
	// binary deliberately does not attempt.
	Timestamps             int `json:"timestamps,omitempty"`
	TimestampedCheckpoints int `json:"timestamped_checkpoints,omitempty"`

	// ChainedCheckpoints counts checkpoints that carry the linkage fields, so a
	// reader can tell how much of the attestation history is protected against
	// deletion rather than only against forgery. Checkpoints written before
	// those fields existed are counted in Checkpoints and not here.
	ChainedCheckpoints int `json:"chained_checkpoints,omitempty"`

	// Notes carry findings that are not integrity failures, such as a log that
	// verifies but that nothing attests to.
	Notes []string `json:"notes,omitempty"`

	Problems []Problem `json:"problems,omitempty"`
	Duration string    `json:"duration"`
}

// OK reports whether the chain verified without any problem.
func (r *VerifyResult) OK() bool { return len(r.Problems) == 0 }

// Intact reports whether the chain itself is sound: every record hashes to what
// it carries, every link holds, no sequence number is missing, and nothing that
// is signed contradicts it.
//
// This is deliberately narrower than OK. A problem that says "I could not check
// this" is not a problem that says "this is broken", and collapsing the two
// makes the tool print its maximum-severity claim over an intact log because a
// public key was missing from the copy it was handed. A reader has to be able
// to tell a damaged chain from an incomplete one.
func (r *VerifyResult) Intact() bool {
	for _, p := range r.Problems {
		if !uncheckable[p.Kind] {
			return false
		}
	}
	return true
}

// uncheckable names the problems that mean verification could not be completed,
// as opposed to completing and finding damage. Each is still reported and still
// makes OK false; what they do not do is claim the chain is broken.
var uncheckable = map[string]bool{
	ProblemUnknownKey:        true,
	ProblemUnknownCheckpoint: true,
	ProblemBadTimestamp:      true,
}

// Verify walks every segment in dir and checks that each record's hash matches
// its contents, that each record links to its predecessor, and that sequence
// numbers are contiguous across segment boundaries.
//
// When pruned.json is present the walk starts from the anchor instead of the
// genesis hash, and the result says so. When public-key.pem is present every
// checkpoint signature is checked, and every checkpoint is cross-checked
// against the record it claims to cover: that cross-check is what catches a log
// that was rewritten end to end and still hashes consistently.
//
// It reads only the files on disk and needs no running server, so a third
// party can check a chain with nothing but this binary and the evidence
// directory.
func Verify(dir string) (*VerifyResult, error) {
	start := time.Now()
	res := &VerifyResult{Dir: dir}

	anchor := loadAnchorForVerify(dir, res)
	keys := loadKeysForVerify(dir, res)
	verifyAnchorSignature(res, anchor, keys)
	checks := loadCheckpointsForVerify(dir, res, keys)
	verifyTimestamps(dir, res, checks)

	segs, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		res.Problems = append(res.Problems, Problem{
			Segment:  filepath.Base(dir),
			Kind:     ProblemEmptyDir,
			Severity: SeverityMedium,
			Detail:   "no seg-*.jsonl files found in evidence directory",
		})
		res.Duration = time.Since(start).String()
		return res, nil
	}

	prevHash := GenesisHash
	var prevSeq uint64
	if anchor != nil && res.Pruned {
		prevHash = anchor.LastPrunedHash
		prevSeq = anchor.LastPrunedSeq
	}
	firstRecord := true
	var watch anchorWatch

	for _, seg := range segs {
		name := filepath.Base(seg.Path)
		res.Segments = append(res.Segments, name)

		f, err := os.Open(seg.Path)
		if err != nil {
			return nil, err
		}
		sc := newLineScanner(f)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec Record
			if err := json.Unmarshal(line, &rec); err != nil {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(),
					Kind:     ProblemMalformed,
					Severity: SeverityHigh,
					Detail:   err.Error(),
				})
				// The chain head is unknown from here on, so keep reading for
				// a full damage report but stop trusting the linkage.
				prevHash = ""
				firstRecord = false
				continue
			}

			if firstRecord {
				firstRecord = false
				if res.Pruned && anchor != nil {
					prevHash, prevSeq = classifyPrunedStart(res, &watch, anchor, name, sc.Line(), rec)
				}
			}

			if want := rec.Hash(); want != rec.RecordHash {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(), Seq: rec.Seq,
					Kind:     ProblemHashMismatch,
					Severity: SeverityHigh,
					Detail:   fmt.Sprintf("record_hash is %s, contents hash to %s", short(rec.RecordHash), short(want)),
				})
			}
			if prevHash != "" && rec.PrevHash != prevHash {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(), Seq: rec.Seq,
					Kind:     ProblemBrokenLink,
					Severity: SeverityHigh,
					Detail:   fmt.Sprintf("prev_hash is %s, predecessor hashes to %s", short(rec.PrevHash), short(prevHash)),
				})
			}
			if prevSeq != 0 && rec.Seq != prevSeq+1 {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(), Seq: rec.Seq,
					Kind:     ProblemSeqGap,
					Severity: SeverityHigh,
					Detail:   fmt.Sprintf("expected seq %d, found %d", prevSeq+1, rec.Seq),
				})
			}
			checks.match(res, name, sc.Line(), rec)
			watch.observe(res, name, sc.Line(), rec)

			if res.Records == 0 {
				res.FirstSeq = rec.Seq
				res.FirstTime = rec.Timestamp
			}
			res.Records++
			res.LastSeq = rec.Seq
			res.LastTime = rec.Timestamp
			res.HeadHash = rec.RecordHash
			prevHash = rec.RecordHash
			prevSeq = rec.Seq
		}
		scanErr := sc.Err()
		f.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read %s: %w", name, scanErr)
		}
	}

	watch.finish(res, dir)
	checks.finish(res, anchor)
	res.Duration = time.Since(start).String()
	return res, nil
}

// loadAnchorForVerify reads pruned.json and decides whether the walk starts
// from it. A malformed or unsigned-but-expected anchor is a problem in its own
// right: it is the only thing standing between "records were deleted by
// policy" and "records were deleted by someone".
func loadAnchorForVerify(dir string, res *VerifyResult) *PruneAnchor {
	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		res.Problems = append(res.Problems, Problem{
			Segment:  PruneAnchorFile,
			Kind:     ProblemBadAnchor,
			Severity: SeverityHigh,
			Detail:   err.Error(),
		})
		return nil
	}
	if anchor == nil {
		return nil
	}

	switch {
	case anchor.Version != PruneAnchorVersion:
		res.Problems = append(res.Problems, Problem{
			Segment: PruneAnchorFile, Kind: ProblemBadAnchor, Severity: SeverityHigh,
			Detail: fmt.Sprintf("version is %d, this build understands version %d", anchor.Version, PruneAnchorVersion),
		})
		return anchor
	case anchor.LastPrunedSeq == 0:
		res.Problems = append(res.Problems, Problem{
			Segment: PruneAnchorFile, Kind: ProblemBadAnchor, Severity: SeverityHigh,
			Detail: "last_pruned_seq is 0, so the anchor does not say where the surviving chain begins",
		})
		return anchor
	case !isChainHash(anchor.LastPrunedHash):
		res.Problems = append(res.Problems, Problem{
			Segment: PruneAnchorFile, Kind: ProblemBadAnchor, Severity: SeverityHigh,
			Detail: fmt.Sprintf("last_pruned_hash %q is not a 64-character hex digest", anchor.LastPrunedHash),
		})
		return anchor
	}

	res.Pruned = true
	res.PrunedThroughSeq = anchor.LastPrunedSeq
	res.PrunedRecords = anchor.Records
	res.PrunedSegments = anchor.Segments
	res.PrunedAt = anchor.PrunedAt
	return anchor
}

func verifyAnchorSignature(res *VerifyResult, anchor *PruneAnchor, keys *KeySet) {
	if anchor == nil || keys.Len() == 0 {
		return
	}
	if anchor.Signature == "" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%s is not signed, so the record of what was deleted rests on the chain linkage alone", PruneAnchorFile))
		return
	}
	key, ok := keys.signerOf(anchor.KeyID)
	if !ok {
		res.Problems = append(res.Problems, Problem{
			Segment: PruneAnchorFile, Kind: ProblemUnknownKey, Severity: SeverityMedium,
			Detail: unknownKeyDetail(anchor.KeyID, keys),
		})
		return
	}
	if err := VerifyPruneAnchorSignature(key.Public, *anchor); err != nil {
		res.Problems = append(res.Problems, Problem{
			Segment: PruneAnchorFile, Kind: ProblemBadSignature, Severity: SeverityHigh,
			Detail: err.Error(),
		})
	}
}

// loadKeysForVerify reads every key signatures may be checked against: the
// current one and every key rotation has retired. A key file that exists but
// cannot be read is reported rather than noted, because corrupting one would
// otherwise be a way to turn signature checking off and still be told the log
// is fine.
func loadKeysForVerify(dir string, res *VerifyResult) *KeySet {
	keys := LoadKeySet(dir)
	for _, u := range keys.Unreadable {
		res.Problems = append(res.Problems, Problem{
			Segment: u.Source, Kind: ProblemUnknownKey, Severity: SeverityMedium,
			Detail: fmt.Sprintf("%v; no signature could be checked against it", u.Err),
		})
	}
	if current, ok := keys.Current(); ok {
		res.KeyID = current.ID
	}
	res.RetiredKeys = keys.RetiredIDs()
	return keys
}

// signerOf resolves the key a signature names. A checkpoint written before key
// ids were recorded carries none, and is checked against the current key,
// which is the only one it could have been signed with.
func (ks *KeySet) signerOf(keyID string) (KnownKey, bool) {
	if keyID == "" {
		return ks.Current()
	}
	return ks.ByID(keyID)
}

// unknownKeyDetail says what was looked for and where, because "unknown key"
// on its own leaves an operator with nowhere to go.
func unknownKeyDetail(keyID string, keys *KeySet) string {
	named := keyID
	if named == "" {
		named = "no key at all"
	}
	held := make([]string, 0, keys.Len())
	for _, k := range keys.Keys {
		held = append(held, k.ID)
	}
	if len(held) == 0 {
		return fmt.Sprintf("signed by key %s, and this directory holds no public key to check it with", named)
	}
	return fmt.Sprintf(
		"signed by key %s, which is neither %s nor any retired key in %s/ (this directory holds %s)",
		named, PublicKeyFile, RetiredKeysDir, strings.Join(held, ", "))
}

// checkpointSet cross-checks checkpoints against the chain while it is walked,
// so that verification stays a single pass over the records and needs memory
// proportional to the number of checkpoints rather than to the log.
type checkpointSet struct {
	all    []Checkpoint
	bySeq  map[uint64][]int
	signed []bool
	seen   []bool
}

func loadCheckpointsForVerify(dir string, res *VerifyResult, keys *KeySet) *checkpointSet {
	cs := &checkpointSet{bySeq: map[uint64][]int{}}

	list, err := ReadCheckpoints(dir)
	if err != nil {
		res.Problems = append(res.Problems, Problem{
			Segment: CheckpointsFile, Kind: ProblemBadCheckpoint, Severity: SeverityMedium,
			Detail: err.Error(),
		})
		return cs
	}
	cs.all = list
	cs.signed = make([]bool, len(list))
	cs.seen = make([]bool, len(list))
	res.Checkpoints = len(list)

	for i, c := range list {
		cs.bySeq[c.Seq] = append(cs.bySeq[c.Seq], i)
		if keys.Len() == 0 {
			// Nothing to check against; reported once in finish.
			continue
		}
		// A checkpoint from a newer build is unreadable, not forged. Reporting
		// it as a bad signature would accuse an operator of tampering for the
		// ordinary act of upgrading, so it is named for what it is and the
		// signature is not checked against a preimage this build cannot render.
		if c.Version != CheckpointVersion {
			res.Problems = append(res.Problems, Problem{
				Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
				Kind: ProblemUnknownCheckpoint, Severity: SeverityMedium,
				Detail: fmt.Sprintf(
					"%s declares checkpoint version %d and this build understands version %d, so its signature was not checked; verify with a build that knows version %d",
					checkpointLabel(c), c.Version, CheckpointVersion, c.Version),
			})
			continue
		}
		key, ok := keys.signerOf(c.KeyID)
		if !ok {
			res.Problems = append(res.Problems, Problem{
				Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
				Kind: ProblemUnknownKey, Severity: SeverityMedium,
				Detail: unknownKeyDetail(c.KeyID, keys),
			})
			continue
		}
		if err := VerifyCheckpointSignature(key.Public, c); err != nil {
			res.Problems = append(res.Problems, Problem{
				Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
				Kind: ProblemBadSignature, Severity: SeverityHigh,
				Detail: err.Error(),
			})
			continue
		}
		if c.Chained() {
			if err := VerifyCheckpointChainSignature(key.Public, c); err != nil {
				res.Problems = append(res.Problems, Problem{
					Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
					Kind: ProblemBadSignature, Severity: SeverityHigh,
					Detail: err.Error(),
				})
				continue
			}
		}
		cs.signed[i] = true
	}
	cs.checkLinkage(res)
	return cs
}

// checkLinkage walks the checkpoint chain and reports deletions.
//
// Signatures alone cannot do this. Every checkpoint an attacker leaves behind
// verifies perfectly; what betrays the ones removed is that the survivors
// commit to a position and to a predecessor. A gap in the index, or a link that
// names a checkpoint that is not there, is a deletion and nothing else, so it
// is reported at high severity next to the rewrite case it accompanies.
func (cs *checkpointSet) checkLinkage(res *VerifyResult) {
	var prev *Checkpoint
	var prevIndex int
	for i := range cs.all {
		c := cs.all[i]
		if !c.Chained() {
			// Predates chaining. Nothing to check, and nothing it can prove.
			prev, prevIndex = nil, 0
			continue
		}
		res.ChainedCheckpoints++
		if prev == nil {
			// The first chained checkpoint numbers itself after everything
			// already in the file. If it claims a higher position than there is
			// room for, the checkpoints before it were deleted from the front,
			// which the link walk below cannot see because the survivors are
			// contiguous among themselves.
			if c.Index > uint64(i) {
				res.Problems = append(res.Problems, Problem{
					Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
					Kind: ProblemCheckpointGap, Severity: SeverityHigh,
					Detail: fmt.Sprintf(
						"%s is numbered %d but only %d checkpoint(s) precede it in this file: %d attestation(s) were removed from the beginning",
						checkpointLabel(c), c.Index, i, c.Index-uint64(i)),
				})
			}
			prev, prevIndex = &cs.all[i], i
			continue
		}
		if c.Index != prev.Index+1 {
			missing := c.Index - prev.Index - 1
			res.Problems = append(res.Problems, Problem{
				Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
				Kind: ProblemCheckpointGap, Severity: SeverityHigh,
				Detail: fmt.Sprintf(
					"%s is numbered %d and the one before it is numbered %d: %d attestation(s) that were signed are no longer in this file",
					checkpointLabel(c), c.Index, prev.Index, missing),
			})
		} else if want := CheckpointHash(*prev); c.PrevCheckpointHash != want {
			res.Problems = append(res.Problems, Problem{
				Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
				Kind: ProblemCheckpointGap, Severity: SeverityHigh,
				Detail: fmt.Sprintf(
					"%s links to a predecessor with hash %s, but the checkpoint on line %d hashes to %s: an attestation was replaced or removed",
					checkpointLabel(c), short(c.PrevCheckpointHash), prevIndex+1, short(want)),
			})
		}
		prev, prevIndex = &cs.all[i], i
	}
}

// verifyTimestamps checks the RFC 3161 anchors against the checkpoints they
// are filed against.
//
// The check is structural and its limits are the point: it establishes that a
// token covers the same bytes as the checkpoint it sits beside, which is what
// makes the anchor about this log rather than about some other one. It does
// not validate the authority's signature, so a token that cannot be parsed is
// a note rather than a problem, while a token that parses and contradicts its
// checkpoint is a problem, because that is a claim about this log that is
// demonstrably wrong.
func verifyTimestamps(dir string, res *VerifyResult, checks *checkpointSet) {
	stamps, err := ReadTimestamps(dir)
	if err != nil {
		res.Problems = append(res.Problems, Problem{
			Segment: TimestampsFile, Kind: ProblemBadTimestamp, Severity: SeverityMedium,
			Detail: err.Error(),
		})
		return
	}
	res.Timestamps = len(stamps)

	for i, ts := range stamps {
		line := i + 1
		covered, ok := checks.checkpointAt(ts.Seq)
		if !ok {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"%s line %d anchors a checkpoint at seq %d that %s does not hold",
				TimestampsFile, line, ts.Seq, CheckpointsFile))
			continue
		}
		if covered.RecordHash != ts.RecordHash {
			res.Problems = append(res.Problems, Problem{
				Segment: TimestampsFile, Line: line, Seq: ts.Seq,
				Kind: ProblemBadTimestamp, Severity: SeverityMedium,
				Detail: fmt.Sprintf(
					"anchors record_hash %s, but the checkpoint at seq %d attests %s",
					short(ts.RecordHash), ts.Seq, short(covered.RecordHash)),
			})
			continue
		}
		// The line between a note and a problem here is what this build can
		// read. A token it cannot parse is its own limitation and says nothing
		// about the log; a token it can parse that covers other bytes is a
		// claim about this log that is wrong.
		token, err := ts.Token()
		var info *TimestampInfo
		if err == nil {
			info, err = ParseTimestampToken(token)
		}
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"%s line %d could not be checked: %v", TimestampsFile, line, err))
			continue
		}
		if !strings.EqualFold(info.Imprint, ts.RecordHash) {
			res.Problems = append(res.Problems, Problem{
				Segment: TimestampsFile, Line: line, Seq: ts.Seq,
				Kind: ProblemBadTimestamp, Severity: SeverityMedium,
				Detail: fmt.Sprintf(
					"the token covers %s, but it is filed against record_hash %s; it anchors a different record",
					short(info.Imprint), short(ts.RecordHash)),
			})
			continue
		}
		res.TimestampedCheckpoints++
	}
}

// checkpointAt returns the checkpoint covering a sequence number. Several
// checkpoints may name one sequence when a store was restarted, and they agree
// unless the log was rewritten, which the chain cross-check reports on its own.
func (cs *checkpointSet) checkpointAt(seq uint64) (Checkpoint, bool) {
	for _, i := range cs.bySeq[seq] {
		return cs.all[i], true
	}
	return Checkpoint{}, false
}

// match compares rec against any checkpoint that claims to cover it. A
// checkpoint that disagrees with the chain is the signal that the log was
// rewritten after the checkpoint was signed, which is exactly the attack the
// hash chain alone cannot see.
func (cs *checkpointSet) match(res *VerifyResult, segment string, line int, rec Record) {
	for _, i := range cs.bySeq[rec.Seq] {
		cs.seen[i] = true
		c := cs.all[i]
		if c.RecordHash != rec.RecordHash {
			res.Problems = append(res.Problems, Problem{
				Segment: segment, Line: line, Seq: rec.Seq,
				Kind: ProblemCheckpointMismatch, Severity: SeverityHigh,
				Detail: fmt.Sprintf(
					"%s attests record_hash %s, the log holds %s",
					checkpointLabel(c), short(c.RecordHash), short(rec.RecordHash)),
			})
			continue
		}
		if cs.signed[i] {
			res.CheckpointsVerified++
			res.Attested = true
		}
	}
}

func (cs *checkpointSet) finish(res *VerifyResult, anchor *PruneAnchor) {
	for i, c := range cs.all {
		if cs.seen[i] {
			continue
		}
		if anchor != nil && c.Seq <= anchor.LastPrunedSeq {
			// The record this checkpoint covers was deleted by retention. The
			// checkpoint stays as a record that it once existed.
			continue
		}
		res.Problems = append(res.Problems, Problem{
			Segment: CheckpointsFile, Line: i + 1, Seq: c.Seq,
			Kind: ProblemCheckpointMismatch, Severity: SeverityHigh,
			Detail: fmt.Sprintf(
				"%s attests a record that is not in the log; records were removed after the checkpoint was signed",
				checkpointLabel(c)),
		})
	}

	if len(cs.all) == 0 {
		// Deliberately not a problem. A public key can sit in a directory whose
		// log was written with signing off, so an empty checkpoint file cannot
		// be told apart from a log that was never attested, and guessing would
		// accuse honest operators. --require-attestation is how somebody who
		// knows their log is signed turns this into a failure.
		res.Notes = append(res.Notes,
			"no checkpoints found: the chain is internally consistent, but nothing signed attests to when it was written or by whom. "+
				"If this log was written with signing on, the attestations have been removed; run with --require-attestation where that is known.")
		return
	}
	if res.KeyID == "" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"no usable %s, so checkpoint signatures were not checked; obtain the public key from the operator to complete verification", PublicKeyFile))
		return
	}
	if !res.Attested {
		res.Notes = append(res.Notes, "no checkpoint both verified against the key and matched the chain")
	}
}

func checkpointLabel(c Checkpoint) string {
	if c.Timestamp == "" {
		return fmt.Sprintf("the checkpoint at seq %d", c.Seq)
	}
	return fmt.Sprintf("the checkpoint of %s at seq %d", c.Timestamp, c.Seq)
}

func isChainHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
