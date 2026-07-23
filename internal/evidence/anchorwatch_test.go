package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// agedStore writes n records that are all old enough to be pruned, in segments
// small enough that several exist.
func agedStore(t *testing.T, dir string, n int) {
	t.Helper()
	base := time.Now().AddDate(0, 0, -400)
	i := 0
	s, err := Open(Options{
		Dir:             dir,
		SegmentMaxBytes: 1500,
		Now: func() time.Time {
			i++
			return base.Add(time.Duration(i) * time.Second)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := 0; k < n; k++ {
		if err := s.Append(&Event{EventType: EventInference, RequestID: "r", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func problemsOfKind(res *VerifyResult, kind string) []Problem {
	var out []Problem
	for _, p := range res.Problems {
		if p.Kind == kind {
			out = append(out, p)
		}
	}
	return out
}

// A prune interrupted between two unlinks leaves the anchor ahead of the log.
// That is recoverable and must be reported as such, not as a cascade of broken
// links the operator cannot act on.
func TestPruneInterruptedBetweenUnlinksIsDiagnosed(t *testing.T) {
	dir := t.TempDir()
	agedStore(t, dir, 12)

	segsBefore, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segsBefore) < 3 {
		t.Fatalf("fixture needs at least three segments, got %d", len(segsBefore))
	}

	saved := map[string][]byte{}
	for _, s := range segsBefore {
		body, err := os.ReadFile(s.Path)
		if err != nil {
			t.Fatal(err)
		}
		saved[filepath.Base(s.Path)] = body
	}

	policy := RetentionPolicy{MinDays: 180}
	enforced, err := policy.Enforce(dir, EnforceOptions{Reason: "test"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(enforced.Deleted) < 2 {
		t.Skipf("retention deleted %d segment(s); need at least two to interrupt", len(enforced.Deleted))
	}

	// Enforce unlinks oldest first, so a crash before the final unlink leaves
	// the last segment it would have removed still on disk.
	last := enforced.Deleted[len(enforced.Deleted)-1]
	if err := os.WriteFile(filepath.Join(dir, last), saved[last], 0o640); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}

	incomplete := problemsOfKind(res, ProblemPruneIncomplete)
	if len(incomplete) != 1 {
		t.Fatalf("expected exactly one prune_incomplete, got problems: %v", res.Problems)
	}
	if incomplete[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium for a recoverable interruption", incomplete[0].Severity)
	}
	if !strings.Contains(incomplete[0].Detail, "re-run it to finish") {
		t.Errorf("detail does not say what to do: %q", incomplete[0].Detail)
	}

	// The cascade this diagnosis exists to prevent must not appear.
	for _, kind := range []string{ProblemBrokenLink, ProblemSeqGap, ProblemAnchorMismatch} {
		if got := problemsOfKind(res, kind); len(got) != 0 {
			t.Errorf("interrupted prune produced %s: %v", kind, got)
		}
	}
}

// Replacing the whole log with a fresh chain from genesis, leaving pruned.json
// in place, is the shape an end-to-end rewrite has. It must never be reported
// as a recoverable operational hiccup.
func TestWholeLogReplacementIsNotMistakenForAnInterruptedPrune(t *testing.T) {
	dir := t.TempDir()
	agedStore(t, dir, 12)

	policy := RetentionPolicy{MinDays: 180}
	res, err := policy.Enforce(dir, EnforceOptions{Reason: "test"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) == 0 {
		t.Skip("retention deleted nothing; nothing to contradict")
	}

	// Remove every surviving segment and write a fresh, internally consistent
	// chain from genesis. pruned.json ends up exactly as retention left it.
	//
	// The anchor is moved aside while the replacement is generated because a
	// store that finds one continues the chain from it instead of from genesis,
	// which is the honest behaviour and not the one being simulated here: an
	// attacker rewriting the log from the beginning has no reason to consult the
	// anchor they are about to contradict.
	anchorPath := filepath.Join(dir, PruneAnchorFile)
	anchorBytes, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range segs {
		if err := os.Remove(s.Path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(anchorPath); err != nil {
		t.Fatal(err)
	}
	agedStore(t, dir, 20)
	if err := os.WriteFile(anchorPath, anchorBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	verified, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}

	if verified.OK() {
		t.Fatal("a replaced log verified cleanly")
	}
	mismatches := problemsOfKind(verified, ProblemAnchorMismatch)
	if len(mismatches) == 0 {
		t.Fatalf("replacement was not reported as an anchor mismatch: %v", verified.Problems)
	}
	if mismatches[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want high for a log that contradicts its anchor", mismatches[0].Severity)
	}
	if !strings.Contains(mismatches[0].Detail, "replaced") {
		t.Errorf("detail does not name the cause: %q", mismatches[0].Detail)
	}
	// The wrong diagnosis must be gone, not merely accompanied.
	if got := problemsOfKind(verified, ProblemPruneIncomplete); len(got) != 0 {
		t.Errorf("replacement is still reported as a recoverable interruption: %v", got)
	}
}

// An anchor describing a longer log than the one on disk is also a mismatch,
// not a missing record the walk can shrug off.
func TestAnchorAttestingBeyondTheEndOfTheLogIsAMismatch(t *testing.T) {
	dir := t.TempDir()
	agedStore(t, dir, 6)

	head, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}

	// An anchor claiming a deletion far beyond anything this log contains.
	anchor := PruneAnchor{
		Version:        PruneAnchorVersion,
		PrunedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		LastPrunedSeq:  head.LastSeq + 500,
		LastPrunedHash: strings.Repeat("a", 64),
		Segments:       []string{"seg-00000001.jsonl"},
		Records:        head.LastSeq + 500,
		Reason:         "fabricated",
	}
	if err := WritePruneAnchor(dir, anchor); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	mismatches := problemsOfKind(res, ProblemAnchorMismatch)
	if len(mismatches) == 0 {
		t.Fatalf("an anchor beyond the end of the log was accepted: %v", res.Problems)
	}
	if mismatches[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", mismatches[0].Severity)
	}
	if !strings.Contains(mismatches[0].Detail, "does not describe this log") {
		t.Errorf("detail = %q", mismatches[0].Detail)
	}
}

// A completed prune is the normal case and must verify without complaint,
// while still reporting itself as pruned rather than intact from genesis.
func TestCompletedPruneVerifiesAndReportsItselfAsPruned(t *testing.T) {
	dir := t.TempDir()
	agedStore(t, dir, 12)

	policy := RetentionPolicy{MinDays: 180}
	enforced, err := policy.Enforce(dir, EnforceOptions{Reason: "test"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(enforced.Deleted) == 0 {
		t.Skip("retention deleted nothing")
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a completed prune did not verify: %v", res.Problems)
	}
	if !res.Pruned {
		t.Error("Pruned = false after a prune; a reader would be shown this as intact from the beginning")
	}
	if res.PrunedThroughSeq == 0 {
		t.Error("PrunedThroughSeq = 0; the result does not say where the surviving chain begins")
	}
	if _, err := os.Stat(filepath.Join(dir, PruneAnchorFile)); err != nil {
		t.Errorf("no anchor was written: %v", err)
	}
}
