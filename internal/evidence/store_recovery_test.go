package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Rotation creates the next segment file before any record goes into it. A
// crash in that window leaves an empty newest segment, and recovering the head
// from that file alone finds nothing. Starting again from genesis at that point
// puts a second chain inside an existing log, which Verify reports as tampering
// even though the cause was a clean crash. That false alarm is worse than the
// crash.
func TestEmptyNewestSegmentDoesNotStartASecondChain(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 400)
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected several segments, got %d", len(segs))
	}
	newest := segs[len(segs)-1]
	before := readRecords(t, newest.Path)
	if err := os.Truncate(newest.Path, 0); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, dir, 400)
	appendN(t, reopened, 3)
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("restarting on an empty newest segment broke the chain: %v", res.Problems)
	}
	// The records that were in the truncated segment are gone, but the chain
	// that continues must pick up from the last record still on disk rather
	// than from seq 1.
	wantFirstNew := before[0].Seq
	if res.LastSeq != wantFirstNew+2 {
		t.Errorf("log ends at seq %d, want %d: the new records did not continue the chain", res.LastSeq, wantFirstNew+2)
	}
}

// The same crash, in a log that has been pruned: the surviving chain begins
// after the anchor, so a store that finds no record anywhere must continue from
// the anchor rather than from genesis.
func TestRecoveryAfterPruneContinuesFromTheAnchor(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	if _, err := testPolicy().Enforce(dir, EnforceOptions{Reason: "test"}); err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	anchor, err := ReadPruneAnchor(dir)
	if err != nil || anchor == nil {
		t.Fatalf("expected an anchor: %v", err)
	}

	// Every surviving segment is emptied, the shape a crash leaves when the
	// only records left were in the segment that was about to be written.
	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range segs {
		if err := os.Truncate(seg.Path, 0); err != nil {
			t.Fatal(err)
		}
	}

	s := openTestStore(t, dir, 0)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readRecords(t, segs[len(segs)-1].Path)
	if recs[0].Seq != anchor.LastPrunedSeq+1 {
		t.Errorf("first record after the anchor has seq %d, want %d", recs[0].Seq, anchor.LastPrunedSeq+1)
	}
	if recs[0].PrevHash != anchor.LastPrunedHash {
		t.Errorf("first record links to %s, want the anchor hash %s", recs[0].PrevHash, anchor.LastPrunedHash)
	}
	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("appending after a prune broke verification: %v", res.Problems)
	}
}

// A directory holding nothing but empty segment files is a new log, not a
// pruned one, so the first record starts the chain at genesis.
func TestAllEmptySegmentsStartAtGenesis(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 3; i++ {
		if err := os.WriteFile(filepath.Join(dir, SegmentName(i)), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}

	s := openTestStore(t, dir, 0)
	appendN(t, s, 2)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readRecords(t, filepath.Join(dir, SegmentName(3)))
	if recs[0].Seq != 1 || recs[0].PrevHash != GenesisHash {
		t.Errorf("first record is seq %d linking to %s, want seq 1 linking to the genesis hash", recs[0].Seq, recs[0].PrevHash)
	}
	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a new log in a directory of empty segments does not verify: %v", res.Problems)
	}
}

// An anchor that does not say where the surviving chain begins must stop the
// store rather than let it invent a starting point.
func TestUnusableAnchorRefusesToOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, SegmentName(1)), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := WritePruneAnchor(dir, PruneAnchor{
		Version:       PruneAnchorVersion,
		PrunedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		LastPrunedSeq: 40,
		Reason:        "hash missing",
	}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err == nil {
		s.Close()
		t.Fatal("Open accepted an anchor that names no record hash")
	}
	if !strings.Contains(err.Error(), PruneAnchorFile) {
		t.Errorf("error does not name the file to repair: %v", err)
	}
}
