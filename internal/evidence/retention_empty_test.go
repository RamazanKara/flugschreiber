package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shiftSegmentsForEmptyFront renames every segment one index up and leaves a
// zero-byte seg-00000001.jsonl in front of them, which is what a crash between
// rotating and writing the first record into the new file leaves behind.
func shiftSegmentsForEmptyFront(t *testing.T, dir string) {
	t.Helper()
	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(segs) - 1; i >= 0; i-- {
		to := filepath.Join(dir, SegmentName(segs[i].Index+1))
		if err := os.Rename(segs[i].Path, to); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, SegmentName(1)), nil, 0o640); err != nil {
		t.Fatal(err)
	}
}

// A segment holding no records must not park itself in front of the log. Since
// deletion only ever takes a prefix, one zero-byte file that never ages out
// would make every segment behind it unprunable for as long as the log exists.
func TestEmptyLeadingSegmentDoesNotBlockPruning(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	// The last record of what will become seg-00000003, which is the newest
	// record retention is allowed to delete and therefore the anchor point.
	aged := readRecords(t, filepath.Join(dir, SegmentName(2)))
	wantAnchor := aged[len(aged)-1]
	shiftSegmentsForEmptyFront(t, dir)

	res, err := testPolicy().Enforce(dir, EnforceOptions{Reason: "test"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}

	want := []string{SegmentName(1), SegmentName(2), SegmentName(3)}
	if len(res.Deleted) != len(want) {
		t.Fatalf("deleted %v, want %v", res.Deleted, want)
	}
	for i, name := range want {
		if res.Deleted[i] != name {
			t.Fatalf("deleted %v, want %v", res.Deleted, want)
		}
	}
	if !res.AnchorWritten {
		t.Fatal("records were deleted but no anchor was written")
	}
	// The anchor must describe the last deleted record, not the empty file that
	// happened to be deleted with it.
	if res.LastPrunedSeq != wantAnchor.Seq || res.LastPrunedHash != wantAnchor.RecordHash {
		t.Errorf("anchor point = seq %d hash %s, want seq %d hash %s",
			res.LastPrunedSeq, res.LastPrunedHash, wantAnchor.Seq, wantAnchor.RecordHash)
	}

	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.LastPrunedSeq != wantAnchor.Seq || anchor.LastPrunedHash != wantAnchor.RecordHash {
		t.Errorf("pruned.json records seq %d hash %s, want seq %d hash %s",
			anchor.LastPrunedSeq, anchor.LastPrunedHash, wantAnchor.Seq, wantAnchor.RecordHash)
	}
	if anchor.Records != wantAnchor.Seq {
		t.Errorf("pruned.json counts %d deleted records, want %d", anchor.Records, wantAnchor.Seq)
	}
	if len(anchor.Segments) != len(want) {
		t.Errorf("pruned.json names %v, want all three deleted files", anchor.Segments)
	}

	verified, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.OK() {
		t.Fatalf("the pruned log does not verify: %v", verified.Problems)
	}
	if !verified.Pruned {
		t.Error("the log was pruned but Verify does not say so")
	}
}

// Removing only empty files deletes no record, so there is no gap for an anchor
// to explain and none is written. Claiming a prune that removed nothing would
// make a later verifier expect records that never existed.
func TestRemovingOnlyEmptySegmentsWritesNoAnchor(t *testing.T) {
	dir := t.TempDir()
	buildLog(t, dir, [][]time.Time{
		{at(2026, 6, 1)},
		{at(2026, 6, 20)},
	})
	shiftSegmentsForEmptyFront(t, dir)

	res, err := testPolicy().Enforce(dir, EnforceOptions{Reason: "test"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 1 || res.Deleted[0] != SegmentName(1) {
		t.Fatalf("deleted %v, want only the empty segment", res.Deleted)
	}
	if res.AnchorWritten || res.LastPrunedSeq != 0 {
		t.Errorf("an anchor was written for a prune that removed no record: %+v", res)
	}
	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if anchor != nil {
		t.Errorf("%s exists after deleting only empty files: %+v", PruneAnchorFile, anchor)
	}

	verified, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.OK() {
		t.Fatalf("removing an empty file broke verification: %v", verified.Problems)
	}
	if verified.Pruned {
		t.Error("Verify reports the log as pruned although no record was deleted")
	}
}

// The segment being appended to is never deleted, however empty it is: the
// store holds it open, so unlinking it would send the next records into a file
// nobody can read.
func TestEmptyActiveSegmentIsNeverDeleted(t *testing.T) {
	dir := t.TempDir()
	buildLog(t, dir, [][]time.Time{{at(2025, 1, 5)}})
	if err := os.WriteFile(filepath.Join(dir, SegmentName(2)), nil, 0o640); err != nil {
		t.Fatal(err)
	}

	rep, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	active := rep.Segments[len(rep.Segments)-1]
	if active.Eligible {
		t.Errorf("the empty active segment %s is eligible for deletion", active.Segment)
	}

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	for _, name := range res.Deleted {
		if name == SegmentName(2) {
			t.Fatal("the active segment was deleted")
		}
	}
}
