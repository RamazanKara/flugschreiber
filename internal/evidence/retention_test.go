package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// enforcementNow is the moment every retention test pretends it is.
var enforcementNow = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

func at(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 9, 0, 0, 0, time.UTC)
}

// buildLog writes a correctly chained log where each inner slice becomes one
// segment with records carrying the given timestamps. Writing the files
// directly is what lets a test place a record's age in a specific segment.
func buildLog(t *testing.T, dir string, segments [][]time.Time) {
	t.Helper()
	prev := GenesisHash
	var seq uint64
	for i, times := range segments {
		var b strings.Builder
		for _, ts := range times {
			seq++
			payload := json.RawMessage(`{"schema_version":1,"event_type":"inference","request_id":"r"}`)
			stamp := ts.UTC().Format(time.RFC3339Nano)
			rec := Record{
				Seq:        seq,
				Timestamp:  stamp,
				PrevHash:   prev,
				RecordHash: ComputeHash(seq, stamp, prev, payload),
				Event:      payload,
			}
			line, err := json.Marshal(&rec)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(line)
			b.WriteByte('\n')
			prev = rec.RecordHash
		}
		if err := os.WriteFile(filepath.Join(dir, SegmentName(i+1)), []byte(b.String()), 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func testPolicy() RetentionPolicy {
	return RetentionPolicy{MinDays: 180, Now: func() time.Time { return enforcementNow }}
}

// A log with two segments fully beyond retention, one straddling the cutoff,
// and one still being written.
func agedLog(t *testing.T, dir string) {
	t.Helper()
	buildLog(t, dir, [][]time.Time{
		{at(2025, 1, 5), at(2025, 1, 6)},
		{at(2025, 2, 1), at(2025, 2, 2)},
		{at(2025, 3, 1), at(2026, 6, 1)},
		{at(2026, 6, 20)},
	})
}

func TestInspectReportsAgeAndDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	rep, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(rep.Segments) != 4 {
		t.Fatalf("reported %d segments, want 4", len(rep.Segments))
	}
	if rep.Records != 7 {
		t.Errorf("Records = %d, want 7", rep.Records)
	}

	want := []bool{true, true, false, false}
	for i, st := range rep.Segments {
		if st.BeyondRetention != want[i] {
			t.Errorf("%s: BeyondRetention = %v, want %v", st.Segment, st.BeyondRetention, want[i])
		}
		if st.Records == 0 {
			t.Errorf("%s: no records counted", st.Segment)
		}
		if st.Bytes == 0 {
			t.Errorf("%s: no size reported", st.Segment)
		}
		if st.NewestTime == "" {
			t.Errorf("%s: no newest record time reported", st.Segment)
		}
	}
	if !rep.Segments[3].Active {
		t.Error("the last segment is not marked as the one being written")
	}
	if strings.Join(rep.Eligible, ",") != "seg-00000001.jsonl,seg-00000002.jsonl" {
		t.Errorf("Eligible = %v", rep.Eligible)
	}

	// Nothing was removed and nothing was created.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Errorf("Inspect changed the directory: %d entries, want 4", len(entries))
	}
}

func TestEnforceDeletesOnlyWholeSegmentsFromTheFront(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if strings.Join(res.Deleted, ",") != "seg-00000001.jsonl,seg-00000002.jsonl" {
		t.Fatalf("Deleted = %v, want the first two segments only", res.Deleted)
	}
	for _, name := range res.Deleted {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still on disk", name)
		}
	}
	for _, name := range []string{SegmentName(3), SegmentName(4)} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was deleted although it holds records inside retention", name)
		}
	}
	if res.RetainedRecords != 3 {
		t.Errorf("RetainedRecords = %d, want 3", res.RetainedRecords)
	}
}

// A segment holding one record still inside retention blocks everything behind
// it, because deletion is whole-segment only and the log has to stay a prefix.
func TestSegmentWithOneYoungRecordIsNotDeleted(t *testing.T) {
	dir := t.TempDir()
	buildLog(t, dir, [][]time.Time{
		{at(2025, 1, 5), at(2026, 6, 1)},
		{at(2025, 1, 6)},
		{at(2026, 6, 20)},
	})

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("deleted %v although the front segment holds a record inside retention", res.Deleted)
	}
}

func TestActiveSegmentIsNeverDeleted(t *testing.T) {
	dir := t.TempDir()
	buildLog(t, dir, [][]time.Time{
		{at(2025, 1, 5)},
		{at(2025, 1, 6)},
	})

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if strings.Join(res.Deleted, ",") != SegmentName(1) {
		t.Fatalf("Deleted = %v, want only the first segment", res.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dir, SegmentName(2))); err != nil {
		t.Fatalf("the segment being written was deleted although every record in it is beyond retention: %v", err)
	}
}

func TestLegalHoldBlocksDeletionAndStatesItsReason(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	reason := "Bundesnetzagentur enquiry 2026-114, hold until closed"
	if err := os.WriteFile(filepath.Join(dir, LegalHoldFile), []byte(reason+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !res.Hold.InForce {
		t.Fatal("the hold was not reported as in force")
	}
	if res.Hold.Reason != reason {
		t.Errorf("Hold.Reason = %q, want %q", res.Hold.Reason, reason)
	}
	if len(res.Deleted) != 0 {
		t.Errorf("deleted %v while a legal hold was in force", res.Deleted)
	}
	if res.AnchorWritten {
		t.Error("a prune anchor was written while a legal hold was in force")
	}
	if len(res.Eligible) == 0 {
		t.Error("the result does not say what the hold is holding")
	}
	if _, err := os.Stat(filepath.Join(dir, SegmentName(1))); err != nil {
		t.Errorf("seg-00000001.jsonl was deleted under a hold: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, PruneAnchorFile)); !os.IsNotExist(err) {
		t.Error("pruned.json exists although nothing was pruned")
	}
}

func TestHoldWithNoReasonStillNamesTheFile(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	if err := os.WriteFile(filepath.Join(dir, LegalHoldFile), []byte("   \n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Hold.InForce || !strings.Contains(res.Hold.Reason, LegalHoldFile) {
		t.Errorf("Hold = %+v, want a reason pointing at the file", res.Hold)
	}
}

func TestDryRunReportsExactlyWhatWouldHappenAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	dry, err := testPolicy().Enforce(dir, EnforceOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Enforce dry run: %v", err)
	}
	if len(dry.Deleted) != 0 {
		t.Errorf("a dry run reported deletions: %v", dry.Deleted)
	}
	if dry.AnchorWritten {
		t.Error("a dry run wrote the anchor")
	}
	if strings.Join(dry.Eligible, ",") != "seg-00000001.jsonl,seg-00000002.jsonl" {
		t.Errorf("Eligible = %v", dry.Eligible)
	}
	if dry.EligibleRecords != 4 {
		t.Errorf("EligibleRecords = %d, want 4", dry.EligibleRecords)
	}

	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("a dry run changed the directory: %d entries, was %d", len(after), len(before))
	}

	wet, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(wet.Deleted, ",") != strings.Join(dry.Eligible, ",") {
		t.Errorf("the real run deleted %v, the dry run predicted %v", wet.Deleted, dry.Eligible)
	}
}

func TestPrunedLogVerifiesFromTheAnchorAndSaysItIsPruned(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	agedLog(t, dir)

	res, err := testPolicy().Enforce(dir, EnforceOptions{Keys: kp, Reason: "retention"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !res.AnchorWritten {
		t.Fatal("no anchor was written")
	}

	ver, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ver.OK() {
		t.Fatalf("a pruned log did not verify: %v", ver.Problems)
	}
	if !ver.Pruned {
		t.Fatal("a pruned log was reported as intact from genesis, which is exactly what must never happen")
	}
	if ver.PrunedThroughSeq != res.LastPrunedSeq {
		t.Errorf("PrunedThroughSeq = %d, want %d", ver.PrunedThroughSeq, res.LastPrunedSeq)
	}
	if ver.PrunedRecords != 4 {
		t.Errorf("PrunedRecords = %d, want 4", ver.PrunedRecords)
	}
	if ver.FirstSeq != res.LastPrunedSeq+1 {
		t.Errorf("the surviving log starts at seq %d, want %d", ver.FirstSeq, res.LastPrunedSeq+1)
	}

	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPruneAnchorSignature(kp.Public, *anchor); err != nil {
		t.Errorf("the anchor signature does not verify: %v", err)
	}
}

// The anchor has to name the hash of the last deleted record, which can only be
// read before that record's file is removed.
func TestAnchorCarriesTheHashOfTheLastDeletedRecord(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	recs := readRecords(t, filepath.Join(dir, SegmentName(2)))
	want := recs[len(recs)-1]

	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err != nil {
		t.Fatal(err)
	}
	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.LastPrunedSeq != want.Seq {
		t.Errorf("LastPrunedSeq = %d, want %d", anchor.LastPrunedSeq, want.Seq)
	}
	if anchor.LastPrunedHash != want.RecordHash {
		t.Errorf("LastPrunedHash = %s, want %s", anchor.LastPrunedHash, want.RecordHash)
	}

	survivor := readRecords(t, filepath.Join(dir, SegmentName(3)))[0]
	if survivor.PrevHash != anchor.LastPrunedHash {
		t.Error("the first surviving record does not link to the anchor, so the log cannot be walked")
	}
}

func TestPruningTwiceAccumulatesInOneAnchor(t *testing.T) {
	dir := t.TempDir()
	buildLog(t, dir, [][]time.Time{
		{at(2025, 1, 1)},
		{at(2025, 2, 1)},
		{at(2025, 3, 1)},
		{at(2026, 6, 20)},
	})

	first := RetentionPolicy{MinDays: 180, Now: func() time.Time { return time.Date(2025, 8, 15, 0, 0, 0, 0, time.UTC) }}
	if _, err := first.Enforce(dir, EnforceOptions{}); err != nil {
		t.Fatalf("first Enforce: %v", err)
	}
	second, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("second Enforce: %v", err)
	}
	if len(second.Deleted) == 0 {
		t.Fatal("the second run deleted nothing although more segments had aged out")
	}

	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchor.Segments) != 3 {
		t.Errorf("Segments = %v, want every segment ever pruned", anchor.Segments)
	}
	if anchor.Records != 3 {
		t.Errorf("Records = %d, want the total ever pruned", anchor.Records)
	}
	ver, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ver.OK() {
		t.Fatalf("a twice-pruned log did not verify: %v", ver.Problems)
	}
}

func TestSecondEnforceWithNothingNewToDoDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err != nil {
		t.Fatal(err)
	}
	again, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("second Enforce: %v", err)
	}
	if len(again.Deleted) != 0 {
		t.Errorf("the second run deleted %v", again.Deleted)
	}
	if again.AnchorWritten {
		t.Error("the second run rewrote the anchor although it pruned nothing")
	}
}

func TestEnforceRefusesWithoutAMinimumRetention(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	for _, days := range []int{0, -1} {
		p := RetentionPolicy{MinDays: days, Now: func() time.Time { return enforcementNow }}
		if _, err := p.Enforce(dir, EnforceOptions{}); err == nil {
			t.Fatalf("MinDays %d was accepted", days)
		}
		if _, err := p.Inspect(dir); err == nil {
			t.Fatalf("Inspect accepted MinDays %d", days)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, SegmentName(1))); err != nil {
		t.Error("segments were deleted by a policy that was rejected")
	}
}

// If the chain is already broken at the cut, pruning would make the break
// permanent and indistinguishable from tampering.
func TestEnforceRefusesWhenTheChainDoesNotLinkAcrossTheCut(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	path := filepath.Join(dir, SegmentName(3))
	recs := readRecords(t, path)
	recs[0].PrevHash = strings.Repeat("11", 32)
	writeRecords(t, path, recs)

	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err == nil {
		t.Fatal("pruning a log whose chain is broken at the cut was allowed")
	}
	if _, err := os.Stat(filepath.Join(dir, SegmentName(1))); err != nil {
		t.Error("segments were deleted despite the refusal")
	}
}

// An anchor that already reaches further than this run would is a sign that
// the log and the anchor do not belong together, most likely a restore from a
// backup taken at a different time.
func TestEnforceRefusesToMoveAnExistingAnchorBackwards(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	if err := WritePruneAnchor(dir, PruneAnchor{
		Version:        PruneAnchorVersion,
		PrunedAt:       enforcementNow.Format(time.RFC3339Nano),
		LastPrunedSeq:  9999,
		LastPrunedHash: strings.Repeat("33", 32),
		Segments:       []string{"seg-00000900.jsonl"},
		Records:        9999,
		Reason:         "an earlier, larger prune",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err == nil {
		t.Fatal("a prune that would rewind the anchor was allowed")
	}
	if _, err := os.Stat(filepath.Join(dir, SegmentName(1))); err != nil {
		t.Error("segments were deleted despite the refusal")
	}
}

func TestEnforceRefusesALogItCannotFullyRead(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	path := filepath.Join(dir, SegmentName(1))
	if err := os.WriteFile(path, []byte("{not a record\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err == nil {
		t.Fatal("a log with an unreadable record was pruned anyway")
	}
	if _, err := os.Stat(filepath.Join(dir, SegmentName(2))); err != nil {
		t.Error("segments were deleted despite the refusal")
	}
}

func TestRecordWithAnUnreadableTimestampKeepsItsSegment(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	path := filepath.Join(dir, SegmentName(1))
	recs := readRecords(t, path)
	recs[0].Timestamp = "some time last year"
	writeRecords(t, path, recs)

	res, err := testPolicy().Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Errorf("deleted %v although the age of a record could not be established", res.Deleted)
	}
}

// The anchor is written and fsynced before the first unlink. If it cannot be
// written, nothing may be deleted: a gap with no anchor can never be explained
// afterwards.
func TestNothingIsDeletedWhenTheAnchorCannotBeWritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not block writes on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	agedLog(t, dir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err == nil {
		t.Fatal("enforcement succeeded although the anchor could not be written")
	}
	for i := 1; i <= 4; i++ {
		if _, err := os.Stat(filepath.Join(dir, SegmentName(i))); err != nil {
			t.Errorf("%s was deleted although no anchor exists to explain it", SegmentName(i))
		}
	}
}

// An interrupted prune leaves an anchor ahead of the log. That is recoverable
// and must be reported as such rather than as a broken chain.
func TestAnchorAheadOfTheLogIsReportedAsAnIncompletePrune(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	dry, err := testPolicy().Enforce(dir, EnforceOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePruneAnchor(dir, PruneAnchor{
		Version:        PruneAnchorVersion,
		PrunedAt:       enforcementNow.Format(time.RFC3339Nano),
		LastPrunedSeq:  dry.LastPrunedSeq,
		LastPrunedHash: dry.LastPrunedHash,
		Segments:       dry.Eligible,
		Records:        dry.EligibleRecords,
		Reason:         "interrupted run",
	}); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	kinds := problemKinds(res)
	if !kinds[ProblemPruneIncomplete] {
		t.Fatalf("expected a prune_incomplete problem, got %v", res.Problems)
	}
	if kinds[ProblemBrokenLink] || kinds[ProblemSeqGap] {
		t.Errorf("an interrupted prune was reported as chain damage: %v", res.Problems)
	}

	// Finishing the prune clears it.
	if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err != nil {
		t.Fatalf("re-running enforcement after an interrupted prune: %v", err)
	}
	res, err = Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("finishing the prune did not clear the problem: %v", res.Problems)
	}
}

func TestTamperedAnchorIsDetected(t *testing.T) {
	cases := []struct {
		name string
		edit func(*PruneAnchor)
		kind string
	}{
		{"hash replaced", func(a *PruneAnchor) { a.LastPrunedHash = strings.Repeat("22", 32) }, ProblemBrokenLink},
		// Moving the anchor past the end of the log leaves it attesting to a
		// record at seq 99 that this log never reaches, which anchorWatch
		// diagnoses as a mismatch rather than a gap: there is no gap to point
		// at, the anchor simply does not describe this log.
		{"seq moved", func(a *PruneAnchor) { a.LastPrunedSeq = 99 }, ProblemAnchorMismatch},
		{"hash emptied", func(a *PruneAnchor) { a.LastPrunedHash = "" }, ProblemBadAnchor},
		{"unknown version", func(a *PruneAnchor) { a.Version = 7 }, ProblemBadAnchor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			agedLog(t, dir)
			if _, err := testPolicy().Enforce(dir, EnforceOptions{}); err != nil {
				t.Fatal(err)
			}
			anchor, err := ReadPruneAnchor(dir)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(anchor)
			if err := WritePruneAnchor(dir, *anchor); err != nil {
				t.Fatal(err)
			}

			res, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() {
				t.Fatalf("tampering with the anchor (%s) went undetected", tc.name)
			}
			if !problemKinds(res)[tc.kind] {
				t.Errorf("expected a %s problem, got %v", tc.kind, res.Problems)
			}
		})
	}
}

func TestForgedAnchorSignatureIsDetected(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	agedLog(t, dir)
	if _, err := testPolicy().Enforce(dir, EnforceOptions{Keys: kp}); err != nil {
		t.Fatal(err)
	}

	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	anchor.Reason = "an operator can edit this freely"
	anchor.Signature = strings.Repeat("ab", 64)
	if err := WritePruneAnchor(dir, *anchor); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !problemKinds(res)[ProblemBadSignature] {
		t.Fatalf("a forged anchor signature went undetected: %v", res.Problems)
	}
}

// A checkpoint whose record was deleted by retention is not evidence of
// tampering, and a checkpoint of a surviving record must still be checked.
func TestCheckpointsOverPrunedRecordsDoNotBreakVerification(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	agedLog(t, dir)

	for _, spec := range []struct {
		segment string
		rec     Record
	}{
		{SegmentName(2), readRecords(t, filepath.Join(dir, SegmentName(2)))[1]},
		{SegmentName(4), readRecords(t, filepath.Join(dir, SegmentName(4)))[0]},
	} {
		c := Checkpoint{
			Segment:    spec.segment,
			Seq:        spec.rec.Seq,
			RecordHash: spec.rec.RecordHash,
			Records:    spec.rec.Seq,
			Timestamp:  spec.rec.Timestamp,
		}
		if err := SignCheckpoint(kp.Private, kp.ID, &c); err != nil {
			t.Fatal(err)
		}
		if err := AppendCheckpoint(dir, c); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := testPolicy().Enforce(dir, EnforceOptions{Keys: kp}); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("pruning records that a checkpoint covered was reported as damage: %v", res.Problems)
	}
	if !res.Attested {
		t.Error("the checkpoint covering a surviving record did not count as attestation")
	}
	if res.CheckpointsVerified != 1 {
		t.Errorf("CheckpointsVerified = %d, want 1", res.CheckpointsVerified)
	}
}

func TestInspectReportsAHoldWithoutTouchingAnything(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	if err := os.WriteFile(filepath.Join(dir, LegalHoldFile), []byte("litigation"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Hold.InForce || rep.Hold.Reason != "litigation" {
		t.Errorf("Hold = %+v", rep.Hold)
	}
}

func TestEnforceOnAnEmptyDirectoryIsANoOp(t *testing.T) {
	res, err := testPolicy().Enforce(t.TempDir(), EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 0 || res.AnchorWritten {
		t.Errorf("an empty directory produced %+v", res)
	}
}
