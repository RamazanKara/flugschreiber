package evidence

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// cappedPolicy is the standard test policy with a size cap added.
func cappedPolicy(maxBytes int64) RetentionPolicy {
	p := testPolicy()
	p.MaxBytes = maxBytes
	return p
}

// youngLog is a log where every record is comfortably inside retention, which
// is the situation the cap is not allowed to resolve.
func youngLog(t *testing.T, dir string) {
	t.Helper()
	buildLog(t, dir, [][]time.Time{
		{at(2026, 6, 1), at(2026, 6, 2)},
		{at(2026, 6, 10), at(2026, 6, 11)},
		{at(2026, 6, 20)},
	})
}

// This is the case the pressure valve exists for and the one it must refuse:
// the disk is full, and the only way to free space would be to delete evidence
// the retention floor still covers. The tool says so and deletes nothing.
func TestOverTheCapButInsideRetentionDeletesNothingAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	youngLog(t, dir)

	sized, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	limit := sized.Bytes / 2
	if limit == 0 {
		t.Fatal("the fixture is too small to be over any cap")
	}

	res, err := cappedPolicy(limit).Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("deleted %v although every record is inside the retention floor", res.Deleted)
	}
	if res.AnchorWritten {
		t.Error("a prune anchor was written although nothing was pruned")
	}
	if !res.OverCap {
		t.Fatal("the result does not say the directory is over its cap")
	}
	if res.MaxBytes != limit {
		t.Errorf("MaxBytes = %d, want %d", res.MaxBytes, limit)
	}
	if want := res.RetainedBytes - limit; res.BytesOverCap != want {
		t.Errorf("BytesOverCap = %d, want %d", res.BytesOverCap, want)
	}
	for _, want := range []string{
		strconv.FormatInt(limit, 10),
		"retention floor",
		strconv.Itoa(res.MinDays),
	} {
		if !strings.Contains(res.CapNote, want) {
			t.Errorf("the refusal does not mention %q: %q", want, res.CapNote)
		}
	}

	for i := 1; i <= 3; i++ {
		if _, err := os.Stat(filepath.Join(dir, SegmentName(i))); err != nil {
			t.Errorf("%s was deleted to satisfy a size cap: %v", SegmentName(i), err)
		}
	}
}

// Beyond-retention segments go oldest first, and when that is enough the run
// ends under the cap with nothing to report.
func TestDeletingBeyondRetentionSegmentsBringsTheDirectoryUnderTheCap(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	sized, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sized.EligibleBytes == 0 {
		t.Fatal("the fixture has nothing beyond retention")
	}
	// A cap that exactly fits what survives: over it before the run, under it
	// after.
	limit := sized.Bytes - sized.EligibleBytes
	if sized.Bytes <= limit {
		t.Fatal("the fixture is not over the cap to begin with")
	}

	res, err := cappedPolicy(limit).Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if strings.Join(res.Deleted, ",") != "seg-00000001.jsonl,seg-00000002.jsonl" {
		t.Fatalf("Deleted = %v, want the two segments beyond retention", res.Deleted)
	}
	if res.OverCap {
		t.Errorf("still reported as over the cap after deleting enough: %q", res.CapNote)
	}
	if res.CapNote != "" {
		t.Errorf("CapNote = %q, want nothing to report", res.CapNote)
	}
	if res.MaxBytes != limit {
		t.Errorf("MaxBytes = %d, want the cap to be reported either way", res.MaxBytes)
	}
	if res.RetainedBytes > limit {
		t.Errorf("RetainedBytes = %d, over the %d cap", res.RetainedBytes, limit)
	}

	ver, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ver.OK() {
		t.Fatalf("trimming to the cap damaged the log: %v", ver.Problems)
	}
}

// However far over the cap the directory is, the floor still holds: the run
// takes what is beyond retention and stops there.
func TestACapFarBelowTheDirectorySizeStillStopsAtTheRetentionFloor(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	res, err := cappedPolicy(1).Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if strings.Join(res.Deleted, ",") != "seg-00000001.jsonl,seg-00000002.jsonl" {
		t.Fatalf("Deleted = %v, want only what is beyond retention", res.Deleted)
	}
	if !res.OverCap {
		t.Error("a directory a thousand times over its cap was not reported as over it")
	}
	for _, name := range []string{SegmentName(3), SegmentName(4)} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s holds records inside retention and was deleted anyway: %v", name, err)
		}
	}
}

func TestInspectReportsTheCapAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	sized, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		limit   int64
		overCap bool
	}{
		{"under the cap", sized.Bytes * 2, false},
		{"over the cap", sized.Bytes / 2, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := cappedPolicy(tc.limit).Inspect(dir)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if rep.MaxBytes != tc.limit {
				t.Errorf("MaxBytes = %d, want %d", rep.MaxBytes, tc.limit)
			}
			if rep.OverCap != tc.overCap {
				t.Errorf("OverCap = %v, want %v (holding %d bytes)", rep.OverCap, tc.overCap, rep.Bytes)
			}
			if tc.overCap && rep.CapNote == "" {
				t.Error("a directory over its cap was reported without a word about it")
			}
			if !tc.overCap && rep.CapNote != "" {
				t.Errorf("CapNote = %q for a directory under its cap", rep.CapNote)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 4 {
				t.Errorf("Inspect changed the directory: %d entries, want 4", len(entries))
			}
		})
	}
}

// A legal hold outranks the cap, as it outranks everything else.
func TestALegalHoldOutranksTheSizeCap(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)
	if err := os.WriteFile(filepath.Join(dir, LegalHoldFile), []byte("enquiry 2026-114"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := cappedPolicy(1).Enforce(dir, EnforceOptions{})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("deleted %v under a legal hold to satisfy a size cap", res.Deleted)
	}
	if !res.OverCap || !strings.Contains(res.CapNote, "enquiry 2026-114") {
		t.Errorf("the result does not explain that the hold is what is holding: %+v", res.CapNote)
	}
}

// Without a cap the result is exactly what it was before the cap existed.
func TestNoCapReportsNoCap(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	rep, err := testPolicy().Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.MaxBytes != 0 || rep.OverCap || rep.CapNote != "" {
		t.Errorf("Inspect invented a cap: %d, %v, %q", rep.MaxBytes, rep.OverCap, rep.CapNote)
	}

	res, err := testPolicy().Enforce(dir, EnforceOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.MaxBytes != 0 || res.OverCap || res.CapNote != "" {
		t.Errorf("Enforce invented a cap: %d, %v, %q", res.MaxBytes, res.OverCap, res.CapNote)
	}
}

// A dry run says what the directory would look like afterwards, so that an
// operator can find out they are stuck before they are stuck.
func TestDryRunReportsTheCapItWouldStillBeOver(t *testing.T) {
	dir := t.TempDir()
	agedLog(t, dir)

	res, err := cappedPolicy(1).Enforce(dir, EnforceOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Errorf("a dry run deleted %v", res.Deleted)
	}
	if !res.OverCap || !strings.Contains(res.CapNote, "would still hold") {
		t.Errorf("the dry run does not say the cap would still be exceeded: %q", res.CapNote)
	}
}
