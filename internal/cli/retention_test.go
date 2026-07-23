package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// recentLog writes a log every record of which is inside the retention floor,
// which is the state the size cap has to be able to report on without being
// able to act on it.
func recentLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir, SegmentMaxBytes: 2048})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := store.Append(&evidence.Event{
			EventType: evidence.EventInference,
			RequestID: strings.Repeat("r", 24),
			Status:    200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func evidenceBytes(t *testing.T, dir string) int64 {
	t.Helper()
	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, s := range segs {
		info, err := os.Stat(s.Path)
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	return total
}

func retentionJSON(t *testing.T, out string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("retention --json is not JSON: %v\n%s", err, out)
	}
}

func TestRetentionReportsTheSizeCapItIsGiven(t *testing.T) {
	dir := recentLog(t)
	total := evidenceBytes(t, dir)
	limit := total / 2

	code, out := runCLI(t, "retention", "--dir", dir, "--max-bytes", itoa(limit), "--json")
	if code != 0 {
		t.Fatalf("retention exited %d\n%s", code, out)
	}
	var rep evidence.RetentionReport
	retentionJSON(t, out, &rep)

	if rep.MaxBytes != limit {
		t.Errorf("max_bytes = %d, want %d", rep.MaxBytes, limit)
	}
	if rep.Bytes != total {
		t.Errorf("bytes = %d, want %d", rep.Bytes, total)
	}
	if !rep.OverCap {
		t.Fatal("a directory holding twice the cap is not reported as over it")
	}
	if rep.BytesOverCap != total-limit {
		t.Errorf("bytes_over_cap = %d, want %d", rep.BytesOverCap, total-limit)
	}
	if rep.CapNote == "" {
		t.Error("nothing explains what being over the cap means here")
	}
}

func TestRetentionWithoutACapSaysNothingAboutOne(t *testing.T) {
	dir := recentLog(t)

	code, out := runCLI(t, "retention", "--dir", dir, "--json")
	if code != 0 {
		t.Fatalf("retention exited %d\n%s", code, out)
	}
	var rep evidence.RetentionReport
	retentionJSON(t, out, &rep)
	if rep.MaxBytes != 0 || rep.OverCap || rep.CapNote != "" {
		t.Errorf("a run with no cap reported one: %+v", rep)
	}

	code, out = runCLI(t, "retention", "--dir", dir, "--max-bytes", itoa(evidenceBytes(t, dir)*2), "--json")
	if code != 0 {
		t.Fatalf("retention exited %d\n%s", code, out)
	}
	rep = evidence.RetentionReport{}
	retentionJSON(t, out, &rep)
	if rep.OverCap || rep.CapNote != "" {
		t.Errorf("a directory under its cap was reported as over it: %+v", rep)
	}
}

// The cap is a report, never a licence to delete. Enforcement with a cap far
// below the current size must still delete nothing while every record is
// inside the retention floor.
func TestTheSizeCapNeverDeletesInsideTheRetentionFloor(t *testing.T) {
	dir := recentLog(t)
	before, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "retention", "--dir", dir, "--max-bytes", "1", "--enforce", "--confirm", "--json")
	if code != 0 {
		t.Fatalf("retention --enforce exited %d\n%s", code, out)
	}
	var res evidence.EnforceResult
	retentionJSON(t, out, &res)

	if len(res.Deleted) != 0 {
		t.Fatalf("the size cap deleted %v from inside the retention floor", res.Deleted)
	}
	after, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("segments went from %d to %d with nothing beyond retention", len(before), len(after))
	}
	if _, err := os.Stat(filepath.Join(dir, evidence.PruneAnchorFile)); err == nil {
		t.Error("a run that deleted nothing wrote a prune anchor")
	}

	if !res.OverCap || res.CapNote == "" {
		t.Fatalf("the run left the directory over its cap and did not say so: %+v", res)
	}
	if res.MaxBytes != 1 {
		t.Errorf("max_bytes = %d, want 1", res.MaxBytes)
	}
	if res.RetainedBytes != evidenceBytes(t, dir) {
		t.Errorf("retained_bytes = %d, want %d", res.RetainedBytes, evidenceBytes(t, dir))
	}
}

// The note comes from internal/evidence and is the sentence that says why
// nothing was deleted. The text output must carry it as written rather than a
// paraphrase, so that both outputs describe the same decision.
func TestTheTextOutputCarriesTheCapNoteAsWritten(t *testing.T) {
	dir := recentLog(t)
	limit := evidenceBytes(t, dir) / 4

	policy := evidence.RetentionPolicy{MinDays: config.RetentionFloorDays, MaxBytes: limit}
	want, err := policy.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want.CapNote == "" {
		t.Fatal("this fixture is not over its cap")
	}

	code, out := runCLI(t, "retention", "--dir", dir, "--max-bytes", itoa(limit))
	if code != 0 {
		t.Fatalf("retention exited %d\n%s", code, out)
	}
	if !strings.Contains(out, want.CapNote) {
		t.Errorf("the text output does not carry the cap note as written.\nwant: %s\ngot:\n%s", want.CapNote, out)
	}
}

// An enforcement run that dies part way through has already deleted evidence.
// The error alone says which unlink failed and nothing about how far the run
// got, so the result has to be reported even though the command fails.
func TestAFailedEnforcementStillReportsWhatItDid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a read-only directory does not stop a delete on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root deletes from a read-only directory")
	}
	dir := t.TempDir()
	// Two zero-byte segments: the older one is deletable regardless of age,
	// because there is nothing in it for retention to protect, and a run that
	// deletes no record writes no prune anchor. That is the one shape where
	// enforcement reaches the unlink without having written to the directory
	// first, which is what lets the mode below stop it there.
	for i := 1; i <= 2; i++ {
		if err := os.WriteFile(filepath.Join(dir, evidence.SegmentName(i)), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "retention", "--dir", dir, "--enforce", "--confirm")
	if code == 0 {
		t.Fatalf("a deletion that could not be carried out exited 0\n%s", out)
	}
	if out == "" {
		t.Fatal("the run printed nothing, so the operator is told only that one unlink failed and nothing about the state of the directory")
	}
	if !strings.Contains(out, evidence.SegmentName(1)) {
		t.Errorf("the output does not name the segment the run was working on:\n%s", out)
	}
	if strings.Contains(out, "retention enforced") {
		t.Errorf("a run that failed part way through reported itself as enforced:\n%s", out)
	}

	// The JSON path carries the same account. A caller that sees only a
	// non-zero exit code cannot tell a refusal that deleted nothing from a
	// prune that stopped half way through.
	code, out = runCLI(t, "retention", "--dir", dir, "--enforce", "--confirm", "--json")
	if code == 0 {
		t.Fatalf("a deletion that could not be carried out exited 0\n%s", out)
	}
	var res evidence.EnforceResult
	retentionJSON(t, out, &res)
	if len(res.Eligible) == 0 {
		t.Errorf("the emitted result names no segment the run was working on: %+v", res)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, evidence.SegmentName(1))); err != nil {
		t.Fatalf("the segment was deleted after all, so this test proves nothing: %v", err)
	}
}

func TestRetentionRefusesANegativeCap(t *testing.T) {
	dir := recentLog(t)
	if code, out := runCLI(t, "retention", "--dir", dir, "--max-bytes", "-1"); code == 0 {
		t.Fatalf("a negative size cap was accepted\n%s", out)
	}
}

// itoa keeps the flag values in these tests as the command line sees them.
func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
