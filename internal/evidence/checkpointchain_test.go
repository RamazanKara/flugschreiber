package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chainedLog writes a log with several checkpoints and returns its directory.
func chainedLog(t *testing.T, records int) string {
	t.Helper()
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Small segments so rotation produces a checkpoint every few records.
	s, err := Open(Options{Dir: dir, SegmentMaxBytes: 400, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, records)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readCheckpointLines(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, CheckpointsFile))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeCheckpointLines(t *testing.T, dir string, lines []string) {
	t.Helper()
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, CheckpointsFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The attack this exists to stop: an attacker who cannot forge a signature
// deletes the attestations instead. Every checkpoint left behind still
// verifies, so without linkage the log reports itself as intact and attested.
func TestDeletingACheckpointFromTheMiddleIsDetected(t *testing.T) {
	dir := chainedLog(t, 24)
	lines := readCheckpointLines(t, dir)
	if len(lines) < 3 {
		t.Fatalf("the fixture produced %d checkpoints, it needs at least three", len(lines))
	}

	before, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !before.OK() {
		t.Fatalf("the fixture did not verify: %v", before.Problems)
	}
	if before.ChainedCheckpoints != len(lines) {
		t.Fatalf("ChainedCheckpoints = %d, want %d: the fixture is not chained", before.ChainedCheckpoints, len(lines))
	}

	// Remove one from the middle and leave everything else byte-identical.
	writeCheckpointLines(t, dir, append(append([]string{}, lines[:1]...), lines[2:]...))

	after, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.OK() {
		t.Fatal("deleting a signed checkpoint left the log reporting itself as intact")
	}
	var found bool
	for _, p := range after.Problems {
		if p.Kind == ProblemCheckpointGap && p.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("no high-severity checkpoint_gap was reported: %v", after.Problems)
	}
}

// Deleting from the front leaves the survivors contiguous with each other, so
// the link walk alone cannot see it. The first survivor's own index does.
func TestDeletingCheckpointsFromTheFrontIsDetected(t *testing.T) {
	dir := chainedLog(t, 24)
	lines := readCheckpointLines(t, dir)
	if len(lines) < 3 {
		t.Fatalf("the fixture produced %d checkpoints, it needs at least three", len(lines))
	}

	writeCheckpointLines(t, dir, lines[2:])

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("deleting the first two checkpoints left the log reporting itself as intact")
	}
	var found bool
	for _, p := range res.Problems {
		if p.Kind == ProblemCheckpointGap && strings.Contains(p.Detail, "removed from the beginning") {
			found = true
		}
	}
	if !found {
		t.Errorf("front deletion was not reported: %v", res.Problems)
	}
}

// Renumbering the survivors to close the gap is the obvious next move, and the
// chain signature is what refuses it.
func TestRenumberingASurvivingCheckpointIsRefused(t *testing.T) {
	dir := chainedLog(t, 24)
	lines := readCheckpointLines(t, dir)
	if len(lines) < 3 {
		t.Fatalf("the fixture produced %d checkpoints", len(lines))
	}

	var c Checkpoint
	if err := json.Unmarshal([]byte(lines[2]), &c); err != nil {
		t.Fatal(err)
	}
	// Delete the second checkpoint, then renumber the third to close the gap.
	c.Index--
	edited, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	writeCheckpointLines(t, dir, []string{lines[0], string(edited)})

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a renumbered checkpoint was accepted")
	}
}

// The linkage must not cost backward compatibility: a verifier that predates it
// checks the v1 signature and must still find it valid. Reproduced here by
// verifying with the chain fields stripped, which is exactly what an older
// build's parser leaves behind.
func TestAnOlderVerifierStillValidatesAChainedCheckpoint(t *testing.T) {
	dir := chainedLog(t, 12)
	for _, line := range readCheckpointLines(t, dir) {
		var c Checkpoint
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatal(err)
		}
		if !c.Chained() {
			t.Fatal("the fixture is not chained, so this proves nothing")
		}
		// What a build without the linkage fields would hold after unmarshalling.
		old := Checkpoint{
			Version: c.Version, Segment: c.Segment, Seq: c.Seq,
			RecordHash: c.RecordHash, Records: c.Records,
			Timestamp: c.Timestamp, KeyID: c.KeyID, Signature: c.Signature,
		}
		pub, err := LoadPublicKeyPEM(filepath.Join(dir, PublicKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCheckpointSignature(pub, old); err != nil {
			t.Fatalf("a chained checkpoint does not verify under the v1 rule, so every deployed verifier would call it a forgery: %v", err)
		}
	}
}

// A checkpoint from a future build is unreadable, not forged, and saying
// otherwise accuses an operator of tampering for upgrading.
func TestAnUnknownCheckpointVersionIsNotReportedAsForgery(t *testing.T) {
	dir := chainedLog(t, 8)
	lines := readCheckpointLines(t, dir)

	var c Checkpoint
	if err := json.Unmarshal([]byte(lines[0]), &c); err != nil {
		t.Fatal(err)
	}
	c.Version = CheckpointVersion + 1
	edited, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	writeCheckpointLines(t, dir, append([]string{string(edited)}, lines[1:]...))

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Problems {
		if p.Kind == ProblemBadSignature {
			t.Errorf("a newer checkpoint version was reported as a bad signature, which reads as forgery: %v", p)
		}
	}
	var named bool
	for _, p := range res.Problems {
		if p.Kind == ProblemUnknownCheckpoint && strings.Contains(p.Detail, "was not checked") {
			named = true
		}
	}
	if !named {
		t.Errorf("an unknown checkpoint version was not named as unreadable: %v", res.Problems)
	}
}
