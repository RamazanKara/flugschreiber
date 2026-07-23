package evidence

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleCheckpoint() Checkpoint {
	return Checkpoint{
		Version:    CheckpointVersion,
		Segment:    "seg-00000002.jsonl",
		Seq:        42,
		RecordHash: strings.Repeat("ab", 32),
		Records:    42,
		Timestamp:  "2026-03-01T12:00:00Z",
		KeyID:      "0123456789abcdef",
	}
}

// The preimage is the one thing a third-party verifier has to reimplement byte
// for byte. Pinning it here means a refactor cannot quietly invalidate every
// signature ever written.
func TestCheckpointPreimageIsExactlyTheDocumentedBytes(t *testing.T) {
	want := "flugschreiber-checkpoint-v1\n" +
		"version:1\n" +
		"segment:seg-00000002.jsonl\n" +
		"seq:42\n" +
		"record_hash:" + strings.Repeat("ab", 32) + "\n" +
		"records:42\n" +
		"timestamp:2026-03-01T12:00:00Z\n" +
		"key_id:0123456789abcdef\n"

	if got := string(CheckpointPreimage(sampleCheckpoint())); got != want {
		t.Errorf("preimage mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestCheckpointPreimageExcludesTheSignature(t *testing.T) {
	c := sampleCheckpoint()
	before := string(CheckpointPreimage(c))
	c.Signature = strings.Repeat("ff", 64)
	if after := string(CheckpointPreimage(c)); after != before {
		t.Error("the signature is covered by its own preimage, which makes verification impossible")
	}
}

func TestSignedCheckpointVerifiesAndAnyEditBreaksIt(t *testing.T) {
	kp, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	edits := []struct {
		name string
		edit func(*Checkpoint)
	}{
		{"segment", func(c *Checkpoint) { c.Segment = "seg-00000009.jsonl" }},
		{"seq", func(c *Checkpoint) { c.Seq = 43 }},
		{"record hash", func(c *Checkpoint) { c.RecordHash = strings.Repeat("cd", 32) }},
		{"records", func(c *Checkpoint) { c.Records = 41 }},
		{"timestamp", func(c *Checkpoint) { c.Timestamp = "2026-03-01T12:00:01Z" }},
		{"version", func(c *Checkpoint) { c.Version = 2 }},
		{"key id", func(c *Checkpoint) { c.KeyID = "ffffffffffffffff" }},
	}

	for _, tc := range edits {
		t.Run(tc.name, func(t *testing.T) {
			c := sampleCheckpoint()
			if err := SignCheckpoint(kp.Private, kp.ID, &c); err != nil {
				t.Fatal(err)
			}
			if err := VerifyCheckpointSignature(kp.Public, c); err != nil {
				t.Fatalf("a freshly signed checkpoint did not verify: %v", err)
			}
			tc.edit(&c)
			if err := VerifyCheckpointSignature(kp.Public, c); err == nil {
				t.Fatalf("editing the %s left the signature valid", tc.name)
			}
		})
	}
}

func TestCheckpointDoesNotVerifyAgainstAnotherKey(t *testing.T) {
	mine, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	c := sampleCheckpoint()
	if err := SignCheckpoint(mine.Private, mine.ID, &c); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointSignature(theirs.Public, c); err == nil {
		t.Fatal("a checkpoint verified against a key that did not sign it")
	}
}

func TestSignCheckpointRefusesAnEmptyKeyID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := sampleCheckpoint()
	if err := SignCheckpoint(priv, "", &c); err == nil {
		t.Fatal("signing with no key id was allowed; nobody could attribute the result")
	}
}

func TestAppendCheckpointOnlyEverAppends(t *testing.T) {
	dir := t.TempDir()
	for seq := uint64(1); seq <= 3; seq++ {
		c := sampleCheckpoint()
		c.Seq = seq
		if err := AppendCheckpoint(dir, c); err != nil {
			t.Fatalf("AppendCheckpoint %d: %v", seq, err)
		}
	}

	got, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatalf("ReadCheckpoints: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d checkpoints, want 3", len(got))
	}
	for i, c := range got {
		if c.Seq != uint64(i+1) {
			t.Errorf("checkpoint %d has seq %d, want %d; order was not preserved", i, c.Seq, i+1)
		}
	}
}

func TestReadCheckpointsOnAnAbsentFileIsNotAnError(t *testing.T) {
	got, err := ReadCheckpoints(t.TempDir())
	if err != nil {
		t.Fatalf("ReadCheckpoints: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil for a log that has never been checkpointed", got)
	}
}

// Corrupting a checkpoint must not be a way to make it disappear quietly.
func TestReadCheckpointsReportsAnUnparseableLine(t *testing.T) {
	dir := t.TempDir()
	if err := AppendCheckpoint(dir, sampleCheckpoint()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, CheckpointsFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{not json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, err := ReadCheckpoints(dir); err == nil {
		t.Fatal("a corrupt checkpoint line was skipped instead of reported")
	}
}

func TestStoreCheckpointsOnRotationAndOnClose(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(Options{Dir: dir, SegmentMaxBytes: 400, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) < 2 {
		t.Fatalf("got %d checkpoints, want at least one per rotation plus one at shutdown", len(checks))
	}
	if uint64(len(checks)) != s.Checkpoints() {
		t.Errorf("Checkpoints() = %d, but %d are on disk", s.Checkpoints(), len(checks))
	}

	last := checks[len(checks)-1]
	if last.Seq != 12 {
		t.Errorf("the shutdown checkpoint covers seq %d, want 12", last.Seq)
	}
	if err := VerifyCheckpointSignature(kp.Public, last); err != nil {
		t.Errorf("shutdown checkpoint does not verify: %v", err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a checkpointed log did not verify: %v", res.Problems)
	}
	if !res.Attested {
		t.Error("Attested is false although every checkpoint verified against the chain")
	}
	if res.CheckpointsVerified != len(checks) {
		t.Errorf("CheckpointsVerified = %d, want %d", res.CheckpointsVerified, len(checks))
	}
}

func TestEmptyLogIsNeverCheckpointed(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 0 {
		t.Fatalf("an empty log produced %d checkpoints", len(checks))
	}
}

func TestIdleLogIsNotCheckpointedRepeatedly(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, CheckpointInterval: time.Millisecond, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 1)
	time.Sleep(30 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 {
		t.Fatalf("an idle log wrote %d checkpoints in 30 timer ticks, want 1", len(checks))
	}
}

// This is the attack the hash chain alone cannot see: the whole log rewritten
// consistently. The checkpoint still names the old head.
func TestRewrittenLogContradictsItsCheckpoints(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 5)
	s.Close()

	path := filepath.Join(dir, SegmentName(1))
	recs := readRecords(t, path)
	prev := GenesisHash
	for i := range recs {
		recs[i].Event = json.RawMessage(`{"schema_version":1,"event_type":"inference","request_id":"rewritten","status":200}`)
		recs[i].PrevHash = prev
		recs[i].RecordHash = ComputeHash(recs[i].Seq, recs[i].Timestamp, prev, recs[i].Event)
		prev = recs[i].RecordHash
	}
	writeRecords(t, path, recs)

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an end-to-end rewrite went undetected")
	}
	var sawMismatch bool
	for _, p := range res.Problems {
		if p.Kind == ProblemCheckpointMismatch {
			sawMismatch = true
			if p.Severity != SeverityHigh {
				t.Errorf("checkpoint mismatch reported at severity %q, want %q", p.Severity, SeverityHigh)
			}
		}
	}
	if !sawMismatch {
		t.Errorf("expected a checkpoint_mismatch problem, got %v", res.Problems)
	}
	if res.Attested {
		t.Error("a rewritten log was reported as attested")
	}
}

func TestUncheckpointedLogIsReportedAsUnattested(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	appendN(t, s, 3)
	s.Close()

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("expected an intact chain: %v", res.Problems)
	}
	if res.Attested {
		t.Fatal("a log with no checkpoints was reported as attested")
	}
	if len(res.Notes) == 0 {
		t.Fatal("a log with no checkpoints carried no note saying so")
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "no checkpoints") {
		t.Errorf("notes do not mention the missing checkpoints: %v", res.Notes)
	}
}

func TestCheckpointForARecordThatIsNotInTheLogIsAProblem(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 4)
	s.Close()

	// Truncate the tail of the log after it was attested to.
	recs := readRecords(t, filepath.Join(dir, SegmentName(1)))
	writeRecords(t, filepath.Join(dir, SegmentName(1)), recs[:2])

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("truncating an attested log went undetected")
	}
}
