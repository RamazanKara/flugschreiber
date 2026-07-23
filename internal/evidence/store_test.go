package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

func openTestStore(t *testing.T, dir string, maxBytes int64) *Store {
	t.Helper()
	s, err := Open(Options{Dir: dir, SegmentMaxBytes: maxBytes, Now: fixedClock()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func appendN(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := s.Append(&Event{
			EventType: EventInference,
			RequestID: "req-" + string(rune('a'+i%26)),
			Endpoint:  "/v1/chat/completions",
			Status:    200,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func TestAppendedChainVerifies(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	appendN(t, s, 25)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected intact chain, got problems: %v", res.Problems)
	}
	if res.Records != 25 {
		t.Errorf("Records = %d, want 25", res.Records)
	}
	if res.FirstSeq != 1 || res.LastSeq != 25 {
		t.Errorf("sequence range = %d..%d, want 1..25", res.FirstSeq, res.LastSeq)
	}
}

func TestGenesisRecordLinksToZeroHash(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	appendN(t, s, 1)
	s.Close()

	recs := readRecords(t, filepath.Join(dir, SegmentName(1)))
	if recs[0].PrevHash != GenesisHash {
		t.Errorf("first prev_hash = %q, want the genesis hash", recs[0].PrevHash)
	}
}

// A single flipped byte anywhere in a record must break verification. This is
// the property the whole product rests on, so it is tested across every field
// an attacker might want to change.
func TestFlippedByteBreaksChain(t *testing.T) {
	targets := []struct {
		name string
		from string
		to   string
	}{
		{"event content", `"status":200`, `"status":403`},
		{"request id", `"req-a"`, `"req-X"`},
		{"endpoint", `/v1/chat/completions`, `/v1/embeddings`},
		{"timestamp", `2026-03-01T12:00:01Z`, `2026-03-01T12:00:09Z`},
		{"sequence number", `"seq":1,`, `"seq":9,`},
	}

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := openTestStore(t, dir, 0)
			appendN(t, s, 5)
			s.Close()

			path := filepath.Join(dir, SegmentName(1))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), tc.from) {
				t.Fatalf("fixture does not contain %q; test needs updating", tc.from)
			}
			modified := strings.Replace(string(raw), tc.from, tc.to, 1)
			if err := os.WriteFile(path, []byte(modified), 0o600); err != nil {
				t.Fatal(err)
			}

			res, err := Verify(dir)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.OK() {
				t.Fatalf("tampering with the %s went undetected", tc.name)
			}
		})
	}
}

// An attacker who edits a record and recomputes its hash correctly still
// breaks the link from the following record. Detecting only naive edits would
// make the chain decorative.
func TestRehashedForgeryBreaksTheFollowingLink(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	appendN(t, s, 5)
	s.Close()

	path := filepath.Join(dir, SegmentName(1))
	recs := readRecords(t, path)

	forged := recs[1]
	forged.Event = json.RawMessage(`{"schema_version":1,"event_type":"inference","request_id":"forged","status":200}`)
	forged.RecordHash = ComputeHash(forged.Seq, forged.Timestamp, forged.PrevHash, forged.Event)
	recs[1] = forged
	writeRecords(t, path, recs)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK() {
		t.Fatal("a re-hashed forgery went undetected")
	}
	var sawBrokenLink bool
	for _, p := range res.Problems {
		if p.Kind == ProblemBrokenLink {
			sawBrokenLink = true
		}
		if p.Kind == ProblemHashMismatch {
			t.Errorf("unexpected hash mismatch: the forged record hashes correctly by construction: %v", p)
		}
	}
	if !sawBrokenLink {
		t.Errorf("expected a broken_link problem, got %v", res.Problems)
	}
}

func TestDeletedRecordIsDetected(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	appendN(t, s, 5)
	s.Close()

	path := filepath.Join(dir, SegmentName(1))
	recs := readRecords(t, path)
	writeRecords(t, path, append(recs[:2:2], recs[3:]...))

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK() {
		t.Fatal("a deleted record went undetected")
	}
	kinds := problemKinds(res)
	if !kinds[ProblemBrokenLink] || !kinds[ProblemSeqGap] {
		t.Errorf("expected both a broken link and a sequence gap, got %v", res.Problems)
	}
}

func TestTruncatedFinalRecordIsDetected(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	appendN(t, s, 3)
	s.Close()

	path := filepath.Join(dir, SegmentName(1))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:len(raw)-40], 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK() {
		t.Fatal("a truncated final record went undetected")
	}
}

func TestChainContinuesAcrossSegmentRotation(t *testing.T) {
	dir := t.TempDir()
	// A tiny cap forces a rotation every record or two.
	s := openTestStore(t, dir, 400)
	appendN(t, s, 12)
	s.Close()

	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation into multiple segments, got %d", len(segs))
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("chain broken across segments: %v", res.Problems)
	}
	if res.Records != 12 {
		t.Errorf("Records = %d, want 12", res.Records)
	}
}

func TestChainContinuesAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	s := openTestStore(t, dir, 0)
	appendN(t, s, 4)
	s.Close()

	reopened := openTestStore(t, dir, 0)
	appendN(t, reopened, 4)
	reopened.Close()

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("chain broken across restart: %v", res.Problems)
	}
	if res.Records != 8 || res.LastSeq != 8 {
		t.Errorf("got %d records ending at seq %d, want 8 and 8", res.Records, res.LastSeq)
	}
}

func TestVerifyEmptyDirectoryReportsNoSegments(t *testing.T) {
	res, err := Verify(t.TempDir())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK() {
		t.Fatal("an empty directory should not verify as an intact chain")
	}
	if res.Problems[0].Kind != ProblemEmptyDir {
		t.Errorf("Kind = %q, want %q", res.Problems[0].Kind, ProblemEmptyDir)
	}
}

func TestAppendAfterCloseFails(t *testing.T) {
	s := openTestStore(t, t.TempDir(), 0)
	s.Close()
	if err := s.Append(&Event{EventType: EventSystemEvent}); err == nil {
		t.Fatal("Append after Close should fail")
	}
}

func TestWalkDecodesEventsInOrder(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 300)
	appendN(t, s, 10)
	s.Close()

	var seqs []uint64
	err := Walk(dir, func(e Entry) error {
		seqs = append(seqs, e.Record.Seq)
		if e.Event.EventType != EventInference {
			t.Errorf("EventType = %q", e.Event.EventType)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(seqs) != 10 {
		t.Fatalf("walked %d records, want 10", len(seqs))
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seqs[%d] = %d, want %d", i, s, i+1)
		}
	}
}

func problemKinds(res *VerifyResult) map[string]bool {
	kinds := map[string]bool{}
	for _, p := range res.Problems {
		kinds[p.Kind] = true
	}
	return kinds
}

func readRecords(t *testing.T, path string) []Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

func writeRecords(t *testing.T, path string, recs []Record) {
	t.Helper()
	var b strings.Builder
	for _, r := range recs {
		line, err := json.Marshal(&r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
