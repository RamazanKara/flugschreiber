package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzVerifyRecordLine drives the verifier over arbitrary segment contents.
//
// Verify is the one function in this project that runs on somebody else's
// machine, years from now, over a file whose provenance is exactly what is in
// question. It has to survive anything: a truncated copy, a file somebody
// edited by hand, a segment restored from tape as UTF-16, a deliberately
// malformed record. Crashing on any of those would turn "the log is damaged"
// into "the tool is broken", which is the worse answer to give an auditor.
//
// The properties are that it never panics, that it always returns either a
// result or an error, that its verdict agrees with what it reported, and that
// it says the same thing twice about the same bytes.
func FuzzVerifyRecordLine(f *testing.F) {
	valid := func(seq uint64, ts, prev, event string) string {
		rec := Record{
			Seq:        seq,
			Timestamp:  ts,
			PrevHash:   prev,
			RecordHash: ComputeHash(seq, ts, prev, json.RawMessage(event)),
			Event:      json.RawMessage(event),
		}
		line, err := json.Marshal(&rec)
		if err != nil {
			f.Fatal(err)
		}
		return string(line) + "\n"
	}

	const event = `{"schema_version":1,"event_type":"inference","request_id":"r","status":200}`
	first := valid(1, "2026-03-01T12:00:01Z", GenesisHash, event)

	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte("{"))
	f.Add([]byte("null\n"))
	f.Add([]byte(`{"seq":1}` + "\n"))
	f.Add([]byte(first))
	f.Add([]byte(first[:len(first)/2]))
	f.Add([]byte(first + first))
	f.Add([]byte(valid(0, "", "", "{}")))
	f.Add([]byte(valid(18446744073709551615, "not a time", "zz", `{"event_type":"inference"}`)))
	f.Add([]byte(`{"seq":1,"timestamp":"t","prev_hash":"p","record_hash":"h","event":[1,2,3]}` + "\n"))

	f.Fuzz(func(t *testing.T, segment []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, SegmentName(1)), segment, 0o600); err != nil {
			t.Skip("cannot write the segment on this platform")
		}

		res, err := Verify(dir)
		if err != nil {
			// A read error is a legitimate outcome; a nil result with no error
			// is not.
			return
		}
		if res == nil {
			t.Fatal("Verify returned neither a result nor an error")
		}
		if res.OK() != (len(res.Problems) == 0) {
			t.Fatalf("OK() = %v with %d problems reported", res.OK(), len(res.Problems))
		}
		for _, p := range res.Problems {
			if p.Kind == "" {
				t.Errorf("a problem was reported with no kind: %+v", p)
			}
			if p.Detail == "" {
				t.Errorf("a problem was reported with nothing to act on: %+v", p)
			}
		}

		again, err := Verify(dir)
		if err != nil {
			t.Fatalf("the second pass over the same bytes failed: %v", err)
		}
		if again.OK() != res.OK() || again.Records != res.Records ||
			again.LastSeq != res.LastSeq || len(again.Problems) != len(res.Problems) {
			t.Fatalf("two passes over the same bytes disagreed: %+v then %+v", res, again)
		}
	})
}
