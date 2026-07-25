package acceptance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conformanceDir is evidence written by v1.0 and frozen. Every other test in
// this repository writes a log and reads it back in the same process with the
// same code, so all of that coverage is same-version round-trip and none of it
// would notice the day a change stopped this build reading what an earlier one
// wrote. CONTRIBUTING.md says people will still be verifying today's logs in
// 2032; this is the only thing that mechanically holds anyone to it.
const conformanceDir = "../testdata/conformance"

type conformanceExpectation struct {
	Records      int    `json:"records"`
	Segments     int    `json:"segments"`
	Checkpoints  int    `json:"checkpoints"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSeq      uint64 `json:"last_seq"`
	HeadHash     string `json:"head_hash"`
	KeyID        string `json:"key_id"`
	RecordHashes []struct {
		Seq        uint64 `json:"seq"`
		RecordHash string `json:"record_hash"`
	} `json:"record_hashes"`
}

func loadExpectation(t *testing.T) conformanceExpectation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(conformanceDir, "EXPECTED.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want conformanceExpectation
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	return want
}

// The frozen log must still verify, and reach exactly the values it reached
// when it was written. A change to the hash construction, to the preimage, or
// to how the event bytes are taken shows up here and nowhere else.
func TestFrozenEvidenceStillVerifies(t *testing.T) {
	bin := buildBinary(t)
	want := loadExpectation(t)

	out, err := run(t, bin, "verify", "--dir", conformanceDir, "--json")
	if err != nil {
		t.Fatalf("the frozen evidence no longer verifies, so this build cannot read a log it wrote at 1.0: %v\n%s", err, out)
	}

	var got struct {
		Records     uint64 `json:"records"`
		FirstSeq    uint64 `json:"first_seq"`
		LastSeq     uint64 `json:"last_seq"`
		HeadHash    string `json:"head_hash"`
		KeyID       string `json:"key_id"`
		Checkpoints int    `json:"checkpoints"`
		Attested    bool   `json:"attested"`
		Segments    []string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("verify --json is no longer parseable: %v\n%s", err, out)
	}

	if got.HeadHash != want.HeadHash {
		t.Errorf("head hash is %s, the frozen log heads at %s: the hash construction has changed and every log written before this build is now unverifiable",
			got.HeadHash, want.HeadHash)
	}
	if int(got.Records) != want.Records {
		t.Errorf("records = %d, want %d", got.Records, want.Records)
	}
	if got.FirstSeq != want.FirstSeq || got.LastSeq != want.LastSeq {
		t.Errorf("sequence %d to %d, want %d to %d", got.FirstSeq, got.LastSeq, want.FirstSeq, want.LastSeq)
	}
	if got.Checkpoints != want.Checkpoints {
		t.Errorf("checkpoints = %d, want %d", got.Checkpoints, want.Checkpoints)
	}
	if got.KeyID != want.KeyID {
		t.Errorf("key id = %s, want %s", got.KeyID, want.KeyID)
	}
	if !got.Attested {
		t.Error("the frozen log no longer reports as attested, so the checkpoint signature rule has changed")
	}
}

// Every individual record hash is pinned too, so a change shows which record it
// first affects rather than only that the head moved.
func TestFrozenRecordHashesAreUnchanged(t *testing.T) {
	want := loadExpectation(t)

	segs, err := filepath.Glob(filepath.Join(conformanceDir, "seg-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint64]string{}
	for _, seg := range segs {
		raw, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var rec struct {
				Seq        uint64 `json:"seq"`
				RecordHash string `json:"record_hash"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatal(err)
			}
			got[rec.Seq] = rec.RecordHash
		}
	}

	for _, w := range want.RecordHashes {
		if got[w.Seq] != w.RecordHash {
			t.Errorf("record %d hashes to %s, want %s", w.Seq, got[w.Seq], w.RecordHash)
		}
	}
}

// The fixture is only worth having if it contains the cases a reimplementation
// gets wrong. If somebody regenerates it from tamer content, this says so.
func TestFrozenEvidenceStillContainsTheAwkwardCases(t *testing.T) {
	segs, err := filepath.Glob(filepath.Join(conformanceDir, "seg-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, seg := range segs {
		raw, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(raw)
	}
	body := all.String()

	for _, want := range []struct{ what, needle string }{
		{"HTML-escaped less-than, which Go writes and a re-serialising reader does not", `\u003c`},
		{"HTML-escaped ampersand", `\u0026`},
		{"an escaped newline inside stored text", `\n`},
		{"an escaped quote inside stored text", `\"`},
		{"non-ASCII text, stored literally rather than escaped", "Grüße"},
	} {
		if !strings.Contains(body, want.needle) {
			t.Errorf("the frozen evidence no longer contains %s, so it stops proving what it exists to prove", want.what)
		}
	}
}

// A private key must never be committed, not even a test one, in a repository
// whose subject is key custody.
func TestFrozenEvidenceCarriesNoPrivateKey(t *testing.T) {
	entries, err := os.ReadDir(conformanceDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(conformanceDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "PRIVATE KEY") {
			t.Errorf("%s carries private key material", e.Name())
		}
	}
}
