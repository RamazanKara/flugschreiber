package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleAnchor() PruneAnchor {
	return PruneAnchor{
		Version:        PruneAnchorVersion,
		PrunedAt:       "2026-09-01T00:00:00Z",
		LastPrunedSeq:  120,
		LastPrunedHash: strings.Repeat("7f", 32),
		Segments:       []string{"seg-00000001.jsonl", "seg-00000002.jsonl"},
		Records:        120,
		Reason:         "retention, 180 days",
		KeyID:          "0123456789abcdef",
	}
}

func TestPruneAnchorPreimageIsExactlyTheDocumentedBytes(t *testing.T) {
	want := "flugschreiber-prune-anchor-v1\n" +
		"version:1\n" +
		"pruned_at:2026-09-01T00:00:00Z\n" +
		"last_pruned_seq:120\n" +
		"last_pruned_hash:" + strings.Repeat("7f", 32) + "\n" +
		"records:120\n" +
		"segments:seg-00000001.jsonl,seg-00000002.jsonl\n" +
		"key_id:0123456789abcdef\n"

	if got := string(PruneAnchorPreimage(sampleAnchor())); got != want {
		t.Errorf("preimage mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestSignedAnchorVerifiesAndAnyEditToWhatItAttestsBreaksIt(t *testing.T) {
	kp, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	edits := []struct {
		name string
		edit func(*PruneAnchor)
	}{
		{"last pruned seq", func(a *PruneAnchor) { a.LastPrunedSeq = 121 }},
		{"last pruned hash", func(a *PruneAnchor) { a.LastPrunedHash = strings.Repeat("00", 32) }},
		{"segment list", func(a *PruneAnchor) { a.Segments = append(a.Segments, "seg-00000003.jsonl") }},
		{"records", func(a *PruneAnchor) { a.Records = 1 }},
		{"pruned at", func(a *PruneAnchor) { a.PrunedAt = "2026-09-02T00:00:00Z" }},
		{"version", func(a *PruneAnchor) { a.Version = 2 }},
	}

	for _, tc := range edits {
		t.Run(tc.name, func(t *testing.T) {
			a := sampleAnchor()
			if err := SignPruneAnchor(kp.Private, kp.ID, &a); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPruneAnchorSignature(kp.Public, a); err != nil {
				t.Fatalf("a freshly signed anchor did not verify: %v", err)
			}
			tc.edit(&a)
			if err := VerifyPruneAnchorSignature(kp.Public, a); err == nil {
				t.Fatalf("editing the %s left the signature valid", tc.name)
			}
		})
	}
}

func TestWritePruneAnchorRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := sampleAnchor()
	if err := WritePruneAnchor(dir, want); err != nil {
		t.Fatalf("WritePruneAnchor: %v", err)
	}

	got, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatalf("ReadPruneAnchor: %v", err)
	}
	if got == nil {
		t.Fatal("ReadPruneAnchor returned nil for an anchor that was just written")
	}
	if got.LastPrunedSeq != want.LastPrunedSeq || got.LastPrunedHash != want.LastPrunedHash {
		t.Errorf("anchor point changed on the round trip: %+v", got)
	}
	if strings.Join(got.Segments, ",") != strings.Join(want.Segments, ",") {
		t.Errorf("Segments = %v, want %v", got.Segments, want.Segments)
	}
	if got.Reason != want.Reason {
		t.Errorf("Reason = %q, want %q", got.Reason, want.Reason)
	}
}

func TestReadPruneAnchorOnAnUnprunedLogReturnsNil(t *testing.T) {
	got, err := ReadPruneAnchor(t.TempDir())
	if err != nil {
		t.Fatalf("ReadPruneAnchor: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil for a log that has never been pruned", got)
	}
}

// A half-written anchor makes every surviving record unverifiable, so the
// write goes through a temporary file and a rename. Neither the temporary file
// nor a partial anchor may be left behind.
func TestWritePruneAnchorLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		a := sampleAnchor()
		a.LastPrunedSeq = uint64(100 + i)
		if err := WritePruneAnchor(dir, a); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != PruneAnchorFile {
			t.Errorf("unexpected leftover file %q", e.Name())
		}
	}

	got, err := ReadPruneAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastPrunedSeq != 102 {
		t.Errorf("LastPrunedSeq = %d, want the last write to have won", got.LastPrunedSeq)
	}
}

func TestPruneAnchorIsReadableByOthers(t *testing.T) {
	dir := t.TempDir()
	if err := WritePruneAnchor(dir, sampleAnchor()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, PruneAnchorFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm() & 0o004; got == 0 {
		t.Errorf("%s has mode %04o; a verifier has to be able to read it", PruneAnchorFile, info.Mode().Perm())
	}
}

func TestUnsignedAnchorIsWrittenWithoutSignatureFields(t *testing.T) {
	dir := t.TempDir()
	a := sampleAnchor()
	a.KeyID = ""
	if err := WritePruneAnchor(dir, a); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, PruneAnchorFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "signature") || strings.Contains(string(raw), "key_id") {
		t.Errorf("an unsigned anchor carries empty signature fields:\n%s", raw)
	}
}
