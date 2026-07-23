package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkpointOverHead signs a checkpoint covering the log's last record with the
// given key and appends it, which is how a test produces an attestation under a
// key of its choosing.
func checkpointOverHead(t *testing.T, dir string, kp *KeyPair) Checkpoint {
	t.Helper()
	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("no segments to checkpoint")
	}
	recs := readRecords(t, segs[len(segs)-1].Path)
	head := recs[len(recs)-1]

	c := Checkpoint{
		Segment:    filepath.Base(segs[len(segs)-1].Path),
		Seq:        head.Seq,
		RecordHash: head.RecordHash,
		Records:    head.Seq,
		Timestamp:  head.Timestamp,
	}
	if err := SignCheckpoint(kp.Private, kp.ID, &c); err != nil {
		t.Fatal(err)
	}
	if err := AppendCheckpoint(dir, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func writeRetiredKey(t *testing.T, dir, name string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, RetiredKeysDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// One unreadable file in keys/ must not switch signature checking off for the
// whole directory. Otherwise corrupting a retired key would be a way to have a
// log reported as fine without any signature being checked at all.
func TestOneUnreadableRetiredKeyDoesNotStopTheOthersFromChecking(t *testing.T) {
	dir := t.TempDir()
	s, kp := signedStore(t, dir)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	writeRetiredKey(t, dir, retiredKeyFile("00000000deadbeef"), []byte("this is not a PEM block\n"))

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Attested {
		t.Error("a corrupt retired key stopped the current key's checkpoints from being checked")
	}
	if res.KeyID != kp.ID {
		t.Errorf("KeyID = %q, want the current key %s", res.KeyID, kp.ID)
	}
	if !problemKinds(res)[ProblemUnknownKey] {
		t.Errorf("the unreadable key was not reported: %v", res.Problems)
	}
}

// A key filed under someone else's id is either a copy made by hand or one
// somebody dropped in hoping their signatures would be accepted. It is refused
// until it is filed under its own id, and it verifies nothing in the meantime.
func TestARetiredKeyFiledUnderTheWrongIDIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, _ := signedStore(t, dir)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	outsider, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	forged := checkpointOverHead(t, dir, outsider)

	outsiderPEM := publicKeyPEMOf(t, outsider)

	// Filed under a name that is not its key id: refused, and its checkpoint
	// stays unattributable.
	writeRetiredKey(t, dir, retiredKeyFile("ffffffffffffffff"), outsiderPEM)
	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !problemKinds(res)[ProblemUnknownKey] {
		t.Fatalf("a misfiled key was accepted quietly: %v", res.Problems)
	}
	var namedTheMismatch, namedTheForgery bool
	for _, p := range res.Problems {
		if strings.Contains(p.Detail, "filed under its own id") {
			namedTheMismatch = true
		}
		if p.Seq == forged.Seq && strings.Contains(p.Detail, outsider.ID) {
			namedTheForgery = true
		}
	}
	if !namedTheMismatch {
		t.Errorf("nothing said the file name and its contents disagree: %v", res.Problems)
	}
	if !namedTheForgery {
		t.Errorf("the checkpoint signed by the misfiled key was not reported as unknown: %v", res.Problems)
	}

	// Filed correctly, it is a key this directory accounts for.
	if err := os.Remove(filepath.Join(dir, retiredKeyFile("ffffffffffffffff"))); err != nil {
		t.Fatal(err)
	}
	writeRetiredKey(t, dir, retiredKeyFile(outsider.ID), outsiderPEM)
	res, err = Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a correctly filed retired key still did not verify: %v", res.Problems)
	}
	if strings.Join(res.RetiredKeys, ",") != outsider.ID {
		t.Errorf("RetiredKeys = %v, want %s", res.RetiredKeys, outsider.ID)
	}
}

func TestLoadKeySetOnADirectoryWithNoKeys(t *testing.T) {
	ks := LoadKeySet(t.TempDir())
	if ks.Len() != 0 || len(ks.Unreadable) != 0 {
		t.Fatalf("LoadKeySet on an empty directory returned %+v", ks)
	}
	if _, ok := ks.Current(); ok {
		t.Error("Current reported a key in a directory with none")
	}
	if _, ok := ks.ByID(""); ok {
		t.Error("an empty key id matched a key; a signature nobody can attribute is not evidence")
	}
}

func publicKeyPEMOf(t *testing.T, kp *KeyPair) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), PublicKeyFile)
	if err := writePublicKey(path, kp.Public); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
