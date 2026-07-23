package evidence

import (
	"bytes"
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signedStore opens a store that signs its checkpoints with the key in dir.
func signedStore(t *testing.T, dir string) (*Store, *KeyPair) {
	t.Helper()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	return s, kp
}

// Rotation is only worth having if the log written before it stays checkable
// afterwards. This is the whole property in one test: checkpoints signed under
// the retired key and under the current key both verify, in one pass, against
// one directory.
func TestCheckpointsVerifyUnderBothTheRetiredAndTheCurrentKey(t *testing.T) {
	dir := t.TempDir()
	before, old := signedStore(t, dir)
	appendN(t, before, 3)
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := RotateKey(dir)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if res.OldKeyID != old.ID {
		t.Errorf("OldKeyID = %s, want %s", res.OldKeyID, old.ID)
	}
	if res.NewKeyID == old.ID {
		t.Fatal("rotation kept the same key")
	}

	after, current := signedStore(t, dir)
	appendN(t, after, 3)
	if err := after.Close(); err != nil {
		t.Fatal(err)
	}
	if current.ID != res.NewKeyID {
		t.Fatalf("the store loaded key %s after rotating to %s", current.ID, res.NewKeyID)
	}

	checks, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	var underOld, underNew int
	for _, c := range checks {
		switch c.KeyID {
		case res.OldKeyID:
			underOld++
			if err := VerifyCheckpointSignature(old.Public, c); err != nil {
				t.Errorf("checkpoint at seq %d does not verify under the retired key: %v", c.Seq, err)
			}
		case res.NewKeyID:
			underNew++
			if err := VerifyCheckpointSignature(current.Public, c); err != nil {
				t.Errorf("checkpoint at seq %d does not verify under the current key: %v", c.Seq, err)
			}
		default:
			t.Errorf("checkpoint at seq %d is signed by unexpected key %s", c.Seq, c.KeyID)
		}
	}
	if underOld == 0 || underNew == 0 {
		t.Fatalf("expected checkpoints under both keys, got %d old and %d new", underOld, underNew)
	}

	ver, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ver.OK() {
		t.Fatalf("a rotated log did not verify: %v", ver.Problems)
	}
	if !ver.Attested {
		t.Error("a rotated log was reported as unattested")
	}
	if ver.CheckpointsVerified != len(checks) {
		t.Errorf("CheckpointsVerified = %d, want all %d", ver.CheckpointsVerified, len(checks))
	}
	if ver.KeyID != res.NewKeyID {
		t.Errorf("KeyID = %s, want the current key %s", ver.KeyID, res.NewKeyID)
	}
	if strings.Join(ver.RetiredKeys, ",") != res.OldKeyID {
		t.Errorf("RetiredKeys = %v, want just %s", ver.RetiredKeys, res.OldKeyID)
	}
}

// Without the retired key on disk the old checkpoints are signed by a key
// nobody can account for, and that is exactly what unknown_key has to mean.
// Deleting the retired key is the control case that proves the key set, rather
// than something else, is what makes the rotated log verify.
func TestRemovingTheRetiredKeyMakesOldCheckpointsUnknown(t *testing.T) {
	dir := t.TempDir()
	s, _ := signedStore(t, dir)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := RotateKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(dir, res.RetiredKeyFile)); err != nil {
		t.Fatal(err)
	}
	ver, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ver.OK() {
		t.Fatal("checkpoints signed by a key the directory no longer holds verified anyway")
	}
	if !problemKinds(ver)[ProblemUnknownKey] {
		t.Errorf("expected an unknown_key problem, got %v", ver.Problems)
	}
	for _, p := range ver.Problems {
		if p.Kind == ProblemUnknownKey && !strings.Contains(p.Detail, res.OldKeyID) {
			t.Errorf("the problem does not name the key that signed: %s", p.Detail)
		}
	}
}

// The log has to document its own custody history, or an auditor is left
// inferring a key change from file modification times.
func TestRotationIsRecordedInTheChain(t *testing.T) {
	dir := t.TempDir()
	s, _ := signedStore(t, dir)
	appendN(t, s, 2)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := RotateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordSeq == 0 {
		t.Fatal("the rotation reported no chain position for its own record")
	}

	var found *Event
	err = Walk(dir, func(e Entry) error {
		if e.Event.EventType == EventConfigChange && e.Record.Seq == res.RecordSeq {
			ev := e.Event
			found = &ev
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatalf("no config_change event at seq %d", res.RecordSeq)
	}
	for _, want := range []string{res.OldKeyID, res.NewKeyID} {
		if !strings.Contains(found.Note, want) {
			t.Errorf("the config_change note does not name key %s: %q", want, found.Note)
		}
	}

	ver, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ver.OK() {
		t.Fatalf("recording the rotation broke the chain: %v", ver.Problems)
	}
}

// The old private key must not survive the rotation: a key that is still on
// disk can still sign, which is the thing rotation exists to stop.
func TestRotationLeavesNoUsableOldPrivateKey(t *testing.T) {
	dir := t.TempDir()
	s, old := signedStore(t, dir)
	appendN(t, s, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := RotateKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("the directory is unusable after rotating: %v", err)
	}
	if reloaded.ID != res.NewKeyID {
		t.Errorf("%s holds key %s, want the new key %s", SigningKeyFile, reloaded.ID, res.NewKeyID)
	}
	if reloaded.Private.Equal(old.Private) {
		t.Fatal("the old private key is still the signing key")
	}

	// Not just under its old name: a temporary file or a backup copy left
	// anywhere in the directory would still be a key that can sign.
	oldDER, err := x509.MarshalPKCS8PrivateKey(old.Private)
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, oldDER) {
			t.Errorf("%s still holds the retired private key", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	retired, err := LoadPublicKeyPEM(filepath.Join(dir, res.RetiredKeyFile))
	if err != nil {
		t.Fatalf("the retired public key was not kept: %v", err)
	}
	if !retired.Equal(old.Public) {
		t.Error("the retired file does not hold the key that was retired")
	}
}

// Rotating underneath a running writer would take the key away from the
// process that is signing with it, so it is refused rather than raced.
func TestRotationRefusesWhileAStoreIsOpen(t *testing.T) {
	dir := t.TempDir()
	s, _ := signedStore(t, dir)
	appendN(t, s, 1)

	_, err := RotateKey(dir)
	if err == nil {
		s.Close()
		t.Fatal("the signing key was rotated while a store held the directory")
	}
	if !strings.Contains(err.Error(), WriterLockFile) {
		t.Errorf("the refusal does not say what to remove if nothing is running: %v", err)
	}
	if !strings.Contains(err.Error(), "stop the server") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateKey(dir); err != nil {
		t.Fatalf("rotation still refused after the store was closed: %v", err)
	}
}

func TestClosedStoreLeavesNoWriterLock(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 0)
	lock := ReadWriterLock(dir)
	if lock == nil || lock.PID != os.Getpid() {
		t.Fatalf("an open store did not claim the directory: %+v", lock)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if lock = ReadWriterLock(dir); lock != nil {
		t.Errorf("a closed store left %s behind: %+v", WriterLockFile, lock)
	}
}

func TestRotateKeyRefusesADirectoryWithNoKey(t *testing.T) {
	if _, err := RotateKey(t.TempDir()); err == nil {
		t.Fatal("rotating a directory with no signing key was allowed")
	}
}

// A retired key file must never be overwritten: it is the only copy of a key
// that signed records still in the log.
func TestRotationRefusesToOverwriteADifferentRetiredKey(t *testing.T) {
	dir := t.TempDir()
	s, old := signedStore(t, dir)
	appendN(t, s, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	foreign, err := LoadOrCreateKeyPair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, RetiredKeysDir), 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, retiredKeyFile(old.ID))
	if err := writePublicKey(target, foreign.Public); err != nil {
		t.Fatal(err)
	}

	if _, err := RotateKey(dir); err == nil {
		t.Fatal("rotation overwrote a retired key holding a different key")
	}
	kept, err := LoadPublicKeyPEM(target)
	if err != nil {
		t.Fatal(err)
	}
	if !kept.Equal(foreign.Public) {
		t.Error("the retired key file was changed by the refused rotation")
	}
}
