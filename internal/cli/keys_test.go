package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// runCLI drives the dispatcher the binary uses and captures what it printed,
// so that a test exercises the command surface rather than the functions
// behind it.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()

	code := Main(args)
	w.Close()
	os.Stdout = orig
	return code, <-out
}

// signedLog writes n records under a signing key and closes the store, which
// leaves a shutdown checkpoint signed by whatever key was in force.
func signedLog(t *testing.T, dir string, n int) *evidence.KeyPair {
	t.Helper()
	kp, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := evidence.Open(evidence.Options{Dir: dir, Keys: kp})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := store.Append(&evidence.Event{
			EventType: evidence.EventInference, RequestID: "r", Status: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return kp
}

// The property rotation exists to preserve: checkpoints written before it
// still verify afterwards. A rotation that dropped the old public key would
// leave them signed by a key nothing in the directory accounts for, which is
// how verify reports a forged attestation.
func TestRotationLeavesOlderCheckpointsVerifiable(t *testing.T) {
	dir := t.TempDir()
	old := signedLog(t, dir, 3)

	before, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.CheckpointsVerified == 0 {
		t.Fatalf("no checkpoint to lose: %+v", before.Problems)
	}

	code, out := runCLI(t, "keys", "rotate", "--dir", dir)
	if code != 0 {
		t.Fatalf("keys rotate exited %d\n%s", code, out)
	}

	newKey, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if newKey.ID == old.ID {
		t.Fatal("the signing key is unchanged, so nothing was rotated")
	}
	for _, want := range []string{old.ID, newKey.ID, "retired-" + old.ID} {
		if !strings.Contains(out, want) {
			t.Errorf("rotation output does not name %q:\n%s", want, out)
		}
	}

	retired := filepath.Join(dir, evidence.RetiredKeysDir, "retired-"+old.ID+".pem")
	pub, err := evidence.LoadPublicKeyPEM(retired)
	if err != nil {
		t.Fatalf("the retired public key is not readable at %s: %v", retired, err)
	}
	if got := evidence.KeyID(pub); got != old.ID {
		t.Fatalf("retired file holds key %s, want %s", got, old.ID)
	}

	// Record more under the new key, then check the whole log: the old
	// checkpoints and the new ones must all verify against the key that signed
	// them.
	signedLog(t, dir, 2)
	after, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.OK() {
		t.Fatalf("the log stopped verifying after a rotation: %+v", after.Problems)
	}
	if after.Checkpoints <= before.Checkpoints {
		t.Fatalf("expected checkpoints under both keys, got %d after %d", after.Checkpoints, before.Checkpoints)
	}
	if after.CheckpointsVerified != after.Checkpoints {
		t.Fatalf("%d of %d checkpoints verified", after.CheckpointsVerified, after.Checkpoints)
	}

	// The retired key is what carries the older half. Removing it must break
	// exactly those checkpoints, which is what proves the check above was not
	// passing for some other reason.
	if err := os.Remove(retired); err != nil {
		t.Fatal(err)
	}
	stranded, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	var unknown int
	for _, p := range stranded.Problems {
		if p.Kind == evidence.ProblemUnknownKey {
			unknown++
		}
	}
	if unknown == 0 {
		t.Fatal("removing the retired key changed nothing, so the earlier checkpoints were not being checked against it")
	}
}

func TestRotationRefusesWhenThereIsNoKeyToRotate(t *testing.T) {
	dir := t.TempDir()

	if code, out := runCLI(t, "keys", "rotate", "--dir", dir); code == 0 {
		t.Fatalf("rotating an unsigned directory succeeded\n%s", out)
	}
	// A refusal must not leave a key behind: creating one here would silently
	// start signing a log whose operator chose not to.
	for _, name := range []string{evidence.SigningKeyFile, evidence.PublicKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("the refusal created %s", name)
		}
	}
}

func TestRotationRefusesAKeyItDoesNotHold(t *testing.T) {
	dir := t.TempDir()
	kp := signedLog(t, dir, 1)

	cfg := filepath.Join(t.TempDir(), "config.json")
	body := `{"signer": "exec:/opt/hsm/sign", "signer_public_key": "/opt/hsm/public.pem"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if code, out := runCLI(t, "keys", "rotate", "--dir", dir, "--config", cfg); code == 0 {
		t.Fatalf("rotated a key held by an external signer\n%s", out)
	}
	after, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != kp.ID {
		t.Fatal("the local key was replaced although signing is delegated to a helper")
	}
	if _, err := os.Stat(filepath.Join(dir, evidence.RetiredKeysDir)); err == nil {
		t.Error("the refusal retired a key anyway")
	}
}

func TestRotationRefusesWhileAWriterHoldsTheDirectory(t *testing.T) {
	dir := t.TempDir()
	kp, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := evidence.Open(evidence.Options{Dir: dir, Keys: kp})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if code, out := runCLI(t, "keys", "rotate", "--dir", dir); code == 0 {
		t.Fatalf("rotated the key underneath a running writer\n%s", out)
	}
	after, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != kp.ID {
		t.Fatal("the key changed while a writer held the directory")
	}
}

func TestKeysListNamesTheActiveKeyAndEveryRetiredOne(t *testing.T) {
	dir := t.TempDir()
	first := signedLog(t, dir, 1)
	if code, out := runCLI(t, "keys", "rotate", "--dir", dir); code != 0 {
		t.Fatalf("first rotation exited %d\n%s", code, out)
	}
	second, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := runCLI(t, "keys", "rotate", "--dir", dir); code != 0 {
		t.Fatalf("second rotation exited %d\n%s", code, out)
	}
	third, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "keys", "list", "--dir", dir, "--json")
	if code != 0 {
		t.Fatalf("keys list exited %d\n%s", code, out)
	}
	var got keysListResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("keys list --json is not JSON: %v\n%s", err, out)
	}
	if got.Active == nil || got.Active.ID != third.ID {
		t.Fatalf("active key = %+v, want %s", got.Active, third.ID)
	}
	if got.Active.Source != evidence.PublicKeyFile {
		t.Errorf("active key file = %q, want %q", got.Active.Source, evidence.PublicKeyFile)
	}

	files := map[string]string{}
	for _, k := range got.Retired {
		files[k.ID] = k.Source
	}
	for _, id := range []string{first.ID, second.ID} {
		src, ok := files[id]
		if !ok {
			t.Fatalf("retired key %s is not listed: %+v", id, got.Retired)
		}
		if _, err := evidence.LoadPublicKeyPEM(filepath.Join(dir, filepath.FromSlash(src))); err != nil {
			t.Errorf("listed file %s for key %s does not hold a key: %v", src, id, err)
		}
	}
	if _, listed := files[third.ID]; listed {
		t.Error("the active key is also listed as retired")
	}
}

func TestKeysListRefusesADirectoryThatHasNoKeys(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{
		EventType: evidence.EventInference, RequestID: "r", Status: 200,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if code, out := runCLI(t, "keys", "list", "--dir", dir); code == 0 {
		t.Fatalf("listing keys in an unsigned directory succeeded\n%s", out)
	}
}

func TestKeysListReportsThatSigningIsOff(t *testing.T) {
	dir := t.TempDir()
	signedLog(t, dir, 1)

	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte(`{"signing_disabled": true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "keys", "list", "--dir", dir, "--config", cfg, "--json")
	if code != 0 {
		t.Fatalf("keys list exited %d\n%s", code, out)
	}
	var got keysListResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Signing != "disabled" {
		t.Errorf("signing = %q, want disabled: a key file present is not a key in use", got.Signing)
	}
}

func TestKeysRefusesAnUnknownSubcommand(t *testing.T) {
	for _, args := range [][]string{
		{"keys"},
		{"keys", "delete", "--dir", "/tmp"},
	} {
		if code, _ := runCLI(t, args...); code != 1 {
			t.Errorf("Main(%v) = %d, want 1", args, code)
		}
	}
}

// With an external signer the rotation happens at the helper, so the only way
// to keep earlier checkpoints verifiable is to retire the old public key here.
// Without it every checkpoint signed before the change is attributed to a key
// the directory no longer holds, permanently.
func TestRetiringAPublicKeyKeepsItsCheckpointsVerifiable(t *testing.T) {
	dir := t.TempDir()
	kp, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := evidence.Open(evidence.Options{Dir: dir, Keys: kp, SegmentMaxBytes: 400})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		if err := s.Append(&evidence.Event{
			EventType: evidence.EventInference,
			RequestID: fmt.Sprintf("req-%d", i),
			Status:    200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Keep a copy of the old public key, then replace it as an external
	// rotation would: a new key becomes active and the old one is gone.
	oldPub := filepath.Join(t.TempDir(), "old-public-key.pem")
	raw, err := os.ReadFile(filepath.Join(dir, evidence.PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPub, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	newKeyDir := t.TempDir()
	newKP, err := evidence.LoadOrCreateKeyPair(newKeyDir)
	if err != nil {
		t.Fatal(err)
	}
	newRaw, err := os.ReadFile(filepath.Join(newKeyDir, evidence.PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, evidence.PublicKeyFile), newRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = newKP

	// This is the state an operator lands in today: the old checkpoints name a
	// key nothing here holds.
	before, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.OK() {
		t.Fatal("the fixture did not reproduce the stranded state, so this proves nothing")
	}

	if err := Keys([]string{"retire", "--dir", dir, "--key", oldPub}); err != nil {
		t.Fatalf("keys retire: %v", err)
	}

	after, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.OK() {
		t.Errorf("retiring the old public key did not make its checkpoints verifiable again: %v", after.Problems)
	}

	// Running it twice is not an error, so it is safe in a runbook.
	if err := Keys([]string{"retire", "--dir", dir, "--key", oldPub}); err != nil {
		t.Errorf("retiring an already retired key failed: %v", err)
	}
}
