package evidence

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateKeyPairReturnsTheSameKeyEveryTime(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateKeyPair: %v", err)
	}
	second, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateKeyPair: %v", err)
	}

	if !first.Public.Equal(second.Public) {
		t.Error("the second call generated a different key; every checkpoint signed before it would become unverifiable")
	}
	if first.ID != second.ID {
		t.Errorf("key id changed between calls: %s then %s", first.ID, second.ID)
	}
	if len(first.ID) != 16 {
		t.Errorf("key id %q is %d characters, want 16", first.ID, len(first.ID))
	}
}

func TestPrivateKeyIsCreatedUnreadableByGroupAndOther(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are synthesised on Windows")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, SigningKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("%s has mode %04o, want 0600", SigningKeyFile, got)
	}
	pubInfo, err := os.Stat(filepath.Join(dir, PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("%s has mode %04o, want 0644 so that a verifier can read it", PublicKeyFile, got)
	}
}

func TestGroupOrWorldReadablePrivateKeyIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are synthesised on Windows")
	}
	modes := []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666}
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			if _, err := LoadOrCreateKeyPair(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, SigningKeyFile)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}

			_, err := LoadOrCreateKeyPair(dir)
			if err == nil {
				t.Fatalf("a signing key with mode %04o was accepted", mode.Perm())
			}
			if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("error does not say how to fix it: %v", err)
			}
		})
	}
}

// The point of PEM plus PKCS#8 and PKIX is that a regulator can inspect the
// key with openssl. Parsing them back with only crypto/x509 proves the
// encoding is the standard one rather than something bespoke.
func TestKeyFilesUseStandardPEMEncodings(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}

	privPEM, err := os.ReadFile(filepath.Join(dir, SigningKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("private key is not a PRIVATE KEY PEM block: %q", string(privPEM))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("private key is not PKCS#8: %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Fatalf("private key parsed as %T, want ed25519.PrivateKey", parsed)
	}

	pub, err := LoadPublicKeyPEM(filepath.Join(dir, PublicKeyFile))
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if !pub.Equal(kp.Public) {
		t.Error("public-key.pem does not hold the public half of signing-key.pem")
	}
}

func TestMissingPublicKeyIsRegeneratedFromThePrivateKey(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, PublicKeyFile)); err != nil {
		t.Fatal(err)
	}

	again, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeyPair after removing the public key: %v", err)
	}
	if !again.Public.Equal(kp.Public) {
		t.Fatal("the regenerated public key does not match the private key")
	}
	if _, err := os.Stat(filepath.Join(dir, PublicKeyFile)); err != nil {
		t.Errorf("public key was not rewritten: %v", err)
	}
}

// Swapping public-key.pem for someone else's is how an attacker would make
// their own signatures verify. Refusing to start beats picking a winner.
func TestPublicKeyThatDoesNotMatchThePrivateKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if _, err := LoadOrCreateKeyPair(other); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(filepath.Join(other, PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PublicKeyFile), foreign, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateKeyPair(dir); err == nil {
		t.Fatal("a public key belonging to a different private key was accepted")
	}
}

func TestKeyIDIsDerivedFromTheKeyAndIsStable(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := KeyID(pub)
	if len(id) != 16 {
		t.Fatalf("KeyID = %q, want 16 hex characters", id)
	}
	if KeyID(pub) != id {
		t.Error("KeyID is not deterministic")
	}

	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(otherPub) == id {
		t.Error("two different keys produced the same id")
	}
}

func TestLoadPublicKeyPEMRejectsNonKeyFiles(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not pem", "this is not a key"},
		{"wrong block type", "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"},
		{"corrupt der", "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), PublicKeyFile)
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPublicKeyPEM(path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
