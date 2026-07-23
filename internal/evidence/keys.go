package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Names of the files this package writes into the evidence directory. They are
// exported because export bundles, documentation and operator tooling all have
// to name them, and a typo in a string literal somewhere else is a bug nobody
// finds until an audit.
const (
	SigningKeyFile  = "signing-key.pem"
	PublicKeyFile   = "public-key.pem"
	CheckpointsFile = "checkpoints.jsonl"
	PruneAnchorFile = "pruned.json"
	LegalHoldFile   = "LEGAL_HOLD"

	// RetiredKeysDir holds the public half of every key rotation has replaced.
	// They are kept forever: a checkpoint signed in 2026 has to stay checkable
	// after the key that signed it has been retired, or rotation would quietly
	// invalidate the log's own history.
	RetiredKeysDir = "keys"
)

// PEM block types, chosen so that openssl reads both files without being told
// what they are.
const (
	privateKeyPEMType = "PRIVATE KEY"
	publicKeyPEMType  = "PUBLIC KEY"
)

// KeyPair is the Ed25519 identity that signs checkpoints and prune anchors.
// The private half never leaves the evidence directory and is never included
// in an export.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	ID      string
}

// KeyID identifies a public key by the first 16 hex characters of the SHA-256
// of its PKIX encoding. It is short enough to print in a checkpoint and in
// operator output, and it is derived from the key rather than assigned, so two
// installations cannot claim the same id without holding the same key.
//
// It returns the empty string for a value that is not a well-formed Ed25519
// public key; callers that sign obtain their id from LoadOrCreateKeyPair,
// which validates the key first.
func KeyID(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16]
}

// LoadOrCreateKeyPair returns the signing identity for dir, generating one on
// first call. It is idempotent: every later call returns the same key, and two
// processes racing to create it converge on whichever key reached the disk
// first rather than overwriting each other.
func LoadOrCreateKeyPair(dir string) (*KeyPair, error) {
	if dir == "" {
		return nil, errors.New("evidence: key directory is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("evidence: create key directory: %w", err)
	}

	kp, err := loadKeyPair(dir)
	if err == nil {
		return kp, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := createKeyPair(dir); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	// Reload instead of returning the key just generated, so that the loser of
	// a creation race uses the same key as the winner.
	return loadKeyPair(dir)
}

// LoadPublicKeyPEM reads a PKIX Ed25519 public key from a PEM file. A verifier
// needs nothing else from this package to check a signature.
func LoadPublicKeyPEM(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("evidence: %s does not contain a PEM block", path)
	}
	if block.Type != publicKeyPEMType {
		return nil, fmt.Errorf("evidence: %s holds a %q block, expected %q", path, block.Type, publicKeyPEMType)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("evidence: parse public key %s: %w", path, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("evidence: %s holds a %T, expected an Ed25519 public key", path, parsed)
	}
	return pub, nil
}

func loadKeyPair(dir string) (*KeyPair, error) {
	path := filepath.Join(dir, SigningKeyFile)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := checkPrivateMode(path, info.Mode().Perm()); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("evidence: %s does not contain a PEM block", path)
	}
	if block.Type != privateKeyPEMType {
		return nil, fmt.Errorf("evidence: %s holds a %q block, expected %q", path, block.Type, privateKeyPEMType)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("evidence: parse signing key %s: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("evidence: %s holds a %T, expected an Ed25519 private key", path, parsed)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("evidence: signing key %s is %d bytes, expected %d", path, len(priv), ed25519.PrivateKeySize)
	}

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("evidence: signing key %s has no usable public half", path)
	}
	if err := reconcilePublicKey(dir, pub); err != nil {
		return nil, err
	}
	return &KeyPair{Private: priv, Public: pub, ID: KeyID(pub)}, nil
}

// reconcilePublicKey writes public-key.pem if it is missing and refuses to
// continue if it belongs to a different key. Regenerating it is safe because
// the private key is authoritative, but silently replacing a mismatched one is
// not: it would hide the fact that someone swapped the key a verifier trusts.
func reconcilePublicKey(dir string, pub ed25519.PublicKey) error {
	path := filepath.Join(dir, PublicKeyFile)
	existing, err := LoadPublicKeyPEM(path)
	if err == nil {
		if !existing.Equal(pub) {
			return fmt.Errorf(
				"evidence: %s is public key %s but %s holds private key %s; remove or restore one of them, do not guess which is correct",
				PublicKeyFile, KeyID(existing), SigningKeyFile, KeyID(pub))
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writePublicKey(path, pub)
}

func createKeyPair(dir string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("evidence: generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("evidence: encode signing key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der})

	path := filepath.Join(dir, SigningKeyFile)
	if err := linkNewFile(path, encoded, 0o600); err != nil {
		return err
	}
	if err := writePublicKey(filepath.Join(dir, PublicKeyFile), pub); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// linkNewFile publishes body at path under a name that either does not exist or
// is left untouched, and that never exists in a partial state.
//
// Creating path with O_EXCL and then writing into it would be exclusive but not
// atomic: a second process starting at the same moment sees the name appear
// immediately and can read zero bytes from it, which for a signing key means
// "this file is not a PEM block" rather than "wait a moment". So the content is
// written to a temporary file first, fsynced, and then hard linked into place.
// link is the exclusive step, so two processes still cannot both believe they
// created the key, and the name only ever resolves to fully written bytes.
//
// A caller that loses the race gets fs.ErrExist and is expected to load the
// winner's file.
func linkNewFile(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".new*")
	if err != nil {
		return fmt.Errorf("evidence: create temporary file for %s: %w", filepath.Base(path), err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("evidence: write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("evidence: set mode on %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("evidence: fsync %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("evidence: close %s: %w", filepath.Base(path), err)
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return err
		}
		return fmt.Errorf("evidence: publish %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writePublicKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("evidence: encode public key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der})
	if err := atomicWriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("evidence: write public key: %w", err)
	}
	return nil
}

// checkPrivateMode refuses a signing key that group or other can read. A key
// everyone on the box can read attests to nothing, and finding that out during
// an audit is too late.
func checkPrivateMode(path string, mode fs.FileMode) error {
	if runtime.GOOS == "windows" {
		// Go synthesises Unix permission bits on Windows, so the check would
		// reject every key there while proving nothing about the real ACL.
		return nil
	}
	if mode&0o077 == 0 {
		return nil
	}
	return fmt.Errorf(
		"evidence: signing key %s has mode %04o and is readable by group or other; a signing key everyone can read is not a signing key, run chmod 600 %s",
		path, uint32(mode), path)
}
