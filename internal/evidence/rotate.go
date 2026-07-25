package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// RotationResult is what one rotation did. It is returned even when recording
// the rotation in the chain fails, so that a caller always learns which key is
// now in force.
type RotationResult struct {
	Dir      string `json:"dir"`
	OldKeyID string `json:"old_key_id"`
	NewKeyID string `json:"new_key_id"`

	// RetiredKeyFile is where the old public key now lives, relative to Dir.
	RetiredKeyFile string `json:"retired_key_file"`

	RotatedAt string `json:"rotated_at"`

	// RecordSeq is the chain position of the config_change event that records
	// the rotation. Zero when the event could not be appended.
	RecordSeq uint64 `json:"record_seq,omitempty"`
}

// RotateKey replaces the signing key of an evidence directory.
//
// The old public key is copied to keys/retired-<old key id>.pem before
// anything else changes, because every checkpoint already on disk was signed
// with it and would otherwise become unverifiable. The old private key is then
// replaced by the new one and is gone from the directory: after this returns,
// nothing on the host can produce another signature under the old key, which
// is the point of rotating. Finally the rotation is appended to the chain as a
// config_change event naming both key ids, so the log documents its own
// custody history rather than leaving an auditor to infer it from file dates.
//
// Rotation requires the server stopped. It refuses while an open Store holds
// the directory, and there is no mechanism for taking a key away from a
// running writer: the single-writer rule makes concurrent mutation of an
// evidence directory an operational error rather than a case to be handled.
//
// The two key files are replaced one after the other. A crash between them
// leaves the new public key beside the old private key, which the store
// refuses to open, naming both ids. Recovery is to copy the retired key back
// over public-key.pem and rotate again; the retired copy is written first
// precisely so that this is always possible.
func RotateKey(dir string) (*RotationResult, error) {
	if dir == "" {
		return nil, errors.New("evidence: key directory is required")
	}
	if err := refuseWhileWriterHolds(dir, "rotate the signing key"); err != nil {
		return nil, err
	}

	old, err := loadKeyPair(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf(
				"evidence: %s holds no %s to rotate; a directory gets its first signing key when the server starts",
				dir, SigningKeyFile)
		}
		return nil, err
	}

	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("evidence: generate signing key: %w", err)
	}
	res := &RotationResult{
		Dir:            dir,
		OldKeyID:       old.ID,
		NewKeyID:       KeyID(newPub),
		RetiredKeyFile: retiredKeyFile(old.ID),
		RotatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	if res.NewKeyID == old.ID {
		// Two Ed25519 key generations cannot collide, so this is a broken
		// random source rather than bad luck, and continuing would overwrite
		// the retired copy of the key still in use.
		return nil, errors.New("evidence: the generated key has the same id as the key it would replace; refusing to rotate")
	}

	if err := retirePublicKey(dir, res.RetiredKeyFile, old.Public); err != nil {
		return nil, err
	}
	if err := writePublicKey(filepath.Join(dir, PublicKeyFile), newPub); err != nil {
		return nil, err
	}
	if err := writePrivateKey(filepath.Join(dir, SigningKeyFile), newPriv); err != nil {
		return nil, err
	}
	syncDir(dir)

	seq, err := recordRotation(dir, &KeyPair{Private: newPriv, Public: newPub, ID: res.NewKeyID}, res)
	if err != nil {
		return res, fmt.Errorf(
			"evidence: the key was rotated to %s, but the config_change event recording it could not be appended: %w",
			res.NewKeyID, err)
	}
	res.RecordSeq = seq
	return res, nil
}

// retirePublicKey files the outgoing public key under its own id. Rotating
// twice in a directory that already holds the file is not an error as long as
// the contents agree, which is what re-running an interrupted rotation looks
// like; a file holding a different key is refused rather than overwritten,
// because overwriting it would destroy the only copy of a key that signed
// records still in the log.
func retirePublicKey(dir, relPath string, pub ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Join(dir, RetiredKeysDir), 0o750); err != nil {
		return fmt.Errorf("evidence: create %s: %w", RetiredKeysDir, err)
	}
	full := filepath.Join(dir, relPath)

	switch existing, err := LoadPublicKeyPEM(full); {
	case err == nil:
		if !existing.Equal(pub) {
			return fmt.Errorf(
				"evidence: %s already holds key %s, not the key being retired (%s); refusing to overwrite a retired key",
				relPath, KeyID(existing), KeyID(pub))
		}
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("evidence: read %s: %w", relPath, err)
	}

	if err := writePublicKey(full, pub); err != nil {
		return err
	}
	syncDir(filepath.Dir(full))
	return nil
}

// writePrivateKey replaces the signing key in one step. The replacement is a
// rename over the old name rather than an unlink followed by a write, so there
// is no window in which the directory holds no signing key at all.
func writePrivateKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("evidence: encode signing key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der})
	if err := atomicWriteFile(path, encoded, 0o600); err != nil {
		return fmt.Errorf("evidence: write signing key: %w", err)
	}
	return nil
}

// recordRotation appends the config_change event and returns its sequence
// number. It opens the store briefly under the new key, which also means the
// shutdown checkpoint that closes the run is the first attestation signed by
// the key that has just taken over.
func recordRotation(dir string, kp *KeyPair, res *RotationResult) (uint64, error) {
	s, err := Open(Options{Dir: dir, Keys: kp})
	if err != nil {
		return 0, err
	}
	appendErr := s.Append(&Event{
		EventType: EventConfigChange,
		RequestID: "key-rotation-" + res.NewKeyID,
		Note: fmt.Sprintf(
			"signing key rotated from %s to %s; the retired public key is kept at %s so that checkpoints signed before the rotation still verify",
			res.OldKeyID, res.NewKeyID, res.RetiredKeyFile),
	})
	closeErr := s.Close()
	if appendErr != nil {
		return 0, appendErr
	}
	if closeErr != nil {
		return 0, closeErr
	}

	segs, err := Segments(dir)
	if err != nil {
		return 0, err
	}
	seq, _, err := recoverChainHead(dir, segs)
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// RetireResult is what RetirePublicKey did.
type RetireResult struct {
	KeyID    string `json:"key_id"`
	Path     string `json:"path"`
	Existing bool   `json:"already_retired"`
}

// RetirePublicKey files a public key under keys/ so that checkpoints signed
// with it stay verifiable after it stops being the active key.
//
// It exists for the external-signer case. Rotation happens at the helper there,
// where this tool cannot reach it, and the only supported next step was to
// point signer_public_key at the new key. Doing that left every earlier
// checkpoint attributed to a key the directory no longer holds, so verify
// reported unknown_key on all of them, permanently. SECURITY.md says rotation
// must never strand old checkpoints; this is the operation that keeps that
// true when the private half is somewhere else.
//
// It refuses while a writer holds the directory, and it never overwrites a
// retired key with a different one.
func RetirePublicKey(dir, pemPath string) (*RetireResult, error) {
	if err := refuseWhileWriterHolds(dir, "retire a public key"); err != nil {
		return nil, err
	}
	pub, err := LoadPublicKeyPEM(pemPath)
	if err != nil {
		return nil, fmt.Errorf("evidence: retire public key: %w", err)
	}
	id := KeyID(pub)
	rel := filepath.Join(RetiredKeysDir, "retired-"+id+".pem")

	if existing, err := LoadPublicKeyPEM(filepath.Join(dir, rel)); err == nil && existing.Equal(pub) {
		return &RetireResult{KeyID: id, Path: rel, Existing: true}, nil
	}
	if err := retirePublicKey(dir, rel, pub); err != nil {
		return nil, err
	}
	return &RetireResult{KeyID: id, Path: rel}, nil
}
