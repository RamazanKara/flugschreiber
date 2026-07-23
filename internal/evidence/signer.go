package evidence

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Signer produces the signature over a checkpoint preimage.
//
// It exists so that the private half of the signing key does not have to sit
// beside the evidence it attests to. The checkpoint contract is unchanged
// whichever implementation is in use: the preimage is the same bytes, the
// algorithm is still Ed25519, and verification still needs nothing but the
// public keys on disk. Custody moves; the format does not.
//
// Sign must return a detached Ed25519 signature over preimage, exactly as
// ed25519.Sign would. An implementation that cannot sign returns an error and
// the store treats that as a write error: a checkpoint is never written
// unsigned, and a record is never dropped because signing failed.
type Signer interface {
	Sign(preimage []byte) (sig []byte, err error)
	Public() ed25519.PublicKey
	KeyID() string
}

// KeyPairSigner signs with the key file in the evidence directory, which is
// the default and needs no external process.
//
// It is a wrapper rather than a method set on KeyPair itself because KeyPair
// already carries Public and ID as fields, and a Go type cannot have a field
// and a method of the same name.
type KeyPairSigner struct {
	kp *KeyPair
}

// NewKeyPairSigner adapts a file-based KeyPair to the Signer interface.
func NewKeyPairSigner(kp *KeyPair) *KeyPairSigner {
	return &KeyPairSigner{kp: kp}
}

// Sign signs preimage with the private key.
func (s *KeyPairSigner) Sign(preimage []byte) ([]byte, error) {
	if s == nil || s.kp == nil {
		return nil, errors.New("evidence: no signing key")
	}
	if len(s.kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("evidence: signing key is %d bytes, expected %d", len(s.kp.Private), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(s.kp.Private, preimage), nil
}

// Public returns the public half, which is what a verifier needs.
func (s *KeyPairSigner) Public() ed25519.PublicKey {
	if s == nil || s.kp == nil {
		return nil
	}
	return s.kp.Public
}

// KeyID returns the id every signature is attributed to.
func (s *KeyPairSigner) KeyID() string {
	if s == nil || s.kp == nil {
		return ""
	}
	return s.kp.ID
}
