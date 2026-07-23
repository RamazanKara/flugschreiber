package evidence

import (
	"crypto/ed25519"
	"testing"
)

// The file-based key must satisfy the same interface as an external one, or
// the two paths would drift apart and only one of them would be tested. The
// external path lives in internal/custody, along with its tests, because it
// starts a subprocess and this package's closure stays free of that.
func TestKeyPairSignerSatisfiesTheSignerContract(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	var signer Signer = NewKeyPairSigner(kp)

	if signer.KeyID() != kp.ID {
		t.Errorf("KeyID = %s, want %s", signer.KeyID(), kp.ID)
	}
	if !signer.Public().Equal(kp.Public) {
		t.Error("Public does not return the key pair's public half")
	}
	sig, err := signer.Sign([]byte("preimage"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(kp.Public, []byte("preimage"), sig) {
		t.Error("the signature does not verify against the public half")
	}
}
