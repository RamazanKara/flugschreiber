package evidence

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// retiredKeyPrefix and retiredKeySuffix bracket the key id in the name a
// retired public key is filed under, so that the file says which key it holds
// without being opened.
const (
	retiredKeyPrefix = "retired-"
	retiredKeySuffix = ".pem"
)

// KnownKey is one public key a verifier will accept, and where it came from.
type KnownKey struct {
	ID     string `json:"key_id"`
	Source string `json:"source"`

	// Retired marks a key that rotation replaced. It still verifies everything
	// it signed before the rotation; it must never sign anything again.
	Retired bool `json:"retired,omitempty"`

	Public ed25519.PublicKey `json:"-"`
}

// UnreadableKey is a key file that exists but that this build cannot use.
// It is carried rather than returned as an error because one damaged retired
// key must not stop the other keys from checking the signatures they cover.
type UnreadableKey struct {
	Source string
	Err    error
}

// KeySet is every public key that may legitimately have signed something in
// one evidence directory: the current public-key.pem, plus every key rotation
// has retired into keys/.
//
// Verification needs the whole set rather than the current key alone. After a
// rotation the log holds checkpoints signed under both, and checking them
// against the current key only would report the older half as signed by an
// unknown key, which is the report reserved for a signature nobody in this
// directory can account for.
type KeySet struct {
	Keys       []KnownKey
	Unreadable []UnreadableKey
}

// LoadKeySet reads every public key in dir.
//
// It reports no error of its own. Every key file stands alone, so one that
// cannot be read is recorded in Unreadable and the rest are still usable:
// making a damaged retired key stop the current key from checking anything
// would turn one corrupt file into a log that cannot be verified at all, which
// is both wrong and a rather convenient thing for an attacker to arrange.
func LoadKeySet(dir string) *KeySet {
	ks := &KeySet{}

	switch pub, err := LoadPublicKeyPEM(filepath.Join(dir, PublicKeyFile)); {
	case err == nil:
		ks.Keys = append(ks.Keys, KnownKey{ID: KeyID(pub), Source: PublicKeyFile, Public: pub})
	case errors.Is(err, fs.ErrNotExist):
		// A log written with signing off has no key and is still a valid log.
	default:
		ks.Unreadable = append(ks.Unreadable, UnreadableKey{Source: PublicKeyFile, Err: err})
	}

	files, err := RetiredKeyFiles(dir)
	if err != nil {
		ks.Unreadable = append(ks.Unreadable, UnreadableKey{Source: RetiredKeysDir, Err: err})
	}
	for _, name := range files {
		pub, err := LoadPublicKeyPEM(filepath.Join(dir, name))
		if err != nil {
			ks.Unreadable = append(ks.Unreadable, UnreadableKey{Source: name, Err: err})
			continue
		}
		id := KeyID(pub)
		// The name states which key the file holds. A file whose name and
		// contents disagree is either a copy made by hand or a key somebody
		// added hoping their signatures would be accepted, and neither should
		// pass without being said out loud.
		if want := retiredKeyID(name); want != id {
			ks.Unreadable = append(ks.Unreadable, UnreadableKey{
				Source: name,
				Err: fmt.Errorf(
					"the file name claims key %s but it holds key %s; a retired key is filed under its own id",
					want, id),
			})
			continue
		}
		ks.Keys = append(ks.Keys, KnownKey{ID: id, Source: name, Retired: true, Public: pub})
	}
	return ks
}

// RetiredKeyFiles lists the retired public keys in dir, as paths relative to
// it, in a stable order. Export bundles and operator tooling need the list
// without needing to know how the directory is laid out.
func RetiredKeyFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, RetiredKeysDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("evidence: read %s: %w", RetiredKeysDir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, retiredKeyPrefix) || !strings.HasSuffix(name, retiredKeySuffix) {
			continue
		}
		out = append(out, path.Join(RetiredKeysDir, name))
	}
	sort.Strings(out)
	return out, nil
}

// ByID returns the key a signature names. An empty id matches nothing: a
// signature nobody can attribute is not evidence, and guessing which key was
// meant would be exactly the wrong kind of helpful.
func (ks *KeySet) ByID(id string) (KnownKey, bool) {
	if id == "" {
		return KnownKey{}, false
	}
	for _, k := range ks.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return KnownKey{}, false
}

// Current returns the key the store signs with now, if the directory has one.
func (ks *KeySet) Current() (KnownKey, bool) {
	for _, k := range ks.Keys {
		if !k.Retired {
			return k, true
		}
	}
	return KnownKey{}, false
}

// RetiredIDs lists the ids of the retired keys, in file order.
func (ks *KeySet) RetiredIDs() []string {
	var out []string
	for _, k := range ks.Keys {
		if k.Retired {
			out = append(out, k.ID)
		}
	}
	return out
}

// Len reports how many usable keys the set holds.
func (ks *KeySet) Len() int { return len(ks.Keys) }

// retiredKeyID recovers the key id a retired key file is named for.
func retiredKeyID(name string) string {
	base := filepath.Base(name)
	base = strings.TrimPrefix(base, retiredKeyPrefix)
	return strings.TrimSuffix(base, retiredKeySuffix)
}

// retiredKeyFile renders the name a key of this id is retired under. The
// separator is a forward slash rather than the platform's, because the name is
// also a path inside an export bundle and an object key in an archive, and
// those are slash-separated everywhere.
func retiredKeyFile(keyID string) string {
	return path.Join(RetiredKeysDir, retiredKeyPrefix+keyID+retiredKeySuffix)
}
