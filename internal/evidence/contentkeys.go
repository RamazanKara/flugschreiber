package evidence

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// ContentKeystoreFile is where the content-encryption keys live by default. It
// is a separate file from the chain, and it is the one file in an evidence
// directory whose loss is not recoverable and whose disclosure undoes every
// erasure ever performed: everything else in the directory is either public or
// reproducible, this is neither.
//
// It is never archived, never exported and never included in a bundle. See
// SECURITY.md for what an operator has to do with it instead.
const ContentKeystoreFile = "content-keys.json"

// ContentKeyAlgorithm is the algorithm recorded in Content.Encryption and the
// only one this version reads or writes.
const ContentKeyAlgorithm = "AES-256-GCM"

const (
	contentKeystoreVersion = 1
	contentKeyBytes        = 32
	contentKeyIDBytes      = 16
	contentNonceBytes      = 12

	// wrapDomain and masterIDDomain separate the two uses of the master key
	// from each other and from every other SHA-256 in this project.
	wrapDomain     = "flugschreiber-content-key-wrap-v1"
	masterIDDomain = "flugschreiber-content-master-v1"
)

// ContentKeyState is what a keystore knows about one key id.
type ContentKeyState string

// The three answers a keystore can give about a key id. Unknown is deliberately
// distinct from Erased: a reader holding no keystore at all, or a copy of the
// log taken elsewhere, must not report content as erased when all it can
// honestly say is that it cannot decrypt it here.
const (
	ContentKeyAvailable ContentKeyState = "available"
	ContentKeyErased    ContentKeyState = "erased"
	ContentKeyUnknown   ContentKeyState = "unknown"
)

// ErrContentKeyErased is returned for a key an erasure has destroyed. It is a
// permanent answer: there is no recovery path, by design.
var ErrContentKeyErased = errors.New("evidence: the content key has been erased and the content cannot be recovered")

// ErrContentKeyUnknown is returned for a key id this keystore never held.
var ErrContentKeyUnknown = errors.New("evidence: no such content key in this keystore")

// ErasedDigestCaveat is what every renderer must say about the digests on a
// record whose content has been erased. The sha256 stays in the chain and the
// chain still verifies, but nobody can produce the bytes it covers any more, so
// it has stopped being a checkable digest and become a claim. Saying "content
// not retained" instead would imply it was never stored, and saying nothing at
// all would let a reader take the digest for something it can still test.
const ErasedDigestCaveat = "The sha256 and byte count on an erased record are the digest of the original " +
	"request and response as they crossed the wire, recorded when the interaction happened. They are unchanged " +
	"and the chain over them still verifies. With the content destroyed nobody can recompute them from the " +
	"content, so they stand as a claim that can no longer be re-proven."

// ContentKeystore holds the master content key and the wrapped per-session
// keys the stored text is encrypted under.
//
// The wrapping is what makes Article 17 erasure possible without touching the
// evidence: destroying one wrapped key destroys the readability of exactly the
// records that used it, and the records themselves are never rewritten, so the
// hash chain over them is not disturbed by an erasure at all.
//
// A ContentKeystore is safe for concurrent use. It is not safe for two
// processes: the erase command refuses while a writer holds the directory, for
// the same reason key rotation does.
type ContentKeystore struct {
	// Now is injectable so that tests and golden output are deterministic.
	Now func() time.Time

	path string

	mu     sync.Mutex
	file   contentKeystoreFile
	master []byte

	// bySession indexes the live keys, and unwrapped caches the plaintext keys
	// so that a busy session does not repeat the unwrap on every record. Both
	// are rebuilt from file on load and pruned on erasure; a key that has been
	// destroyed must not survive in a cache.
	bySession map[string]string
	unwrapped map[string][]byte
}

// contentKeyEntry is one live key as it sits on disk. It is unexported, and the
// wrapped material never appears in any type this package returns, so no caller
// can print or serialise a key by accident.
type contentKeyEntry struct {
	KeyID     string `json:"key_id"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	CreatedAt string `json:"created_at"`
	Wrapped   string `json:"wrapped_key"`
}

type contentKeystoreFile struct {
	Version     int                        `json:"version"`
	Algorithm   string                     `json:"algorithm"`
	MasterKeyID string                     `json:"master_key_id"`
	MasterKey   string                     `json:"master_key"`
	Keys        map[string]contentKeyEntry `json:"keys"`
	Erased      []ErasedContentKey         `json:"erased,omitempty"`
}

// ContentKeyInfo describes a key without disclosing anything about it that
// would help decrypt anything.
type ContentKeyInfo struct {
	KeyID     string `json:"key_id"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// ErasedContentKey is the tombstone left where a content key used to be.
//
// The tombstone is what makes erasure idempotent and honest afterwards: a
// second erasure of the same session reports the date of the first rather than
// pretending to destroy something, and a reader can tell "erased on this date"
// from "this keystore never had that key".
type ErasedContentKey struct {
	KeyID     string `json:"key_id"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	ErasedAt  string `json:"erased_at"`
	Requester string `json:"requester,omitempty"`
	Reason    string `json:"reason,omitempty"`

	// Recorded is true once the chain holds the system_event describing this
	// erasure. Keys are destroyed before the event is appended, because a log
	// claiming an erasure that did not happen is worse than an erasure the log
	// has not caught up with yet; this flag is how the next run finishes the
	// job instead of leaving the chain silent.
	Recorded bool `json:"recorded_in_chain"`
}

// ContentErasureRequest selects what to destroy.
type ContentErasureRequest struct {
	// SessionID erases every key issued for one session, live or already gone.
	SessionID string

	// KeyIDs erases named keys, which is how erasure by request id works: the
	// record names the key that sealed it.
	KeyIDs []string

	// Requester and Reason are recorded in the tombstone and in the chain.
	// Neither is verified by Flugschreiber; they are what the operator states.
	Requester string
	Reason    string

	// DryRun computes the result and writes nothing.
	DryRun bool
}

// ContentErasureResult is what an erasure did, or would do. It carries no key
// material, so it is safe to print and to serialise.
type ContentErasureResult struct {
	Keystore  string `json:"keystore"`
	DryRun    bool   `json:"dry_run"`
	SessionID string `json:"session_id,omitempty"`

	// Destroyed lists the keys this call removed, or would remove.
	Destroyed []ContentKeyInfo `json:"destroyed,omitempty"`

	// AlreadyErased lists the keys an earlier erasure had already destroyed.
	AlreadyErased []ErasedContentKey `json:"already_erased,omitempty"`

	// Unknown lists key ids this keystore has never held. A record naming one
	// of them was written against a different keystore.
	Unknown []string `json:"unknown_key_ids,omitempty"`

	// Pending lists tombstones the chain does not yet document, including the
	// ones this call created. The caller appends the erasure event and then
	// calls MarkRecorded with these ids.
	Pending []ErasedContentKey `json:"pending_chain_record,omitempty"`
}

// ContentKeystorePath is the default keystore location for an evidence
// directory.
func ContentKeystorePath(dir string) string {
	return filepath.Join(dir, ContentKeystoreFile)
}

// OpenContentKeystore opens the keystore at path, generating a master key on
// first use. Two processes racing to create it converge on whichever key
// reached the disk first, exactly as the signing key does, because the loser
// overwriting the winner would orphan every record already sealed.
func OpenContentKeystore(path string) (*ContentKeystore, error) {
	if path == "" {
		return nil, errors.New("evidence: content keystore path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("evidence: create content keystore directory: %w", err)
	}

	k := &ContentKeystore{Now: time.Now, path: path}
	err := k.load()
	if errors.Is(err, fs.ErrNotExist) {
		if createErr := createContentKeystore(path); createErr != nil && !errors.Is(createErr, fs.ErrExist) {
			return nil, createErr
		}
		err = k.load()
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Path reports where this keystore lives, so that a refusal or a report can
// name the file an operator has to look after.
func (k *ContentKeystore) Path() string { return k.path }

// MasterKeyID identifies the master key without disclosing it.
func (k *ContentKeystore) MasterKeyID() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.file.MasterKeyID
}

// KeyFor returns the content key a record's stored text is sealed under,
// together with the id that goes into Content.Encryption.
//
// Keys are per session, so that an erasure request naming a data subject's
// session destroys that session and nothing else. Traffic with no session id
// gets a key per record: it is the only granularity available, it costs a
// keystore write per record, and the alternative would be one key covering
// unrelated callers, where erasing for one destroys the evidence about all the
// others.
func (k *ContentKeystore) KeyFor(sessionID, requestID string) ([]byte, string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if sessionID != "" {
		if id, ok := k.bySession[sessionID]; ok {
			key, err := k.unwrapLocked(id)
			if err != nil {
				return nil, "", err
			}
			return key, id, nil
		}
	}

	key := make([]byte, contentKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", fmt.Errorf("evidence: generate content key: %w", err)
	}
	idRaw := make([]byte, contentKeyIDBytes)
	if _, err := io.ReadFull(rand.Reader, idRaw); err != nil {
		return nil, "", fmt.Errorf("evidence: generate content key id: %w", err)
	}
	id := hex.EncodeToString(idRaw)

	wrapped, err := SealContent(k.master, wrapAAD(id, sessionID), key)
	if err != nil {
		return nil, "", fmt.Errorf("evidence: wrap content key: %w", err)
	}
	k.file.Keys[id] = contentKeyEntry{
		KeyID:     id,
		SessionID: sessionID,
		RequestID: requestID,
		CreatedAt: k.now(),
		Wrapped:   wrapped,
	}
	if sessionID != "" {
		k.bySession[sessionID] = id
	}
	k.unwrapped[id] = key

	if err := k.saveLocked(); err != nil {
		// The key never reached the disk, so nothing may be sealed under it:
		// a record whose key is not in the keystore is a record nobody can
		// read and nobody can erase either.
		delete(k.file.Keys, id)
		delete(k.unwrapped, id)
		delete(k.bySession, sessionID)
		return nil, "", err
	}
	return key, id, nil
}

// Key returns the content key with this id, or ErrContentKeyErased when an
// erasure has destroyed it.
func (k *ContentKeystore) Key(keyID string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.unwrapLocked(keyID)
}

// State reports what this keystore knows about a key id. A nil keystore
// answers Unknown, which is what a reader without one can honestly say.
func (k *ContentKeystore) State(keyID string) ContentKeyState {
	if k == nil || keyID == "" {
		return ContentKeyUnknown
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.file.Keys[keyID]; ok {
		return ContentKeyAvailable
	}
	if _, ok := k.erasedLocked(keyID); ok {
		return ContentKeyErased
	}
	return ContentKeyUnknown
}

// MarkErased fills in Erased and ErasedAt on an event that has been read back,
// and reports whether it changed anything.
//
// Nothing on disk ever carries Erased: the chain hashes each record as it was
// written, so an erasure must not go back and stamp the records it covers. The
// erased state is therefore derived at read time from the keystore, which is
// also why a reader with no keystore renders the content as undecryptable here
// rather than as erased.
func (k *ContentKeystore) MarkErased(ev *Event) bool {
	if k == nil || ev == nil || ev.Content == nil || ev.Content.Encryption == nil {
		return false
	}
	enc := ev.Content.Encryption
	k.mu.Lock()
	defer k.mu.Unlock()
	tomb, ok := k.erasedLocked(enc.KeyID)
	if !ok {
		return false
	}
	enc.Erased = true
	enc.ErasedAt = tomb.ErasedAt
	return true
}

// Erase destroys wrapped keys and leaves tombstones in their place.
//
// It never touches a segment, a checkpoint or a record. That is the whole
// design: the evidence stays byte for byte as it was written and keeps
// verifying, and what disappears is the ability to read the text inside it.
func (k *ContentKeystore) Erase(req ContentErasureRequest) (*ContentErasureResult, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	res := &ContentErasureResult{
		Keystore:  k.path,
		DryRun:    req.DryRun,
		SessionID: req.SessionID,
	}

	targets := k.targetsLocked(req)
	now := k.now()
	var fresh []ErasedContentKey

	for _, id := range targets {
		entry, live := k.file.Keys[id]
		if live {
			res.Destroyed = append(res.Destroyed, ContentKeyInfo{
				KeyID:     entry.KeyID,
				SessionID: entry.SessionID,
				RequestID: entry.RequestID,
				CreatedAt: entry.CreatedAt,
			})
			fresh = append(fresh, ErasedContentKey{
				KeyID:     entry.KeyID,
				SessionID: entry.SessionID,
				RequestID: entry.RequestID,
				ErasedAt:  now,
				Requester: req.Requester,
				Reason:    req.Reason,
			})
			continue
		}
		if tomb, ok := k.erasedLocked(id); ok {
			res.AlreadyErased = append(res.AlreadyErased, tomb)
			if !tomb.Recorded {
				res.Pending = append(res.Pending, tomb)
			}
			continue
		}
		res.Unknown = append(res.Unknown, id)
	}
	res.Pending = append(res.Pending, fresh...)

	if req.DryRun || len(fresh) == 0 {
		return res, nil
	}

	for _, tomb := range fresh {
		entry := k.file.Keys[tomb.KeyID]
		delete(k.file.Keys, tomb.KeyID)
		delete(k.unwrapped, tomb.KeyID)
		if entry.SessionID != "" && k.bySession[entry.SessionID] == tomb.KeyID {
			delete(k.bySession, entry.SessionID)
		}
		k.file.Erased = append(k.file.Erased, tomb)
	}
	if err := k.saveLocked(); err != nil {
		// The in-memory state is now ahead of the disk, so it is reloaded
		// rather than left claiming a destruction the file does not record.
		if reloadErr := k.loadLocked(); reloadErr != nil {
			return nil, errors.Join(err, fmt.Errorf("evidence: the keystore could not be reloaded either: %w", reloadErr))
		}
		return nil, err
	}
	return res, nil
}

// MarkRecorded notes that the chain now documents these erasures.
func (k *ContentKeystore) MarkRecorded(keyIDs []string) error {
	if len(keyIDs) == 0 {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	want := make(map[string]bool, len(keyIDs))
	for _, id := range keyIDs {
		want[id] = true
	}
	changed := false
	for i := range k.file.Erased {
		if want[k.file.Erased[i].KeyID] && !k.file.Erased[i].Recorded {
			k.file.Erased[i].Recorded = true
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return k.saveLocked()
}

// SessionsWithKeys lists the sessions this keystore still holds a key for, in
// a stable order. It is how an operator finds out what is still erasable
// without reading the log.
func (k *ContentKeystore) SessionsWithKeys() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range k.file.Keys {
		if e.SessionID == "" || seen[e.SessionID] {
			continue
		}
		seen[e.SessionID] = true
		out = append(out, e.SessionID)
	}
	sort.Strings(out)
	return out
}

// targetsLocked resolves a request to a sorted, deduplicated set of key ids.
func (k *ContentKeystore) targetsLocked(req ContentErasureRequest) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, id := range req.KeyIDs {
		add(id)
	}
	if req.SessionID != "" {
		for _, e := range k.file.Keys {
			if e.SessionID == req.SessionID {
				add(e.KeyID)
			}
		}
		for _, t := range k.file.Erased {
			if t.SessionID == req.SessionID {
				add(t.KeyID)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (k *ContentKeystore) erasedLocked(keyID string) (ErasedContentKey, bool) {
	for _, t := range k.file.Erased {
		if t.KeyID == keyID {
			return t, true
		}
	}
	return ErasedContentKey{}, false
}

func (k *ContentKeystore) unwrapLocked(keyID string) ([]byte, error) {
	if key, ok := k.unwrapped[keyID]; ok {
		return key, nil
	}
	entry, ok := k.file.Keys[keyID]
	if !ok {
		if _, erased := k.erasedLocked(keyID); erased {
			return nil, ErrContentKeyErased
		}
		return nil, ErrContentKeyUnknown
	}
	key, err := OpenContent(k.master, wrapAAD(entry.KeyID, entry.SessionID), entry.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("evidence: unwrap content key %s: %w", keyID, err)
	}
	if len(key) != contentKeyBytes {
		return nil, fmt.Errorf("evidence: content key %s unwrapped to %d bytes, expected %d", keyID, len(key), contentKeyBytes)
	}
	k.unwrapped[keyID] = key
	return key, nil
}

func (k *ContentKeystore) now() string {
	now := k.Now
	if now == nil {
		now = time.Now
	}
	return now().UTC().Format(time.RFC3339Nano)
}

func (k *ContentKeystore) load() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.loadLocked()
}

func (k *ContentKeystore) loadLocked() error {
	info, err := os.Stat(k.path)
	if err != nil {
		return err
	}
	if err := checkKeystoreMode(k.path, info.Mode().Perm()); err != nil {
		return err
	}
	raw, err := os.ReadFile(k.path)
	if err != nil {
		return err
	}

	var f contentKeystoreFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("evidence: read content keystore %s: %w", k.path, err)
	}
	if f.Version != contentKeystoreVersion {
		return fmt.Errorf(
			"evidence: content keystore %s is version %d, this build writes version %d",
			k.path, f.Version, contentKeystoreVersion)
	}
	if f.Algorithm != ContentKeyAlgorithm {
		return fmt.Errorf(
			"evidence: content keystore %s names algorithm %q, this build implements %q",
			k.path, f.Algorithm, ContentKeyAlgorithm)
	}
	master, err := base64.StdEncoding.DecodeString(f.MasterKey)
	if err != nil {
		return fmt.Errorf("evidence: content keystore %s: decode master key: %w", k.path, err)
	}
	if len(master) != contentKeyBytes {
		return fmt.Errorf(
			"evidence: content keystore %s holds a %d-byte master key, expected %d",
			k.path, len(master), contentKeyBytes)
	}
	if id := masterKeyID(master); id != f.MasterKeyID {
		return fmt.Errorf(
			"evidence: content keystore %s says master key %s but holds master key %s; a keystore whose master key has been swapped can decrypt nothing it wrapped, restore the original rather than continuing",
			k.path, f.MasterKeyID, id)
	}
	if f.Keys == nil {
		f.Keys = map[string]contentKeyEntry{}
	}

	k.file = f
	k.master = master
	k.bySession = map[string]string{}
	k.unwrapped = map[string][]byte{}
	for id, e := range f.Keys {
		if e.KeyID != id {
			return fmt.Errorf(
				"evidence: content keystore %s files key %s under the name %s; refusing to guess which id the records name",
				k.path, e.KeyID, id)
		}
		if e.SessionID != "" {
			k.bySession[e.SessionID] = id
		}
	}
	return nil
}

func (k *ContentKeystore) saveLocked() error {
	body, err := json.MarshalIndent(k.file, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: marshal content keystore: %w", err)
	}
	body = append(body, '\n')
	if err := atomicWriteFile(k.path, body, 0o600); err != nil {
		return fmt.Errorf("evidence: write content keystore %s: %w", k.path, err)
	}
	return nil
}

func createContentKeystore(path string) error {
	master := make([]byte, contentKeyBytes)
	if _, err := io.ReadFull(rand.Reader, master); err != nil {
		return fmt.Errorf("evidence: generate master content key: %w", err)
	}
	body, err := json.MarshalIndent(contentKeystoreFile{
		Version:     contentKeystoreVersion,
		Algorithm:   ContentKeyAlgorithm,
		MasterKeyID: masterKeyID(master),
		MasterKey:   base64.StdEncoding.EncodeToString(master),
		Keys:        map[string]contentKeyEntry{},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: marshal content keystore: %w", err)
	}
	body = append(body, '\n')
	if err := linkNewFile(path, body, 0o600); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// masterKeyID names the master key without disclosing it: the id is a
// domain-separated digest, so it can be printed in a report and compared
// across hosts, and it says nothing about the key it identifies.
func masterKeyID(master []byte) string {
	h := sha256.New()
	h.Write([]byte(masterIDDomain))
	h.Write([]byte{0})
	h.Write(master)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// wrapAAD binds a wrapped key to its own id and session, so that a wrapped key
// cannot be moved to another entry in the file and unwrapped there.
func wrapAAD(keyID, sessionID string) string {
	return wrapDomain + "\x00" + keyID + "\x00" + sessionID
}

// SealContent encrypts plaintext under a 32-byte content key and returns
// base64(nonce || AES-256-GCM ciphertext), which is what Payload.Ciphertext
// and the keystore's wrapped keys both hold.
//
// aad is authenticated but not encrypted. Callers bind the ciphertext to where
// it belongs with it, so that moving a sealed value to another record or
// another field fails to open rather than decrypting into the wrong place.
func SealContent(key []byte, aad string, plaintext []byte) (string, error) {
	gcm, err := contentAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("evidence: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(aad))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenContent reverses SealContent.
//
// It fails closed. A wrong key, a wrong aad or a single flipped bit fails the
// GCM tag and returns an error; there is no path on which this returns
// plausible-looking rubbish, which is what would turn a mis-keyed transcript
// into evidence of something that was never said.
func OpenContent(key []byte, aad string, sealed string) ([]byte, error) {
	gcm, err := contentAEAD(key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("evidence: decode ciphertext: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("evidence: ciphertext is %d bytes, too short to hold a %d-byte nonce", len(raw), gcm.NonceSize())
	}
	nonce, body := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("evidence: decrypt content: %w", err)
	}
	return out, nil
}

func contentAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != contentKeyBytes {
		return nil, fmt.Errorf("evidence: content key is %d bytes, expected %d", len(key), contentKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("evidence: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("evidence: aes-gcm: %w", err)
	}
	if gcm.NonceSize() != contentNonceBytes {
		return nil, fmt.Errorf("evidence: aes-gcm nonce is %d bytes, expected %d", gcm.NonceSize(), contentNonceBytes)
	}
	return gcm, nil
}

// checkKeystoreMode refuses a keystore that group or other can read. Anyone who
// can read this file can read every stored prompt in the directory and can undo
// an erasure that has already been reported as done.
func checkKeystoreMode(path string, mode fs.FileMode) error {
	if runtime.GOOS == "windows" {
		// Go synthesises Unix permission bits on Windows, so the check would
		// reject every keystore there while proving nothing about the real ACL.
		return nil
	}
	if mode&0o077 == 0 {
		return nil
	}
	return fmt.Errorf(
		"evidence: content keystore %s has mode %04o and is readable by group or other; anyone who can read it can read every stored prompt, run chmod 600 %s",
		path, uint32(mode), path)
}

// Describe renders the encryption marker for a human reader.
//
// Erased content is never rendered as absent or empty. A reader who is shown
// nothing concludes nothing was said; a reader who is shown "erased on this
// date" learns that something was said, that it was destroyed on request, and
// that the record of the interaction is still there.
func (c *ContentEncryption) Describe() string {
	switch {
	case c == nil:
		return ""
	case c.Erased && c.ErasedAt != "":
		return "content erased " + c.ErasedAt + "; the key that could decrypt it has been destroyed and it cannot be recovered"
	case c.Erased:
		return "content erased; the key that could decrypt it has been destroyed and it cannot be recovered"
	default:
		return "content encrypted at rest with " + c.Algorithm + " under key " + c.KeyID
	}
}

// Placeholder is what a renderer puts inline where the text of an erased
// record would have gone, and the empty string for a record that is not
// erased.
//
// It is never blank for an erased record. A blank line reads as an interaction
// with nothing in it, which is the one thing an erased record is not: something
// was said, it was recorded, and it was destroyed on request.
func (c *ContentEncryption) Placeholder() string {
	if c == nil || !c.Erased {
		return ""
	}
	if c.ErasedAt != "" {
		return "[content erased " + c.ErasedAt + ", the decryption key was destroyed]"
	}
	return "[content erased, the decryption key was destroyed]"
}
