package evidence

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newTestKeystore(t *testing.T) *ContentKeystore {
	t.Helper()
	ks, err := OpenContentKeystore(ContentKeystorePath(t.TempDir()))
	if err != nil {
		t.Fatalf("open keystore: %v", err)
	}
	ks.Now = func() time.Time { return time.Date(2026, 7, 24, 9, 0, 0, 0, time.UTC) }
	return ks
}

// One session, one key. Two records of the same conversation have to decrypt
// under the same key, or an erasure would have to hunt down one key per record
// and would miss any it could not find.
func TestContentKeyIsStablePerSession(t *testing.T) {
	ks := newTestKeystore(t)

	first, firstID, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	second, secondID, err := ks.KeyFor("s-1", "r-2")
	if err != nil {
		t.Fatal(err)
	}
	if firstID != secondID {
		t.Errorf("two records of session s-1 got key ids %s and %s", firstID, secondID)
	}
	if !bytes.Equal(first, second) {
		t.Error("two records of session s-1 got different key material under one key id")
	}
	if len(first) != contentKeyBytes {
		t.Errorf("content key is %d bytes, want %d", len(first), contentKeyBytes)
	}
}

// Two sessions must not share a key, or erasing for one data subject would
// destroy the evidence about another.
func TestContentKeysDifferBetweenSessions(t *testing.T) {
	ks := newTestKeystore(t)

	a, aID, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	b, bID, err := ks.KeyFor("s-2", "r-2")
	if err != nil {
		t.Fatal(err)
	}
	if aID == bID {
		t.Fatalf("sessions s-1 and s-2 share key id %s", aID)
	}
	if bytes.Equal(a, b) {
		t.Error("sessions s-1 and s-2 share key material")
	}

	if _, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(aID); !errors.Is(err, ErrContentKeyErased) {
		t.Errorf("key of the erased session reports %v, want ErrContentKeyErased", err)
	}
	got, err := ks.Key(bID)
	if err != nil {
		t.Fatalf("erasing session s-1 broke session s-2: %v", err)
	}
	if !bytes.Equal(got, b) {
		t.Error("erasing session s-1 changed the key of session s-2")
	}
}

// Traffic that carries no session id falls back to a key per record, which is
// the only granularity left that lets one record be erased on its own.
func TestRecordsWithoutASessionGetTheirOwnKey(t *testing.T) {
	ks := newTestKeystore(t)

	_, firstID, err := ks.KeyFor("", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	_, secondID, err := ks.KeyFor("", "r-2")
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatalf("two sessionless records share key %s, so neither can be erased alone", firstID)
	}

	if _, err := ks.Erase(ContentErasureRequest{KeyIDs: []string{firstID}, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(firstID); !errors.Is(err, ErrContentKeyErased) {
		t.Errorf("erased record key reports %v, want ErrContentKeyErased", err)
	}
	if _, err := ks.Key(secondID); err != nil {
		t.Errorf("erasing r-1 also destroyed r-2: %v", err)
	}
}

// The whole feature rests on the key actually leaving the file. A tombstone
// beside a key that is still there would erase nothing at all.
func TestErasureRemovesTheKeyFromTheFile(t *testing.T) {
	ks := newTestKeystore(t)

	key, id, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrappedKeyOnDisk(t, ks.Path(), id)

	if _, err := ks.Erase(ContentErasureRequest{
		SessionID: "s-1",
		Requester: "dpo@example.org",
		Reason:    "subject access erasure 2026-13",
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(ks.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(wrapped)) {
		t.Error("the wrapped key is still in the keystore file after an erasure")
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(key))) {
		t.Error("the raw content key appears in the keystore file")
	}

	// A fresh keystore, as the next process would see it.
	reopened, err := OpenContentKeystore(ks.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Key(id); !errors.Is(err, ErrContentKeyErased) {
		t.Errorf("after reopening, key %s reports %v, want ErrContentKeyErased", id, err)
	}
	if got := reopened.State(id); got != ContentKeyErased {
		t.Errorf("State(%s) = %q after reopening, want %q", id, got, ContentKeyErased)
	}
}

func TestErasureDryRunDestroysNothing(t *testing.T) {
	ks := newTestKeystore(t)
	key, id, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ks.Path())
	if err != nil {
		t.Fatal(err)
	}

	res, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", DryRun: true, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Destroyed) != 1 || res.Destroyed[0].KeyID != id {
		t.Fatalf("dry run reported %+v, want the one key it would destroy", res.Destroyed)
	}

	after, err := os.ReadFile(ks.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a dry run rewrote the keystore")
	}
	got, err := ks.Key(id)
	if err != nil {
		t.Fatalf("a dry run destroyed the key: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("a dry run changed the key material")
	}
}

// Erasing twice is not an error and does not pretend to destroy anything the
// second time, because a data subject asking again, or a ticket being replayed,
// must not produce a second erasure event in the chain.
func TestErasureIsIdempotent(t *testing.T) {
	ks := newTestKeystore(t)
	if _, _, err := ks.KeyFor("s-1", "r-1"); err != nil {
		t.Fatal(err)
	}
	first, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.MarkRecorded(pendingIDs(first)); err != nil {
		t.Fatal(err)
	}

	second, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "second"})
	if err != nil {
		t.Fatalf("erasing an already erased session is an error: %v", err)
	}
	if len(second.Destroyed) != 0 {
		t.Errorf("the second erasure claims to have destroyed %d key(s)", len(second.Destroyed))
	}
	if len(second.AlreadyErased) != 1 {
		t.Fatalf("the second erasure reports %d tombstones, want 1", len(second.AlreadyErased))
	}
	if second.AlreadyErased[0].ErasedAt == "" {
		t.Error("the tombstone does not say when the content was erased")
	}
	if second.AlreadyErased[0].KeyID != first.Destroyed[0].KeyID {
		t.Error("the second erasure reports a tombstone for a different key")
	}
	if second.AlreadyErased[0].Reason != "first" {
		t.Errorf("the tombstone reason is %q, want the reason given to the erasure that happened", second.AlreadyErased[0].Reason)
	}
	if len(second.Pending) != 0 {
		t.Error("an erasure the chain already documents is still pending a chain record")
	}
}

// An erasure that could not be appended to the chain has to stay pending, or
// the log would be permanently silent about content that is gone.
func TestUnrecordedErasureStaysPending(t *testing.T) {
	ks := newTestKeystore(t)
	if _, _, err := ks.KeyFor("s-1", "r-1"); err != nil {
		t.Fatal(err)
	}
	first, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Pending) != 1 {
		t.Fatalf("a fresh erasure reports %d pending chain records, want 1", len(first.Pending))
	}

	// The append failed, so nothing was marked as recorded. The next run has
	// to offer the same work again.
	retry, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "retry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(retry.Pending) != 1 {
		t.Errorf("the retry reports %d pending chain records, want the one the failed run left behind", len(retry.Pending))
	}
	if len(retry.Destroyed) != 0 {
		t.Error("the retry destroyed something a second time")
	}
}

// Nothing that leaves this package may carry key material. The erasure result
// is printed and serialised into tickets, so it is the most likely place for a
// wrapped key to escape by accident.
func TestErasureResultCarriesNoKeyMaterial(t *testing.T) {
	ks := newTestKeystore(t)
	key, id, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrappedKeyOnDisk(t, ks.Path(), id)

	res, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{
		"wrapped key": wrapped,
		"content key": base64.StdEncoding.EncodeToString(key),
		"master key":  ks.masterKeyMaterialForTest(),
	} {
		if strings.Contains(string(body), secret) {
			t.Errorf("the serialised erasure result contains the %s", name)
		}
	}
}

// A record read back from the log is told it is erased by the keystore, never
// by the file: the record was written before the erasure and is never rewritten.
func TestMarkErasedComesFromTheKeystoreAndNotTheRecord(t *testing.T) {
	ks := newTestKeystore(t)
	_, id, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	ev := &Event{
		EventType: EventInference,
		RequestID: "r-1",
		SessionID: "s-1",
		Content: &Content{
			Mode:       ModeStore,
			Encryption: &ContentEncryption{Algorithm: ContentKeyAlgorithm, KeyID: id},
			Input:      &Payload{SHA256: "abc", Ciphertext: "sealed"},
		},
	}

	if ks.MarkErased(ev) {
		t.Fatal("a record whose key is still there was marked as erased")
	}
	if ev.Content.Encryption.Erased {
		t.Fatal("Erased was set on a record that is not erased")
	}

	if _, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if !ks.MarkErased(ev) {
		t.Fatal("a record whose key has been destroyed was not marked as erased")
	}
	if !ev.Content.Encryption.Erased || ev.Content.Encryption.ErasedAt == "" {
		t.Fatalf("the erased marker is %+v, want Erased with a date", ev.Content.Encryption)
	}

	// A reader holding no keystore says nothing rather than claiming erasure.
	var absent *ContentKeystore
	other := &Event{Content: &Content{Encryption: &ContentEncryption{KeyID: id}}}
	if absent.MarkErased(other) {
		t.Error("a nil keystore claimed a record was erased")
	}
	if got := absent.State(id); got != ContentKeyUnknown {
		t.Errorf("a nil keystore reports %q for a key it cannot see, want %q", got, ContentKeyUnknown)
	}
}

// Erased content must never render as absent content: the two mean different
// things to anyone reading a transcript.
func TestErasedContentRendersAsErasedAndNotAsEmpty(t *testing.T) {
	erased := &ContentEncryption{
		Algorithm: ContentKeyAlgorithm,
		KeyID:     "abc123",
		Erased:    true,
		ErasedAt:  "2026-07-24T09:00:00Z",
	}
	for name, got := range map[string]string{
		"Describe":    erased.Describe(),
		"Placeholder": erased.Placeholder(),
	} {
		if got == "" {
			t.Fatalf("%s renders erased content as nothing at all", name)
		}
		if !strings.Contains(got, "2026-07-24T09:00:00Z") {
			t.Errorf("%s = %q, which does not say when the content was erased", name, got)
		}
		if !strings.Contains(got, "erased") {
			t.Errorf("%s = %q, which does not say the content was erased", name, got)
		}
	}

	live := &ContentEncryption{Algorithm: ContentKeyAlgorithm, KeyID: "abc123"}
	if got := live.Placeholder(); got != "" {
		t.Errorf("Placeholder on a readable record = %q, want nothing", got)
	}
	if got := live.Describe(); strings.Contains(got, "erased") {
		t.Errorf("Describe on a readable record = %q, which calls it erased", got)
	}

	if !strings.Contains(ErasedDigestCaveat, "re-proven") {
		t.Error("the digest caveat does not say that the digest can no longer be re-proven")
	}
}

// A wrong key must fail rather than produce something that looks like a
// transcript. Rubbish rendered as a prompt would be evidence of something
// nobody ever said.
func TestSealedContentFailsClosedOnAWrongKeyOrTamper(t *testing.T) {
	key := randomKey(t)
	other := randomKey(t)
	const aad = "flugschreiber-test\x00r-1\x00input"

	sealed, err := SealContent(key, aad, []byte("the patient's name is Alice"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "Alice") {
		t.Fatal("the ciphertext contains the plaintext")
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Alice")) {
		t.Fatal("the decoded ciphertext contains the plaintext")
	}

	back, err := OpenContent(key, aad, sealed)
	if err != nil {
		t.Fatalf("the right key did not open the ciphertext: %v", err)
	}
	if string(back) != "the patient's name is Alice" {
		t.Fatalf("round trip returned %q", back)
	}

	if _, err := OpenContent(other, aad, sealed); err == nil {
		t.Error("a wrong key opened the ciphertext")
	}
	if _, err := OpenContent(key, "flugschreiber-test\x00r-2\x00input", sealed); err == nil {
		t.Error("ciphertext from one record opened as another record")
	}
	if _, err := OpenContent(key, "flugschreiber-test\x00r-1\x00output", sealed); err == nil {
		t.Error("sealed input opened as output")
	}
	if _, err := OpenContent(key[:16], aad, sealed); err == nil {
		t.Error("a key of the wrong length was accepted")
	}

	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)-1] ^= 0x01
	if _, err := OpenContent(key, aad, base64.StdEncoding.EncodeToString(flipped)); err == nil {
		t.Error("a flipped bit in the ciphertext still opened")
	}
}

// A keystore whose master key has been swapped can decrypt nothing it wrapped.
// It says so rather than reporting every key as erased, which would be an
// erasure nobody ordered.
func TestKeystoreRefusesASwappedMasterKey(t *testing.T) {
	ks := newTestKeystore(t)
	if _, _, err := ks.KeyFor("s-1", "r-1"); err != nil {
		t.Fatal(err)
	}

	var f map[string]any
	raw, err := os.ReadFile(ks.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f["master_key"] = base64.StdEncoding.EncodeToString(randomKey(t))
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ks.Path(), body, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = OpenContentKeystore(ks.Path())
	if err == nil {
		t.Fatal("a keystore with a swapped master key opened without complaint")
	}
	if !strings.Contains(err.Error(), "master key") {
		t.Errorf("the refusal does not name the master key: %v", err)
	}
}

// The same swap, done consistently enough to pass the id check, must still fail
// at the point of unwrapping rather than return a key that decrypts nothing.
func TestASwappedMasterKeyUnwrapsNothing(t *testing.T) {
	dir := t.TempDir()
	ks, err := OpenContentKeystore(ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	_, id, err := ks.KeyFor("s-1", "r-1")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(ks.Path())
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	replacement := randomKey(t)
	f["master_key"] = base64.StdEncoding.EncodeToString(replacement)
	f["master_key_id"] = masterKeyID(replacement)
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ks.Path(), body, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenContentKeystore(ks.Path())
	if err != nil {
		t.Fatalf("a consistently swapped keystore should open and then fail to unwrap: %v", err)
	}
	if _, err := reopened.Key(id); err == nil {
		t.Fatal("a key wrapped under a different master key unwrapped anyway")
	}
}

func TestKeystoreIsNotReadableByGroupOrOther(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Go synthesises permission bits on Windows")
	}
	ks := newTestKeystore(t)
	if _, _, err := ks.KeyFor("s-1", "r-1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ks.Path())
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("keystore mode is %04o; anyone who can read it can read every stored prompt", mode)
	}

	if err := os.Chmod(ks.Path(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContentKeystore(ks.Path()); err == nil {
		t.Error("a world-readable keystore opened without complaint")
	}
}

// The keystore is a separate file from the chain. An erasure must not touch a
// segment, a checkpoint or the prune anchor, because that is the property the
// whole design rests on.
func TestErasureTouchesNoChainFile(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&Event{EventType: EventInference, RequestID: "r-1", SessionID: "s-1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	before := snapshotDir(t, dir)

	ks, err := OpenContentKeystore(ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ks.KeyFor("s-1", "r-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Erase(ContentErasureRequest{SessionID: "s-1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}

	for name, sum := range before {
		now, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s disappeared during an erasure: %v", name, err)
		}
		if string(now) != sum {
			t.Errorf("%s changed during an erasure; the chain must never be rewritten to erase content", name)
		}
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("the chain no longer verifies after an erasure: %+v", res.Problems)
	}
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(body)
	}
	return out
}

// wrappedKeyOnDisk returns the wrapped material for one key, from wherever it
// currently sits. A key that has not been folded in yet is in the journal, and
// for the purpose of "did the material really leave the disk" the two files are
// one store.
func wrappedKeyOnDisk(t *testing.T, path, keyID string) string {
	t.Helper()
	if raw, err := os.ReadFile(path); err == nil {
		var f contentKeystoreFile
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		if entry, ok := f.Keys[keyID]; ok && entry.Wrapped != "" {
			return entry.Wrapped
		}
	}
	journal, err := readJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range journal {
		if e.KeyID == keyID && e.Wrapped != "" {
			return e.Wrapped
		}
	}
	t.Fatalf("key %s is in neither %s nor %s", keyID, path, ContentJournalFile)
	return ""
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, contentKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	return key
}

func pendingIDs(res *ContentErasureResult) []string {
	out := make([]string, 0, len(res.Pending))
	for _, t := range res.Pending {
		out = append(out, t.KeyID)
	}
	return out
}

// masterKeyMaterialForTest reaches into the keystore so that a test can assert
// the master key never appears anywhere it is not supposed to.
func (k *ContentKeystore) masterKeyMaterialForTest() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return base64.StdEncoding.EncodeToString(k.master)
}
