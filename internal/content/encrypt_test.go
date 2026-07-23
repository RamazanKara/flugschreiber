package content

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func newTestEncryptor(t *testing.T) (*Encryptor, *evidence.ContentKeystore) {
	t.Helper()
	ks, err := evidence.OpenContentKeystore(evidence.ContentKeystorePath(t.TempDir()))
	if err != nil {
		t.Fatalf("open keystore: %v", err)
	}
	return NewEncryptor(ks), ks
}

func storeModeEvent() *evidence.Event {
	return &evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-1",
		SessionID: "sess-1",
		ToolCalls: []evidence.ToolCall{{
			Name:          "lookup_patient",
			Arguments:     `{"name":"Alice Schmidt"}`,
			ArgumentsHash: "aaaa",
		}},
		ToolResults: []evidence.ToolResult{{
			CallID:  "call-1",
			SHA256:  "bbbb",
			Bytes:   9,
			Content: "born 1981",
		}},
		Content: &evidence.Content{
			Mode: evidence.ModeStore,
			Input: &evidence.Payload{
				SHA256:   "1111",
				Bytes:    42,
				Messages: []evidence.Message{{Role: "user", Content: "my name is Alice Schmidt"}},
				Text:     "my name is Alice Schmidt",
			},
			Output: &evidence.Payload{
				SHA256: "2222",
				Bytes:  17,
				Text:   "Hello Alice Schmidt",
			},
		},
	}
}

// The point of the whole feature: after encryption, the bytes that go into the
// chain hold no readable text, and the digests over the wire bytes are
// untouched.
func TestEncryptEventLeavesNoPlaintextInTheRecord(t *testing.T) {
	enc, _ := newTestEncryptor(t)
	ev := storeModeEvent()

	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}

	if ev.Content.Encryption == nil {
		t.Fatal("the record is not marked as encrypted")
	}
	if ev.Content.Encryption.Algorithm != evidence.ContentKeyAlgorithm {
		t.Errorf("algorithm is %q, want %q", ev.Content.Encryption.Algorithm, evidence.ContentKeyAlgorithm)
	}
	if ev.Content.Encryption.KeyID == "" {
		t.Error("the record names no key, so nothing can ever decrypt or erase it")
	}
	if ev.Content.Encryption.Erased {
		t.Error("a freshly written record claims to be erased")
	}

	for _, p := range []*evidence.Payload{ev.Content.Input, ev.Content.Output} {
		if p.Text != "" || len(p.Messages) > 0 {
			t.Errorf("payload still holds text: %+v", p)
		}
		if p.Ciphertext == "" {
			t.Error("payload holds no ciphertext")
		}
	}
	if ev.Content.Input.SHA256 != "1111" || ev.Content.Input.Bytes != 42 {
		t.Error("encryption changed the digest of the wire bytes")
	}
	if ev.Content.Output.SHA256 != "2222" || ev.Content.Output.Bytes != 17 {
		t.Error("encryption changed the digest of the wire bytes")
	}

	// Schema version 1 has no ciphertext field for tool text, so it is dropped
	// rather than left in the clear where no erasure could reach it.
	if ev.ToolCalls[0].Arguments != "" {
		t.Error("tool call arguments were left in the clear")
	}
	if ev.ToolCalls[0].ArgumentsHash != "aaaa" {
		t.Error("the tool call digest was lost")
	}
	if ev.ToolResults[0].Content != "" {
		t.Error("tool result content was left in the clear")
	}
	if ev.ToolResults[0].SHA256 != "bbbb" || ev.ToolResults[0].Bytes != 9 {
		t.Error("the tool result digest was lost")
	}

	if strings.Contains(marshal(t, ev), "Alice Schmidt") {
		t.Fatal("the encrypted record still contains the prompt text")
	}
}

func TestEncryptedContentRoundTrips(t *testing.T) {
	enc, _ := newTestEncryptor(t)
	ev := storeModeEvent()
	want := *ev.Content.Input

	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := enc.DecryptEvent(ev); err != nil {
		t.Fatal(err)
	}

	if ev.Content.Input.Text != want.Text {
		t.Errorf("input text round tripped as %q, want %q", ev.Content.Input.Text, want.Text)
	}
	if len(ev.Content.Input.Messages) != 1 || ev.Content.Input.Messages[0].Content != want.Messages[0].Content {
		t.Errorf("input messages round tripped as %+v", ev.Content.Input.Messages)
	}
	if ev.Content.Input.Messages[0].Role != "user" {
		t.Errorf("the message role was lost: %+v", ev.Content.Input.Messages[0])
	}
	if ev.Content.Output.Text != "Hello Alice Schmidt" {
		t.Errorf("output text round tripped as %q", ev.Content.Output.Text)
	}
	if ev.Content.Input.Ciphertext != "" {
		t.Error("a decrypted payload still carries its ciphertext, so a reader would see the content twice")
	}
}

// Hash mode retains no text. Marking such a record as encrypted would claim a
// protection it does not have and would leave a key to erase for content that
// was never stored.
func TestHashModeIsNotMarkedAsEncrypted(t *testing.T) {
	enc, ks := newTestEncryptor(t)
	ev := &evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-1",
		SessionID: "sess-1",
		Content: &evidence.Content{
			Mode:   evidence.ModeHash,
			Input:  &evidence.Payload{SHA256: "1111", Bytes: 42},
			Output: &evidence.Payload{SHA256: "2222", Bytes: 17},
		},
	}

	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	if ev.Content.Encryption != nil {
		t.Error("a hash-mode record was marked as encrypted")
	}
	if len(ks.SessionsWithKeys()) != 0 {
		t.Error("a hash-mode record caused a content key to be issued")
	}
}

// Redact mode stores text, so it is encrypted like store mode, and the
// redaction counts stay readable because they are evidence about the record
// rather than content of it.
func TestRedactModeIsEncryptedAndKeepsItsCounts(t *testing.T) {
	enc, _ := newTestEncryptor(t)
	ev := &evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-1",
		Content: &evidence.Content{
			Mode: evidence.ModeRedact,
			Input: &evidence.Payload{
				SHA256:     "1111",
				Text:       "write to [REDACTED:email]",
				Redactions: map[string]int{"email": 1},
			},
		},
	}

	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	if ev.Content.Encryption == nil {
		t.Fatal("a redact-mode record was not encrypted")
	}
	if ev.Content.Input.Text != "" {
		t.Error("redacted text was left in the clear")
	}
	if ev.Content.Input.Redactions["email"] != 1 {
		t.Error("the redaction counts were lost")
	}
}

// A record with no session gets its own key, so that erasing one interaction
// does not take unrelated callers with it.
func TestRecordsAreKeyedPerSession(t *testing.T) {
	enc, _ := newTestEncryptor(t)

	first := storeModeEvent()
	second := storeModeEvent()
	second.RequestID = "req-2"
	third := storeModeEvent()
	third.RequestID = "req-3"
	third.SessionID = ""

	for _, ev := range []*evidence.Event{first, second, third} {
		if err := enc.EncryptEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	if first.Content.Encryption.KeyID != second.Content.Encryption.KeyID {
		t.Error("two records of one session were sealed under different keys")
	}
	if third.Content.Encryption.KeyID == first.Content.Encryption.KeyID {
		t.Error("a record with no session shares the key of a session")
	}
}

// An erasure destroys the key. What must not happen after that is a reader
// producing plausible text, or a reader reporting the record as empty.
func TestErasedContentCannotBeReadAndSaysSo(t *testing.T) {
	enc, ks := newTestEncryptor(t)
	ev := storeModeEvent()
	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	sealed := ev.Content.Input.Ciphertext

	if _, err := ks.Erase(evidence.ContentErasureRequest{SessionID: "sess-1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}

	err := enc.DecryptEvent(ev)
	if err == nil {
		t.Fatal("an erased record decrypted")
	}
	if !errors.Is(err, evidence.ErrContentKeyErased) {
		t.Errorf("decrypting an erased record reports %v, want ErrContentKeyErased", err)
	}
	if ev.Content.Input.Ciphertext != sealed {
		t.Error("a failed decryption changed the record")
	}
	if ev.Content.Input.Text != "" {
		t.Error("a failed decryption invented text")
	}

	if !ks.MarkErased(ev) {
		t.Fatal("the reader could not tell that the record had been erased")
	}
	if got := ev.Content.Encryption.Placeholder(); got == "" {
		t.Error("an erased record renders as nothing at all")
	}
}

// The write path must never fall back to storing plaintext. If a key cannot be
// had, the text is dropped and the failure is reported.
func TestEncryptionFailureDropsTheTextRatherThanStoringIt(t *testing.T) {
	enc := NewEncryptor(brokenKeystore{})
	ev := storeModeEvent()

	err := enc.EncryptEvent(ev)
	if err == nil {
		t.Fatal("a broken keystore did not fail the encryption")
	}
	if ev.Content.Encryption != nil {
		t.Error("the record claims to be encrypted after the encryption failed")
	}
	for _, p := range []*evidence.Payload{ev.Content.Input, ev.Content.Output} {
		if p.Text != "" || len(p.Messages) > 0 || p.Ciphertext != "" {
			t.Errorf("text survived a failed encryption: %+v", p)
		}
	}
	if ev.ToolCalls[0].Arguments != "" || ev.ToolResults[0].Content != "" {
		t.Error("tool text survived a failed encryption")
	}
	if ev.Content.Input.SHA256 != "1111" {
		t.Error("a failed encryption destroyed the digest as well as the text")
	}
	if strings.Contains(marshal(t, ev), "Alice Schmidt") {
		t.Fatal("the record that would have been appended still contains the prompt")
	}
}

// A record that captured no text has nothing to seal. Issuing a key for it
// would mark it as encrypted under a key that covers nothing, so that an
// erasure naming that key would report destroying content that was never
// stored, and on traffic without a session id it would cost one keystore entry
// per contentless request.
func TestARecordThatCapturedNoTextGetsNoKey(t *testing.T) {
	enc, ks := newTestEncryptor(t)
	ev := &evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-empty",
		Status:    400,
		ToolCalls: []evidence.ToolCall{{Name: "lookup_patient", Arguments: `{"name":"Alice Schmidt"}`, ArgumentsHash: "aaaa"}},
		Content: &evidence.Content{
			Mode:   evidence.ModeStore,
			Input:  &evidence.Payload{SHA256: "1111", Bytes: 0},
			Output: &evidence.Payload{SHA256: "2222", Bytes: 0},
		},
	}

	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	if ev.Content.Encryption != nil {
		t.Errorf("a record with no captured text was marked as encrypted under key %s, which seals nothing",
			ev.Content.Encryption.KeyID)
	}
	if n := keysOnDisk(t, ks.Path()); n != 0 {
		t.Errorf("the keystore holds %d key(s) for a record that had nothing to seal", n)
	}
	if ev.Content.Input.SHA256 != "1111" || ev.Content.Output.SHA256 != "2222" {
		t.Error("the digests were lost")
	}
	// Tool text still goes: it cannot be sealed in schema version 1, so leaving
	// it would put content in the log that no erasure reaches.
	if ev.ToolCalls[0].Arguments != "" {
		t.Error("tool call arguments were left in the clear")
	}
	if ev.ToolCalls[0].ArgumentsHash != "aaaa" {
		t.Error("the tool call digest was lost")
	}
}

// The proxy encrypts from one goroutine per request. A keystore that raced
// would either hand two sessions one key or lose one to a torn write, and the
// second is a record nobody can ever read again.
func TestEncryptEventIsSafeForConcurrentRequests(t *testing.T) {
	enc, ks := newTestEncryptor(t)
	const sessions, perSession = 4, 8

	var wg sync.WaitGroup
	fail := make(chan error, sessions*perSession)
	for s := 0; s < sessions; s++ {
		for i := 0; i < perSession; i++ {
			wg.Add(1)
			go func(session, request int) {
				defer wg.Done()
				ev := storeModeEvent()
				ev.SessionID = fmt.Sprintf("sess-%d", session)
				ev.RequestID = fmt.Sprintf("req-%d-%d", session, request)
				if err := enc.EncryptEvent(ev); err != nil {
					fail <- err
					return
				}
				if err := enc.DecryptEvent(ev); err != nil {
					fail <- err
					return
				}
				if ev.Content.Input.Text != "my name is Alice Schmidt" {
					fail <- fmt.Errorf("%s round tripped to %q", ev.RequestID, ev.Content.Input.Text)
				}
			}(s, i)
		}
	}
	wg.Wait()
	close(fail)
	for err := range fail {
		t.Error(err)
	}

	if got := len(ks.SessionsWithKeys()); got != sessions {
		t.Errorf("%d concurrent sessions produced %d keys, want %d", sessions, got, sessions)
	}
	// The keystore on disk is what the next process reads. A save that lost a
	// key under concurrency would leave records nothing can open.
	reopened, err := evidence.OpenContentKeystore(ks.Path())
	if err != nil {
		t.Fatalf("the keystore written under concurrency does not reopen: %v", err)
	}
	if got := len(reopened.SessionsWithKeys()); got != sessions {
		t.Errorf("the keystore on disk holds keys for %d sessions, want %d", got, sessions)
	}
}

// Encrypting a record twice would orphan the first ciphertext and lose the
// text with it, so it is refused rather than silently done.
func TestEncryptingTwiceIsRefused(t *testing.T) {
	enc, _ := newTestEncryptor(t)
	ev := storeModeEvent()
	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := enc.EncryptEvent(ev); err == nil {
		t.Error("a record was encrypted a second time")
	}
}

// Ciphertext is bound to the record and the field it came from, so a log with
// a swapped payload fails to open rather than attributing one caller's prompt
// to another.
func TestCiphertextIsBoundToItsRecordAndField(t *testing.T) {
	enc, _ := newTestEncryptor(t)
	first := storeModeEvent()
	second := storeModeEvent()
	second.RequestID = "req-2"
	second.Content.Input.Text = "something else entirely"
	second.Content.Input.Messages = nil

	if err := enc.EncryptEvent(first); err != nil {
		t.Fatal(err)
	}
	if err := enc.EncryptEvent(second); err != nil {
		t.Fatal(err)
	}

	moved := storeModeEvent()
	moved.RequestID = second.RequestID
	moved.Content = &evidence.Content{
		Mode:       evidence.ModeStore,
		Encryption: second.Content.Encryption,
		Input:      &evidence.Payload{SHA256: "1111", Ciphertext: first.Content.Input.Ciphertext},
	}
	if err := enc.DecryptEvent(moved); err == nil {
		t.Error("the sealed input of one record opened as another record")
	}

	swapped := storeModeEvent()
	swapped.RequestID = first.RequestID
	swapped.Content = &evidence.Content{
		Mode:       evidence.ModeStore,
		Encryption: first.Content.Encryption,
		Output:     &evidence.Payload{SHA256: "2222", Ciphertext: first.Content.Input.Ciphertext},
	}
	if err := enc.DecryptEvent(swapped); err == nil {
		t.Error("a sealed input opened as the output of the same record")
	}
}

func TestDecryptingAnUnencryptedRecordDoesNothing(t *testing.T) {
	enc, _ := newTestEncryptor(t)
	ev := storeModeEvent()
	if err := enc.DecryptEvent(ev); err != nil {
		t.Fatalf("decrypting a plaintext record failed: %v", err)
	}
	if ev.Content.Input.Text != "my name is Alice Schmidt" {
		t.Error("decrypting a plaintext record changed it")
	}
}

// brokenKeystore is a keystore that cannot issue a key, which is what a full
// disk or a keystore on a read-only mount looks like from here.
type brokenKeystore struct{}

func (brokenKeystore) KeyFor(string, string) ([]byte, string, error) {
	return nil, "", errors.New("keystore is unavailable")
}

func (brokenKeystore) Key(string) ([]byte, error) {
	return nil, errors.New("keystore is unavailable")
}

// keysOnDisk counts the live keys in a keystore file. The keystore hands out no
// count of its own, and the file is what the next process reads.
func keysOnDisk(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return len(f.Keys)
}

// marshal renders an event the way the store would write it, which is the only
// representation that matters when asking whether plaintext survived.
func marshal(t *testing.T, v any) string {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
