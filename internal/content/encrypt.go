package content

import (
	"encoding/json"
	"fmt"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// contentAADDomain separates a sealed payload from every other use of AES-GCM
// in this project, including the keystore's own key wrapping.
const contentAADDomain = "flugschreiber-content-v1"

// Field labels that go into the additional authenticated data, so that the
// sealed input of a record cannot be opened as its output.
const (
	fieldInput  = "input"
	fieldOutput = "output"
)

// Keystore is what an Encryptor needs from the content keystore. It is
// declared here, and satisfied by *evidence.ContentKeystore, so that the
// package which decides what gets encrypted does not also decide where key
// material lives.
type Keystore interface {
	// KeyFor returns the key a record should be sealed under, and the id that
	// goes into the record so a reader can find the key again.
	KeyFor(sessionID, requestID string) (key []byte, keyID string, err error)

	// Key returns a key by id, or evidence.ErrContentKeyErased once an
	// erasure has destroyed it.
	Key(keyID string) ([]byte, error)
}

// Encryptor seals the text-bearing fields of an evidence record before it is
// appended, so that an Article 17 erasure can destroy a key instead of a
// record.
//
// It runs after capture and before the append, which is the only place it can
// run: the chain hashes the event as written, so the ciphertext has to be in
// the bytes that get hashed. Nothing after the append ever rewrites a record.
type Encryptor struct {
	keys Keystore
}

// NewEncryptor returns an Encryptor over a keystore.
func NewEncryptor(keys Keystore) *Encryptor {
	return &Encryptor{keys: keys}
}

// EncryptEvent replaces the stored text of ev with ciphertext and marks the
// record with the key id that will open it.
//
// It fails closed. If a key cannot be obtained or a payload cannot be sealed,
// the text is removed from the event anyway and the error is returned, so a
// caller that logs the failure and appends the record regardless can never
// leave plaintext in a log that the operator has configured to encrypt. The
// digests and byte counts are untouched in every case: they are computed over
// the wire bytes and are what still ties the record to the interaction.
//
// Tool call arguments and tool results are dropped rather than sealed. Schema
// version 1 gives them no ciphertext field, and leaving them in the clear
// would mean an erasure that destroys the prompt and leaves the arguments the
// model was called with, which is not an erasure. Their digests stay.
func (e *Encryptor) EncryptEvent(ev *evidence.Event) error {
	if ev == nil || ev.Content == nil {
		return nil
	}
	if ev.Content.Mode == evidence.ModeHash {
		// Hash mode retains no text, so there is nothing to encrypt and no
		// key to erase later. Marking the record as encrypted would claim a
		// protection it does not have.
		return nil
	}
	if ev.Content.Encryption != nil {
		return fmt.Errorf("content: record %s is already marked as encrypted under key %s", ev.RequestID, ev.Content.Encryption.KeyID)
	}

	// Tool text goes first, and goes whatever happens next, because it cannot
	// be sealed and must not survive a failure further down either.
	dropToolText(ev)

	if !holdsText(ev.Content) {
		// A record that captured no text has nothing to seal. Naming a key on
		// it would claim an encryption that covers nothing, and would leave a
		// key in the keystore whose destruction erases nothing: on traffic
		// without a session id that is one key, and one keystore rewrite, per
		// request that carried no content at all.
		return nil
	}

	key, keyID, err := e.keys.KeyFor(ev.SessionID, ev.RequestID)
	if err != nil {
		stripText(ev)
		return fmt.Errorf("content: no content key for request %s, its text was dropped rather than stored in the clear: %w", ev.RequestID, err)
	}

	if err := sealPayload(ev.Content.Input, key, keyID, ev.RequestID, fieldInput); err != nil {
		stripText(ev)
		return err
	}
	if err := sealPayload(ev.Content.Output, key, keyID, ev.RequestID, fieldOutput); err != nil {
		stripText(ev)
		return err
	}

	ev.Content.Encryption = &evidence.ContentEncryption{
		Algorithm: evidence.ContentKeyAlgorithm,
		KeyID:     keyID,
	}
	return nil
}

// DecryptEvent restores the text of a record that was read back from the log,
// for a reader that holds the keystore.
//
// It changes nothing on disk. When the key has been erased it returns an error
// wrapping evidence.ErrContentKeyErased and leaves the ciphertext in place, so
// the caller renders the record as erased rather than as empty.
func (e *Encryptor) DecryptEvent(ev *evidence.Event) error {
	if ev == nil || ev.Content == nil || ev.Content.Encryption == nil {
		return nil
	}
	enc := ev.Content.Encryption
	if enc.Algorithm != evidence.ContentKeyAlgorithm {
		return fmt.Errorf("content: record %s is sealed with %q, this build implements %q", ev.RequestID, enc.Algorithm, evidence.ContentKeyAlgorithm)
	}

	key, err := e.keys.Key(enc.KeyID)
	if err != nil {
		return fmt.Errorf("content: record %s: %w", ev.RequestID, err)
	}
	if err := openPayload(ev.Content.Input, key, enc.KeyID, ev.RequestID, fieldInput); err != nil {
		return err
	}
	return openPayload(ev.Content.Output, key, enc.KeyID, ev.RequestID, fieldOutput)
}

// sealedPayload is the plaintext that goes inside Payload.Ciphertext. Both
// text-bearing fields travel together so that one key and one nonce cover the
// whole of one side of an interaction, and so that decryption restores exactly
// what was captured.
type sealedPayload struct {
	Text     string             `json:"text,omitempty"`
	Messages []evidence.Message `json:"messages,omitempty"`
}

func sealPayload(p *evidence.Payload, key []byte, keyID, requestID, field string) error {
	if p == nil {
		return nil
	}
	if p.Text == "" && len(p.Messages) == 0 {
		return nil
	}
	plain, err := json.Marshal(sealedPayload{Text: p.Text, Messages: p.Messages})
	if err != nil {
		return fmt.Errorf("content: marshal %s of request %s for encryption: %w", field, requestID, err)
	}
	sealed, err := evidence.SealContent(key, payloadAAD(keyID, requestID, field), plain)
	if err != nil {
		return fmt.Errorf("content: seal %s of request %s: %w", field, requestID, err)
	}
	p.Ciphertext = sealed
	p.Text = ""
	p.Messages = nil
	return nil
}

func openPayload(p *evidence.Payload, key []byte, keyID, requestID, field string) error {
	if p == nil || p.Ciphertext == "" {
		return nil
	}
	plain, err := evidence.OpenContent(key, payloadAAD(keyID, requestID, field), p.Ciphertext)
	if err != nil {
		return fmt.Errorf("content: open %s of request %s: %w", field, requestID, err)
	}
	var out sealedPayload
	if err := json.Unmarshal(plain, &out); err != nil {
		return fmt.Errorf("content: decoded %s of request %s is not a sealed payload: %w", field, requestID, err)
	}
	p.Text = out.Text
	p.Messages = out.Messages
	p.Ciphertext = ""
	return nil
}

// payloadAAD binds a sealed payload to the key, the record and the side of the
// interaction it came from. Moving a ciphertext to another record or another
// field then fails the GCM tag instead of decrypting somewhere it does not
// belong, which matters because the chain would happily attest to a record
// somebody had assembled that way before it was written.
func payloadAAD(keyID, requestID, field string) string {
	return contentAADDomain + "\x00" + keyID + "\x00" + requestID + "\x00" + field
}

// holdsText reports whether either side of an interaction carries anything a
// key would be issued for.
func holdsText(c *evidence.Content) bool {
	for _, p := range []*evidence.Payload{c.Input, c.Output} {
		if p != nil && (p.Text != "" || len(p.Messages) > 0) {
			return true
		}
	}
	return false
}

// stripText removes every text-bearing field of an event. It is the fail-closed
// path: a record that could not be encrypted keeps its digests and loses its
// text, because storing the text unencrypted would put content in the log that
// no erasure can reach.
func stripText(ev *evidence.Event) {
	if ev == nil || ev.Content == nil {
		return
	}
	for _, p := range []*evidence.Payload{ev.Content.Input, ev.Content.Output} {
		if p == nil {
			continue
		}
		p.Text = ""
		p.Messages = nil
		p.Ciphertext = ""
	}
	dropToolText(ev)
}

func dropToolText(ev *evidence.Event) {
	for i := range ev.ToolCalls {
		ev.ToolCalls[i].Arguments = ""
	}
	for i := range ev.ToolResults {
		ev.ToolResults[i].Content = ""
	}
}
