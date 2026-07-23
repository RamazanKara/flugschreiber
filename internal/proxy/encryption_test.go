package proxy

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

const secretPrompt = "my national insurance number is QQ123456C"

func encryptingHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, mockHandler(), func(c *config.Config) {
		c.ContentMode = evidence.ModeStore
		c.ContentEncryption = true
	})
}

func recordAPrompt(h *harness) {
	body := fmt.Sprintf(`{"model":"mock-model","messages":[{"role":"user","content":%q}]}`, secretPrompt)
	h.postAndDrain("/v1/chat/completions", body, map[string]string{"X-Flugschreiber-Session": "sess-erase-me"})
}

// segmentBytes reads the evidence files as bytes. Asserting on the parsed
// record would pass while the plaintext sat in a field the assertion did not
// look at, and the claim being made here is about the file.
func segmentBytes(t *testing.T, dir string) string {
	t.Helper()
	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, s := range segs {
		raw, readErr := os.ReadFile(s.Path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		b.Write(raw)
	}
	if b.Len() == 0 {
		t.Fatal("no evidence was written")
	}
	return b.String()
}

func lastInference(t *testing.T, events []evidence.Event) *evidence.Event {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].EventType == evidence.EventInference {
			return &events[i]
		}
	}
	t.Fatal("no inference record was written")
	return nil
}

// The point of encrypting on the write path is that the prompt is not in the
// file.
func TestStoreModeWithEncryptionLeavesNoPlaintextOnDisk(t *testing.T) {
	h := encryptingHarness(t)
	recordAPrompt(h)
	events := h.events()

	if raw := segmentBytes(t, h.dataDir); strings.Contains(raw, "QQ123456C") {
		t.Error("the prompt is in the evidence file in plain text although content encryption is on")
	}

	ev := lastInference(t, events)
	if ev.Content == nil || ev.Content.Encryption == nil {
		t.Fatal("the record does not say it is encrypted, so no reader would know to decrypt it")
	}
	if ev.Content.Encryption.Algorithm != evidence.ContentKeyAlgorithm {
		t.Errorf("algorithm = %q, want %q", ev.Content.Encryption.Algorithm, evidence.ContentKeyAlgorithm)
	}
	if ev.Content.Encryption.KeyID == "" {
		t.Error("the record names no key, so the content could never be opened again")
	}
	if ev.Content.Input == nil || ev.Content.Input.Ciphertext == "" {
		t.Fatal("the input carries no ciphertext")
	}
	if ev.Content.Input.Text != "" || len(ev.Content.Input.Messages) > 0 {
		t.Error("the input still carries readable text alongside the ciphertext")
	}
	// The digest is what ties the record to the wire bytes, and encryption must
	// not touch it. Otherwise an encrypted record would prove less than an
	// unencrypted one, which would be a reason not to turn this on.
	if ev.Content.Input.SHA256 == "" || ev.Content.Input.Bytes == 0 {
		t.Error("the digest or byte count was lost, so the record no longer attests to the wire bytes")
	}
}

// Without encryption the same prompt is on disk, which is what makes the test
// above a statement about the feature rather than about the fixture.
func TestStoreModeWithoutEncryptionDoesKeepThePlaintext(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) { c.ContentMode = evidence.ModeStore })
	recordAPrompt(h)
	h.events()

	if raw := segmentBytes(t, h.dataDir); !strings.Contains(raw, "QQ123456C") {
		t.Fatal("store mode did not keep the prompt, so the encryption test proves nothing")
	}
}

// Erasure destroys the key and never the record. The chain has to keep
// verifying afterwards, byte for byte, or the feature would have traded one
// legal problem for a worse one.
func TestErasureLeavesTheChainVerifiable(t *testing.T) {
	h := encryptingHarness(t)
	recordAPrompt(h)
	events := h.events()
	dir := h.dataDir

	before, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !before.OK() {
		t.Fatalf("the log did not verify before the erasure: %v", before.Problems)
	}

	keys, err := evidence.OpenContentKeystore(evidence.ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	res, err := keys.Erase(evidence.ContentErasureRequest{
		SessionID: "sess-erase-me",
		Requester: "dpo@muster.example",
		Reason:    "Article 17 request",
	})
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if len(res.Destroyed) == 0 {
		t.Fatal("Erase reported destroying nothing")
	}

	after, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !after.OK() {
		t.Fatalf("erasing content damaged the chain: %v", after.Problems)
	}
	if after.Records != before.Records {
		t.Errorf("records went from %d to %d: erasure deleted evidence", before.Records, after.Records)
	}
	if after.HeadHash != before.HeadHash {
		t.Error("the chain head changed, so a record was rewritten")
	}

	ev := lastInference(t, events)
	if !keys.MarkErased(ev) {
		t.Fatal("a reader is not told the content was erased")
	}
	if ev.Content.Encryption.ErasedAt == "" {
		t.Error("the erased state carries no date, so a reader cannot say when it happened")
	}
	if _, err := keys.Key(ev.Content.Encryption.KeyID); err == nil {
		t.Error("the key still opens after an erasure, so nothing was actually destroyed")
	}
}
