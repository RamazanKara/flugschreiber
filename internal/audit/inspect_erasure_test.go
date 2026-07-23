package audit

import (
	"os"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/content"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// writeEncryptedSession records one sealed interaction and returns the
// directory it lives in.
func writeEncryptedSession(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	keys, err := evidence.OpenContentKeystore(evidence.ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	enc := content.NewEncryptor(keys)

	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ev := &evidence.Event{
		EventType: evidence.EventInference,
		RequestID: "req-erasable",
		SessionID: "sess-erasable",
		Endpoint:  "/v1/chat/completions",
		Status:    200,
		Content: &evidence.Content{
			Mode:   evidence.ModeStore,
			Input:  &evidence.Payload{SHA256: strings.Repeat("aa", 32), Bytes: 41, Text: "the prompt that must go away"},
			Output: &evidence.Payload{SHA256: strings.Repeat("bb", 32), Bytes: 22, Text: "the answer it produced"},
		},
	}
	if err := enc.EncryptEvent(ev); err != nil {
		t.Fatalf("EncryptEvent: %v", err)
	}
	if err := store.Append(ev); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A reader holding the keystore sees the text, because otherwise turning
// encryption on would make the operator's own tooling useless.
func TestReconstructOpensSealedContentWhenTheKeystoreIsThere(t *testing.T) {
	dir := writeEncryptedSession(t)

	s, err := Reconstruct(dir, Query{SessionID: "sess-erasable"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.ContentAvailable {
		t.Fatal("the session reports no readable content although the keystore is present")
	}
	if s.Erased != 0 || s.Encrypted != 0 {
		t.Errorf("Erased = %d, Encrypted = %d, want zero of each", s.Erased, s.Encrypted)
	}
	if got := s.Entries[0].Output; got != "the answer it produced" {
		t.Errorf("output = %q, want the decrypted text", got)
	}
}

// Without the keystore the content is unreadable, and the difference between
// "unreadable here" and "never captured" has to survive into the output. An
// exported bundle is exactly this case.
func TestReconstructSaysContentIsEncryptedRatherThanAbsent(t *testing.T) {
	dir := writeEncryptedSession(t)
	if err := os.Remove(evidence.ContentKeystorePath(dir)); err != nil {
		t.Fatal(err)
	}

	s, err := Reconstruct(dir, Query{SessionID: "sess-erasable"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Encrypted != 1 {
		t.Errorf("Encrypted = %d, want 1", s.Encrypted)
	}
	if s.Entries[0].ContentState != "encrypted" {
		t.Errorf("ContentState = %q, want encrypted", s.Entries[0].ContentState)
	}
	if s.Entries[0].InputHash == "" {
		t.Error("the digest was dropped, so the record no longer says which interaction it was")
	}

	var b strings.Builder
	s.Render(&b)
	out := b.String()
	if !strings.Contains(out, "encrypted content this reader cannot open") {
		t.Errorf("the rendering does not say the content is encrypted:\n%s", out)
	}
	if strings.Contains(out, "No prompt or completion text is recorded") {
		t.Error("encrypted content was rendered as if the log had captured nothing")
	}
}

// Erased content must render as erased, with the date, and never as empty.
func TestReconstructRendersErasedContentAsErased(t *testing.T) {
	dir := writeEncryptedSession(t)

	keys, err := evidence.OpenContentKeystore(evidence.ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	res, err := keys.Erase(evidence.ContentErasureRequest{
		SessionID: "sess-erasable",
		Requester: "dpo@muster.example",
		Reason:    "Article 17 request",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Destroyed) == 0 {
		t.Fatal("nothing was erased, so the rest of this test proves nothing")
	}

	s, err := Reconstruct(dir, Query{SessionID: "sess-erasable"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Erased != 1 {
		t.Fatalf("Erased = %d, want 1", s.Erased)
	}
	entry := s.Entries[0]
	if entry.ContentState != "erased" {
		t.Errorf("ContentState = %q, want erased", entry.ContentState)
	}
	if entry.ErasedAt == "" {
		t.Error("no erasure date, so a reader cannot say when the content went")
	}
	if entry.InputHash == "" || entry.OutputHash == "" {
		t.Error("the digests were dropped; they are what still ties the record to the interaction")
	}
	if strings.Contains(entry.Output, "the answer it produced") {
		t.Fatal("the erased text is still readable")
	}

	var b strings.Builder
	s.Render(&b)
	out := b.String()
	if !strings.Contains(out, "erased under a deletion request") {
		t.Errorf("the rendering does not say the content was erased:\n%s", out)
	}
	if !strings.Contains(out, "claims that can\nno longer be re-proven") {
		t.Errorf("the rendering does not say what the surviving digest is worth:\n%s", out)
	}
	if strings.Contains(out, "content not retained") {
		t.Error("erased content is rendered as if it had never been captured")
	}
	if !strings.Contains(out, "content ERASED on") {
		t.Errorf("the entry itself does not say the content was erased:\n%s", out)
	}
}
