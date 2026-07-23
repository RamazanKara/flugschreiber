package content

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestDefaultModeIsHash(t *testing.T) {
	// Changing this default changes what a deployment retains about its users
	// by accident rather than by decision, so it is pinned by a test.
	if DefaultMode != evidence.ModeHash {
		t.Errorf("DefaultMode = %q, want hash for data minimisation", DefaultMode)
	}
}

func TestPayloadDigestCoversWireBytesInEveryMode(t *testing.T) {
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`)
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])

	red, err := NewRedactor(DefaultPatternNames)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{evidence.ModeHash, evidence.ModeStore, evidence.ModeRedact} {
		c := &Capturer{Mode: mode, Redactor: red}
		got := c.Payload(raw, "hello", nil)
		if got.SHA256 != want {
			t.Errorf("mode %s: SHA256 = %s, want %s", mode, got.SHA256, want)
		}
		if got.Bytes != len(raw) {
			t.Errorf("mode %s: Bytes = %d, want %d", mode, got.Bytes, len(raw))
		}
	}
}

func TestHashModeDropsTextAndMessages(t *testing.T) {
	c := &Capturer{Mode: evidence.ModeHash}
	got := c.Payload([]byte("raw"), "sensitive text", []evidence.Message{{Role: "user", Content: "also sensitive"}})

	if got.Text != "" {
		t.Errorf("Text = %q, want empty", got.Text)
	}
	if len(got.Messages) != 0 {
		t.Errorf("Messages = %+v, want none", got.Messages)
	}
}

func TestRedactorReplacesAndCounts(t *testing.T) {
	r, err := NewRedactor([]string{"email", "iban"})
	if err != nil {
		t.Fatal(err)
	}

	in := "mail a@b.com or c@d.org, IBAN DE89 3704 0044 0532 0130 00"
	out, counts := r.Apply(in)

	if strings.Contains(out, "@b.com") || strings.Contains(out, "@d.org") {
		t.Errorf("emails survived: %q", out)
	}
	if strings.Contains(out, "3704") {
		t.Errorf("IBAN survived: %q", out)
	}
	if counts["email"] != 2 {
		t.Errorf("email count = %d, want 2", counts["email"])
	}
	if counts["iban"] != 1 {
		t.Errorf("iban count = %d, want 1", counts["iban"])
	}
}

func TestRedactorAcceptsCustomPatterns(t *testing.T) {
	r, err := NewRedactor([]string{`case_id=CASE-\d{6}`})
	if err != nil {
		t.Fatal(err)
	}
	out, counts := r.Apply("see CASE-004411 for details")
	if !strings.Contains(out, "[REDACTED:case_id]") {
		t.Errorf("custom pattern did not apply: %q", out)
	}
	if counts["case_id"] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

func TestRedactorRejectsUnknownPatternName(t *testing.T) {
	if _, err := NewRedactor([]string{"not-a-real-pattern"}); err == nil {
		t.Fatal("expected an error for an unknown pattern name")
	}
}

func TestRedactModeAppliesToMessagesAndAggregatesCounts(t *testing.T) {
	r, err := NewRedactor([]string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	c := &Capturer{Mode: evidence.ModeRedact, Redactor: r}

	got := c.Payload([]byte("raw"), "reply to x@y.com", []evidence.Message{
		{Role: "user", Content: "my address is a@b.com"},
		{Role: "user", Content: "and also c@d.com"},
	})

	if got.Redactions["email"] != 3 {
		t.Errorf("Redactions = %v, want three hits across text and messages", got.Redactions)
	}
	for _, m := range got.Messages {
		if strings.Contains(m.Content, "@") {
			t.Errorf("message not redacted: %q", m.Content)
		}
	}
}

func TestPayloadTruncatesOversizedTextButKeepsFullDigest(t *testing.T) {
	huge := strings.Repeat("x", MaxTextBytes+5000)
	raw := []byte(huge)
	c := &Capturer{Mode: evidence.ModeStore}

	got := c.Payload(raw, huge, nil)
	if !got.Truncated {
		t.Error("Truncated = false for oversized text")
	}
	if len(got.Text) != MaxTextBytes {
		t.Errorf("len(Text) = %d, want %d", len(got.Text), MaxTextBytes)
	}
	sum := sha256.Sum256(raw)
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("truncation changed the digest; the digest must cover the complete bytes")
	}
	if got.Bytes != len(raw) {
		t.Errorf("Bytes = %d, want the full length %d", got.Bytes, len(raw))
	}
}

func TestToolArgumentsFollowContentMode(t *testing.T) {
	const args = `{"iban":"DE89370400440532013000"}`
	r, _ := NewRedactor([]string{"iban"})

	cases := map[string]func(text string) bool{
		evidence.ModeHash:  func(text string) bool { return text == "" },
		evidence.ModeStore: func(text string) bool { return text == args },
		evidence.ModeRedact: func(text string) bool {
			return strings.Contains(text, "[REDACTED:iban]") && !strings.Contains(text, "DE89")
		},
	}
	for mode, ok := range cases {
		c := &Capturer{Mode: mode, Redactor: r}
		text, digest := c.ToolArguments(args)
		if !ok(text) {
			t.Errorf("mode %s: arguments = %q", mode, text)
		}
		if len(digest) != 64 {
			t.Errorf("mode %s: digest = %q, want a SHA-256 in every mode", mode, digest)
		}
	}
}

func TestToolResultPayloadFollowsContentMode(t *testing.T) {
	const result = `{"account":"a@b.com","balance":4711}`
	sum := sha256.Sum256([]byte(result))
	wantDigest := hex.EncodeToString(sum[:])
	r, _ := NewRedactor([]string{"email"})

	textOK := map[string]func(string) bool{
		evidence.ModeHash:  func(text string) bool { return text == "" },
		evidence.ModeStore: func(text string) bool { return text == result },
		evidence.ModeRedact: func(text string) bool {
			return strings.Contains(text, "[REDACTED:email]") && !strings.Contains(text, "a@b.com")
		},
	}
	for mode, ok := range textOK {
		c := &Capturer{Mode: mode, Redactor: r}
		got := c.ToolResultPayload("call_9", result)

		if got.CallID != "call_9" {
			t.Errorf("mode %s: CallID = %q, want call_9", mode, got.CallID)
		}
		if got.SHA256 != wantDigest {
			t.Errorf("mode %s: SHA256 = %q, want the content digest in every mode", mode, got.SHA256)
		}
		if got.Bytes != len(result) {
			t.Errorf("mode %s: Bytes = %d, want %d in every mode", mode, got.Bytes, len(result))
		}
		if !ok(got.Content) {
			t.Errorf("mode %s: Content = %q", mode, got.Content)
		}
	}
}

func TestClientHashIsSaltedAndTruncated(t *testing.T) {
	const credential = "Bearer sk-secret"
	a := ClientHash([]byte("salt-one"), credential)
	b := ClientHash([]byte("salt-two"), credential)

	if a == b {
		t.Error("the same credential hashed identically under two different salts")
	}
	if a != ClientHash([]byte("salt-one"), credential) {
		t.Error("ClientHash is not deterministic for a given salt")
	}
	if len(a) != 32 {
		t.Errorf("len = %d, want 32 hex characters", len(a))
	}
	if strings.Contains(a, "secret") {
		t.Error("the credential leaked into the hash")
	}
	if ClientHash([]byte("salt"), "") != "" {
		t.Error("an absent credential should yield an empty identifier, not a hash of nothing")
	}
}

func TestValidMode(t *testing.T) {
	for _, m := range []string{evidence.ModeStore, evidence.ModeHash, evidence.ModeRedact} {
		if !ValidMode(m) {
			t.Errorf("ValidMode(%q) = false", m)
		}
	}
	for _, m := range []string{"", "full", "none", "HASH"} {
		if ValidMode(m) {
			t.Errorf("ValidMode(%q) = true", m)
		}
	}
}
