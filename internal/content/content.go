// Package content implements the three capture fidelities Flugschreiber
// supports, and the identity hashing used to attribute traffic to a caller
// without retaining the caller's credential.
package content

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/flugschreiber/flugschreiber/internal/evidence"
)

// DefaultMode is hash: integrity evidence for every interaction, no prompt or
// completion text at rest. Storing model inputs and outputs by default would
// make every deployment of this proxy a new copy of whatever personal data
// users type into a chat box, which is the opposite of GDPR Article 5(1)(c)
// data minimisation. Operators who need transcripts opt in explicitly.
const DefaultMode = evidence.ModeHash

// MaxTextBytes bounds any single stored transcript. Beyond this the text is
// truncated and flagged; the SHA-256 still covers the complete wire bytes, so
// truncation never weakens the integrity evidence.
const MaxTextBytes = 256 << 10

// ValidMode reports whether m is a supported content mode.
func ValidMode(m string) bool {
	switch m {
	case evidence.ModeStore, evidence.ModeHash, evidence.ModeRedact:
		return true
	}
	return false
}

// Redactor rewrites text before it is stored, replacing matches with a labelled
// placeholder and counting what it replaced. It is only consulted in redact
// mode.
type Redactor struct {
	patterns []namedPattern
}

type namedPattern struct {
	name string
	re   *regexp.Regexp
}

// BuiltinPatterns are the redaction rules available by name. They are
// deliberately conservative: they target formats that are unambiguously
// identifying. They are not a substitute for a DPIA, and no regex-based
// redaction can be complete: free text can carry personal data in forms no
// pattern will match. This is stated in the generated documentation too.
var BuiltinPatterns = map[string]string{
	"email":       `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
	"iban":        `\b[A-Z]{2}[0-9]{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b`,
	"credit_card": `\b(?:\d[ \-]?){13,19}\b`,
	"ipv4":        `\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`,
	"phone":       `\+\d{1,3}[ \-]?(?:\(?\d{2,5}\)?[ \-]?){1,4}\d{2,6}\b`,
}

// DefaultPatternNames are enabled when redact mode is selected without an
// explicit pattern list.
var DefaultPatternNames = []string{"email", "iban", "credit_card", "ipv4"}

// NewRedactor compiles the named built-in patterns. A name of the form
// "label=regexp" defines a custom pattern instead.
func NewRedactor(names []string) (*Redactor, error) {
	r := &Redactor{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if label, expr, ok := strings.Cut(n, "="); ok {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("content: custom pattern %q: %w", label, err)
			}
			r.patterns = append(r.patterns, namedPattern{name: label, re: re})
			continue
		}
		expr, ok := BuiltinPatterns[n]
		if !ok {
			return nil, fmt.Errorf("content: unknown redaction pattern %q (known: %s)", n, strings.Join(builtinNames(), ", "))
		}
		r.patterns = append(r.patterns, namedPattern{name: n, re: regexp.MustCompile(expr)})
	}
	return r, nil
}

func builtinNames() []string {
	names := make([]string, 0, len(BuiltinPatterns))
	for n := range BuiltinPatterns {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Names lists the active pattern labels, for reporting.
func (r *Redactor) Names() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.patterns))
	for _, p := range r.patterns {
		out = append(out, p.name)
	}
	return out
}

// Apply redacts s and returns the result with per-pattern hit counts.
func (r *Redactor) Apply(s string) (string, map[string]int) {
	if r == nil || len(r.patterns) == 0 || s == "" {
		return s, nil
	}
	var counts map[string]int
	for _, p := range r.patterns {
		n := 0
		s = p.re.ReplaceAllStringFunc(s, func(string) string {
			n++
			return "[REDACTED:" + p.name + "]"
		})
		if n > 0 {
			if counts == nil {
				counts = make(map[string]int)
			}
			counts[p.name] += n
		}
	}
	return s, counts
}

// Capturer turns observed bytes into an evidence payload at the configured
// fidelity.
type Capturer struct {
	Mode     string
	Redactor *Redactor
}

// Payload builds the record for one side of an interaction. raw is the exact
// byte sequence that crossed the wire; text is the human-readable rendering
// (assembled completion text, or the request rendered as messages) that store
// and redact modes retain.
//
// The digest is computed over raw in every mode, including hash mode. That is
// what lets someone holding a transcript prove it is the transcript of the
// interaction the chain attests to.
func (c *Capturer) Payload(raw []byte, text string, messages []evidence.Message) *evidence.Payload {
	sum := sha256.Sum256(raw)
	p := &evidence.Payload{
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  len(raw),
	}
	if c.Mode == evidence.ModeHash {
		return p
	}

	if c.Mode == evidence.ModeRedact {
		var counts map[string]int
		text, counts = c.Redactor.Apply(text)
		merge(&p.Redactions, counts)
		for i := range messages {
			redacted, mc := c.Redactor.Apply(messages[i].Content)
			messages[i].Content = redacted
			merge(&p.Redactions, mc)
		}
	}

	if len(text) > MaxTextBytes {
		text = text[:MaxTextBytes]
		p.Truncated = true
	}
	p.Text = text
	p.Messages = messages
	return p
}

// ToolArguments renders a tool call's arguments at the configured fidelity.
// Arguments routinely carry the same personal data as prompts, so they follow
// the same rules rather than being treated as harmless metadata.
func (c *Capturer) ToolArguments(args string) (text, digest string) {
	sum := sha256.Sum256([]byte(args))
	digest = hex.EncodeToString(sum[:])
	switch c.Mode {
	case evidence.ModeStore:
		return args, digest
	case evidence.ModeRedact:
		redacted, _ := c.Redactor.Apply(args)
		return redacted, digest
	default:
		return "", digest
	}
}

func merge(dst *map[string]int, src map[string]int) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[string]int, len(src))
	}
	for k, v := range src {
		(*dst)[k] += v
	}
}

// ClientHash derives a stable, non-reversible identifier for a caller from
// their credential. The salt is generated per installation and never leaves
// the host, so the resulting identifiers cannot be matched against a
// precomputed table of API keys, and they cannot be correlated across two
// installations either.
func ClientHash(salt []byte, credential string) string {
	if credential == "" {
		return ""
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte("\x00client\x00"))
	h.Write([]byte(credential))
	return hex.EncodeToString(h.Sum(nil))[:32]
}
