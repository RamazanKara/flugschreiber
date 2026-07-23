package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// modelSeeds are request-body prefixes the model scanner has to survive: the
// model at the front, buried behind a nested object and an array, absent, a
// non-string model, truncated JSON, a bare value, and raw noise. scanModel reads
// a possibly-truncated peek prefix, so half-formed JSON is the common case, not
// the exception.
var modelSeeds = []string{
	`{"model":"llama-3.1-8b","stream":true}`,
	`{"stream":true,"messages":[{"role":"user","content":"hi"}],"model":"gpt-4o"}`,
	`{"metadata":{"model":"decoy"},"model":"real"}`,
	`{"tools":[{"type":"function"}],"model":"m"}`,
	`{"model":123}`,
	`{"model":`,
	`{"model":"unterminated`,
	`{}`,
	`[]`,
	`not json`,
	`{"model":"m"` + strings.Repeat(",", 4096),
	`{"a":` + strings.Repeat("[", 2048),
	"",
	"\x00\x01\x02",
}

// FuzzScanModel asserts that the streaming model scanner never panics on any
// bytes and is deterministic. scanModel runs on a bounded, often truncated prefix
// of a live request body (D33), so it is fed malformed JSON by design and must
// always return, never fault.
func FuzzScanModel(f *testing.F) {
	for _, s := range modelSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		m1, ok1 := scanModel(body)
		m2, ok2 := scanModel(body)
		if m1 != m2 || ok1 != ok2 {
			t.Fatalf("scanModel is not deterministic: (%q,%v) then (%q,%v)", m1, ok1, m2, ok2)
		}
		if !ok1 && m1 != "" {
			t.Fatalf("scanModel reported not-found but returned a model %q", m1)
		}
	})
}

// FuzzPeekModelReconstructsBody is the property that makes the bounded peek (D33)
// a safe exception to tee-never-buffer: the reader peekModel hands back must
// replay the original body byte-for-byte, or the digest the tap computes over it
// would no longer describe what the upstream received. For every input it asserts
// the peeked prefix is a genuine prefix of the body, the reconstructed stream
// equals the body exactly, the reported model agrees with a scan of the prefix,
// and the whole operation is deterministic.
func FuzzPeekModelReconstructsBody(f *testing.F) {
	for _, s := range modelSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		model, truncated, prefix, rebuilt := peekModel(io.NopCloser(bytes.NewReader(body)))
		if !bytes.HasPrefix(body, prefix) {
			t.Fatalf("peeked prefix is not a prefix of the body (prefix %d bytes, body %d bytes)", len(prefix), len(body))
		}
		got, err := io.ReadAll(rebuilt)
		if err != nil {
			t.Fatalf("reading the reconstructed body: %v", err)
		}
		if err := rebuilt.Close(); err != nil {
			t.Fatalf("closing the reconstructed body: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("reconstructed body differs from the original: got %d bytes, want %d", len(got), len(body))
		}
		if sm, _ := scanModel(prefix); sm != model {
			t.Fatalf("peek model %q disagrees with a scan of the prefix %q", model, sm)
		}

		m2, tr2, pre2, rc2 := peekModel(io.NopCloser(bytes.NewReader(body)))
		got2, _ := io.ReadAll(rc2)
		_ = rc2.Close()
		if model != m2 || truncated != tr2 || !bytes.Equal(prefix, pre2) || !bytes.Equal(got, got2) {
			t.Fatalf("peekModel is not deterministic")
		}
	})
}

// globSeeds are the router_test cases plus patterns built to break a naive
// backtracking matcher: long runs of stars, alternating star and literal, and the
// classic catastrophic-backtracking shape. globMatch selects an upstream from
// operator-supplied globs, so a pattern that hangs or faults it is a routing DoS.
var globSeeds = [][2]string{
	{"llama-3.1-8b", "llama-3.1-8b"},
	{"llama-*", "meta/llama-3.1-8b"},
	{"*", ""},
	{"", ""},
	{"gpt-4?", "gpt-4o"},
	{"a*b*c", "axxbyyc"},
	{"*llama*", "meta/llama-3.1-8b"},
	{strings.Repeat("*", 64), strings.Repeat("a", 64)},
	{strings.Repeat("a*", 32), strings.Repeat("a", 64)},
	{"*?*?*?*", "abcdef"},
}

// FuzzGlobMatch asserts the matcher never panics or hangs on any pattern and
// name, is deterministic, and matches a metacharacter-free pattern exactly when
// it equals the name. The termination guarantee is the point: the code claims a
// hostile pattern cannot drive it into deep recursion, and a fuzzer feeding it
// pathological star runs is how that claim is exercised.
func FuzzGlobMatch(f *testing.F) {
	for _, s := range globSeeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		got := globMatch(pattern, name)
		if again := globMatch(pattern, name); got != again {
			t.Fatalf("globMatch(%q, %q) is not deterministic: %v then %v", pattern, name, got, again)
		}
		// A pattern with no wildcards is a literal, so it matches exactly one
		// name: itself.
		if !strings.ContainsAny(pattern, "*?") {
			if got != (pattern == name) {
				t.Fatalf("literal globMatch(%q, %q) = %v, want %v", pattern, name, got, pattern == name)
			}
		}
	})
}
