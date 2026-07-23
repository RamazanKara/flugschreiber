package proxy

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"log/slog"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// tlsUpstreamHarness starts a TLS mock upstream and returns its URL plus a PEM
// file holding its certificate, which stands in for an internal CA bundle.
func tlsUpstreamHarness(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	up := httptest.NewTLSServer(mockHandler())
	t.Cleanup(up.Close)

	pemPath := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: up.Certificate().Raw,
	})
	if err := os.WriteFile(pemPath, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return up, pemPath
}

// A model server behind an internal CA must be reachable by trusting that CA,
// because the alternative operators fall back to is plaintext, and prompts in
// clear on the wire defeats the rest of the design.
func TestUpstreamBehindAnInternalCA(t *testing.T) {
	up, caFile := tlsUpstreamHarness(t)

	t.Run("without the CA the connection is refused and recorded", func(t *testing.T) {
		h := newHarness(t, mockHandler(), func(c *config.Config) {
			c.Upstream = up.URL
		})
		resp := h.post("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 for an untrusted upstream", resp.StatusCode)
		}
		events := h.events()
		if len(events) != 1 || events[0].Error == "" {
			t.Fatalf("the refused connection was not recorded as evidence: %+v", events)
		}
		if !strings.Contains(events[0].Error, "certificate") && !strings.Contains(events[0].Error, "x509") {
			t.Errorf("recorded error does not name the cause: %q", events[0].Error)
		}
	})

	t.Run("with the CA the interaction proxies and records", func(t *testing.T) {
		h := newHarness(t, mockHandler(), func(c *config.Config) {
			c.Upstream = up.URL
			c.UpstreamCAFile = caFile
		})
		out := h.postAndDrain("/v1/chat/completions",
			`{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
		if !strings.Contains(out, "mock upstream") {
			t.Fatalf("upstream not reached through TLS: %s", out)
		}
		events := h.events()
		if len(events) != 1 || events[0].Status != 200 {
			t.Fatalf("TLS interaction not recorded cleanly: %+v", events)
		}
	})

	t.Run("skip-verify also works, as the documented last resort", func(t *testing.T) {
		h := newHarness(t, mockHandler(), func(c *config.Config) {
			c.Upstream = up.URL
			c.UpstreamTLSSkipVerify = true
		})
		out := h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)
		if !strings.Contains(out, "mock upstream") {
			t.Fatalf("skip-verify did not reach the upstream: %s", out)
		}
	})
}

// A CA file that does not parse must fail at startup with a message naming the
// file, never fall back silently to the system pool.
func TestGarbageCAFileFailsLoudly(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Upstream = "https://vllm.internal:8000"
	cfg.UpstreamCAFile = bad
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate should accept the path; parsing belongs to the proxy: %v", err)
	}

	store := mustOpenStore(t)
	_, err := New(cfg, store, discardLogger())
	if err == nil {
		t.Fatal("a garbage CA file was accepted")
	}
	if !strings.Contains(err.Error(), bad) {
		t.Errorf("error does not name the file: %v", err)
	}
}

func mustOpenStore(t *testing.T) *evidence.Store {
	t.Helper()
	store, err := evidence.Open(evidence.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
