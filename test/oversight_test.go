package acceptance_test

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOversightAndExportEndToEnd is the M3 half of the acceptance demo: record a
// model interaction, record the human decision taken about it, then hand the
// whole thing to a third party as a bundle they can verify without access to
// anything of ours.
func TestOversightAndExportEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}

	const token = "acceptance-events-token"

	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "evidence")
	addr := freeAddr(t)
	baseURL := "http://" + addr

	proc := startServe(t, bin,
		"--mock-upstream", "--data-dir", dataDir, "--listen", addr,
		"--events-token", token)
	waitHealthy(t, baseURL+"/healthz")

	// An inference, then the human decision about it.
	body := postJSON(t, baseURL+"/v1/chat/completions", map[string]any{
		"model":    "llama-3.1-8b",
		"messages": []any{msg("user", "Should we refund order 8821?")},
	})
	if !strings.Contains(body, "mock upstream") {
		t.Fatalf("inference did not reach the upstream: %s", body)
	}

	requestID := postEvent(t, baseURL, token, map[string]any{
		"event_type": "human_intervention",
		"session_id": "sess-acceptance",
		"actor":      "alice@muster.example",
		"decision":   "override",
		"note":       "Model advised refusing. Agent approved the refund under policy 4.2.",
	})
	if requestID == "" {
		t.Fatal("events endpoint returned no request id")
	}

	stopServe(t, proc)

	t.Run("chain covers both the interaction and the decision", func(t *testing.T) {
		out, err := run(t, bin, "verify", "--dir", dataDir)
		if err != nil {
			t.Fatalf("verify failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "hash chain intact") {
			t.Errorf("chain not intact:\n%s", out)
		}
		if !strings.Contains(out, "records     2") {
			t.Errorf("expected the inference and the intervention:\n%s", out)
		}
	})

	t.Run("coverage reports fidelity without overclaiming", func(t *testing.T) {
		out, err := run(t, bin, "coverage", "--dir", dataDir)
		if err != nil {
			t.Fatalf("coverage failed: %v\n%s", err, out)
		}
		for _, want := range []string{"human_intervention", "inference", "hash"} {
			if !strings.Contains(out, want) {
				t.Errorf("coverage output is missing %q:\n%s", want, out)
			}
		}
		// The command must never imply that what it captured is everything.
		if !strings.Contains(out, "cannot describe traffic that bypassed the proxy") {
			t.Errorf("coverage does not state its own limit:\n%s", out)
		}
	})

	t.Run("coverage emits machine-readable output", func(t *testing.T) {
		out, err := run(t, bin, "coverage", "--dir", dataDir, "--json")
		if err != nil {
			t.Fatalf("coverage --json failed: %v\n%s", err, out)
		}
		var c struct {
			Records       int  `json:"records"`
			Inference     int  `json:"inference_records"`
			ChainVerified bool `json:"chain_verified"`
		}
		if err := json.Unmarshal([]byte(out), &c); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if c.Records != 2 || c.Inference != 1 || !c.ChainVerified {
			t.Errorf("coverage = %+v", c)
		}
	})

	t.Run("inspect reconstructs the session with the decision", func(t *testing.T) {
		out, err := run(t, bin, "inspect", "--dir", dataDir, "--session", "sess-acceptance")
		if err != nil {
			t.Fatalf("inspect failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "OVERRIDE by alice@muster.example") {
			t.Errorf("inspect does not show the oversight decision:\n%s", out)
		}
		// Default content mode is hash, so there is no transcript and the
		// output has to say why rather than looking empty.
		if !strings.Contains(out, "No prompt or completion text is recorded") {
			t.Errorf("inspect does not explain the absent transcript:\n%s", out)
		}
	})

	t.Run("export produces a verifiable bundle without secrets", func(t *testing.T) {
		bundle := filepath.Join(work, "evidence-bundle.tar.gz")
		out, err := run(t, bin, "export", "--dir", dataDir, "--out", bundle,
			"--note", "Provided in response to a supervisory authority request.")
		if err != nil {
			t.Fatalf("export failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "no signing key, no client salt and no content keys") {
			t.Errorf("export does not state what it withheld:\n%s", out)
		}

		files := untar(t, bundle)

		for _, want := range []string{"MANIFEST.json", "VERIFY.md"} {
			if _, ok := files["flugschreiber-evidence/"+want]; !ok {
				t.Errorf("bundle is missing %s", want)
			}
		}
		for name := range files {
			base := filepath.Base(name)
			if base == "signing-key.pem" || base == "client-salt" {
				t.Fatalf("bundle leaked %s", base)
			}
		}
		if !strings.Contains(files["flugschreiber-evidence/VERIFY.md"],
			"Provided in response to a supervisory authority request.") {
			t.Error("the exporter's note did not reach VERIFY.md")
		}

		// The decisive property: a recipient who extracts the bundle and runs
		// verify against it gets a clean result, with no access to our host.
		extracted := filepath.Join(work, "received")
		if err := os.MkdirAll(extracted, 0o750); err != nil {
			t.Fatal(err)
		}
		// The bundle's tree is preserved rather than flattened. Retired public
		// keys live under keys/, and a recipient who flattened them would find
		// a directory that fails to verify after any rotation, for a reason
		// nothing in the output would explain.
		for name, bodyText := range files {
			rel := strings.TrimPrefix(name, "flugschreiber-evidence/")
			dst := filepath.Join(extracted, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, []byte(bodyText), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out, err = run(t, bin, "verify", "--dir", extracted)
		if err != nil {
			t.Fatalf("a recipient could not verify the exported bundle: %v\n%s", err, out)
		}
		if !strings.Contains(out, "hash chain intact") {
			t.Errorf("exported bundle does not verify:\n%s", out)
		}
	})
}

// The events endpoint refuses to write anything without a token, because a
// forged oversight record in a tamper-evident log reads as authoritative.
func TestEventsEndpointRequiresATokenEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}

	bin := buildBinary(t)
	dataDir := filepath.Join(t.TempDir(), "evidence")
	addr := freeAddr(t)

	proc := startServe(t, bin, "--mock-upstream", "--data-dir", dataDir, "--listen", addr)
	waitHealthy(t, "http://"+addr+"/healthz")

	payload, err := json.Marshal(map[string]any{
		"event_type": "human_intervention",
		"actor":      "mallory",
		"decision":   "approve",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("http://"+addr+"/flugschreiber/v1/events",
		"application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		t.Fatalf("an unauthenticated caller recorded an oversight event: %s", respBody)
	}
	stopServe(t, proc)

	out, err := run(t, bin, "coverage", "--dir", dataDir, "--json")
	if err != nil {
		t.Fatalf("coverage failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "human_intervention") {
		t.Errorf("a forged oversight record reached the log:\n%s", out)
	}
}

func postEvent(t *testing.T, baseURL, token string, payload map[string]any) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/flugschreiber/v1/events",
		strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("events endpoint returned %d: %s", resp.StatusCode, raw)
	}

	var out struct {
		Recorded  bool   `json:"recorded"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("events response is not JSON: %v (%s)", err, raw)
	}
	if !out.Recorded {
		t.Fatalf("events endpoint did not record: %s", raw)
	}
	return out.RequestID
}

func untar(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("bundle is not gzip: %v", err)
	}
	defer gz.Close()

	out := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("bundle is not a tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(body)
	}
	return out
}
