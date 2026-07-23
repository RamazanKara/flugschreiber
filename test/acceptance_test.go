// Package acceptance_test runs the quickstart from the README end to end,
// against the real binary, over real HTTP.
//
// This is the acceptance demo expressed as a test: docker run, repoint the base
// URL, make three calls with one streamed, verify the chain, generate the
// report. If this test fails, the product's headline promise is broken,
// regardless of what the unit tests say.
package acceptance_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQuickstartEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}

	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "evidence")
	reportDir := filepath.Join(work, "reports")
	addr := freeAddr(t)
	baseURL := "http://" + addr + "/v1"

	// Step 1: run Flugschreiber. The mock upstream stands in for the
	// container's default configuration so the test needs no model server.
	proc := startServe(t, bin, "--mock-upstream", "--data-dir", dataDir, "--listen", addr)
	waitHealthy(t, "http://"+addr+"/healthz")

	// Step 2 and 3: three chat completion calls through the proxy, one of them
	// streamed. This is what "repoint OPENAI_BASE_URL" amounts to.
	t.Run("three calls, one streamed", func(t *testing.T) {
		first := postJSON(t, baseURL+"/chat/completions", map[string]any{
			"model":       "llama-3.1-8b",
			"temperature": 0.2,
			"messages":    []any{msg("user", "What is our refund window?")},
		})
		if !strings.Contains(first, "mock upstream") {
			t.Fatalf("first call did not reach the upstream: %s", first)
		}

		chunks := postStream(t, baseURL+"/chat/completions", map[string]any{
			"model":          "llama-3.1-8b",
			"stream":         true,
			"stream_options": map[string]any{"include_usage": true},
			"messages":       []any{msg("user", "Summarise ticket 8821.")},
		})
		if len(chunks) < 3 {
			t.Fatalf("expected an incremental stream, got %d chunks", len(chunks))
		}

		third := postJSON(t, baseURL+"/embeddings", map[string]any{
			"model": "bge-m3",
			"input": []string{"contract clause 4", "contract clause 5"},
		})
		if !strings.Contains(third, "embedding") {
			t.Fatalf("embeddings call failed: %s", third)
		}
	})

	stopServe(t, proc)

	// Step 4: verify the chain, with no server running.
	t.Run("verify reports an intact chain", func(t *testing.T) {
		out, err := run(t, bin, "verify", "--dir", dataDir)
		if err != nil {
			t.Fatalf("verify failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "hash chain intact") {
			t.Errorf("verify did not confirm the chain:\n%s", out)
		}
		if !strings.Contains(out, "records     3") {
			t.Errorf("expected three recorded interactions:\n%s", out)
		}
	})

	t.Run("verify emits machine-readable output", func(t *testing.T) {
		out, err := run(t, bin, "verify", "--dir", dataDir, "--json")
		if err != nil {
			t.Fatalf("verify --json failed: %v\n%s", err, out)
		}
		var res struct {
			Records  int `json:"records"`
			Problems []struct {
				Kind string `json:"kind"`
			} `json:"problems"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("verify --json did not emit JSON: %v\n%s", err, out)
		}
		if res.Records != 3 || len(res.Problems) != 0 {
			t.Errorf("verify --json = %+v", res)
		}
	})

	// Step 5: generate the documentation artifacts.
	t.Run("report generates the artifacts", func(t *testing.T) {
		out, err := run(t, bin, "report",
			"--dir", dataDir, "--out", reportDir,
			"--organisation", "Muster GmbH",
			"--system-name", "Support Assistant",
			"--purpose", "drafting first-line support replies for human review",
			"--contact", "ai-governance@muster.example")
		if err != nil {
			t.Fatalf("report failed: %v\n%s", err, out)
		}

		want := []string{
			"technical-documentation.md",
			"transparency-article-50-en.md",
			"transparency-article-50-de.md",
		}
		for _, name := range want {
			body, err := os.ReadFile(filepath.Join(reportDir, name))
			if err != nil {
				t.Fatalf("expected artifact %s: %v", name, err)
			}
			if len(body) < 500 {
				t.Errorf("%s is suspiciously short (%d bytes)", name, len(body))
			}
		}

		doc := readFile(t, filepath.Join(reportDir, "technical-documentation.md"))

		// The documentation must be pre-filled from what actually happened,
		// not from a static template.
		for _, needle := range []string{
			"Support Assistant",
			"Muster GmbH",
			"/v1/chat/completions",
			"/v1/embeddings",
			"flugschreiber-mock-1",
			"llama-3.1-8b",
			"hash chain verified intact",
		} {
			if !strings.Contains(doc, needle) {
				t.Errorf("technical documentation is missing observed detail %q", needle)
			}
		}

		if !strings.Contains(doc, "**TODO:**") {
			t.Error("technical documentation has no TODO markers; gaps must be marked, not glossed over")
		}

		de := readFile(t, filepath.Join(reportDir, "transparency-article-50-de.md"))
		if !strings.Contains(de, "Sie chatten mit einer KI") {
			t.Error("German transparency pack is missing the chatbot disclosure snippet")
		}
		en := readFile(t, filepath.Join(reportDir, "transparency-article-50-en.md"))
		if !strings.Contains(en, "You are chatting with an AI assistant") {
			t.Error("English transparency pack is missing the chatbot disclosure snippet")
		}
	})

	// Not part of the five-minute demo, but the claim the demo rests on: if
	// the log is edited, verification says so and exits non-zero.
	t.Run("tampering is detected", func(t *testing.T) {
		tampered := filepath.Join(work, "tampered")
		copyDir(t, dataDir, tampered)

		seg := filepath.Join(tampered, "seg-00000001.jsonl")
		raw := readFile(t, seg)
		edited := strings.Replace(raw, `"llama-3.1-8b"`, `"llama-3.1-7b"`, 1)
		if edited == raw {
			t.Fatal("test fixture does not contain the string it means to edit")
		}
		if err := os.WriteFile(seg, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}

		out, err := run(t, bin, "verify", "--dir", tampered)
		if err == nil {
			t.Fatal("verify exited 0 on a tampered log")
		}
		if !strings.Contains(out, "VERIFICATION FAILED") {
			t.Errorf("verify did not report the failure clearly:\n%s", out)
		}
		if !strings.Contains(out, "hash_mismatch") {
			t.Errorf("verify did not name the problem:\n%s", out)
		}
	})
}

// Proxy overhead is a product claim, so it is measured rather than asserted in
// a README. The mock upstream responds in microseconds, so nearly all of the
// measured latency is the proxy itself.
func TestProxyOverheadStaysUnderBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("overhead measurement runs the binary")
	}

	bin := buildBinary(t)
	dataDir := filepath.Join(t.TempDir(), "evidence")
	addr := freeAddr(t)

	proc := startServe(t, bin, "--mock-upstream", "--data-dir", dataDir, "--listen", addr)
	defer stopServe(t, proc)
	waitHealthy(t, "http://"+addr+"/healthz")

	body := map[string]any{
		"model":    "llama-3.1-8b",
		"messages": []any{msg("user", "ping")},
	}

	const n = 200
	latencies := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		postJSON(t, "http://"+addr+"/v1/chat/completions", body)
		latencies = append(latencies, time.Since(start))
	}

	p50 := percentile(latencies, 0.50)
	p95 := percentile(latencies, 0.95)
	t.Logf("round trip through the proxy over %d requests: p50 %v, p95 %v", n, p50, p95)

	// The target is 5 ms at p50 excluding upstream latency. The mock's own
	// work is included here, which makes this a conservative check.
	if p50 > 5*time.Millisecond {
		t.Errorf("p50 round trip %v exceeds the 5 ms budget", p50)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	name := "flugschreiber"
	if runtime.GOOS == "windows" {
		// Windows resolves executables by extension; without it the spawn
		// fails with "executable file not found", which the first real
		// Windows CI run demonstrated.
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "../cmd/flugschreiber")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func startServe(t *testing.T, bin string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"serve"}, args...)...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return cmd
}

func stopServe(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal serve: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("serve did not shut down within 10s")
	}
}

func waitHealthy(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s never became healthy", url)
}

func run(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return string(out), err
}

func msg(role, content string) map[string]any {
	return map[string]any{"role": role, "content": content}
}

func postJSON(t *testing.T, url string, payload map[string]any) string {
	t.Helper()
	resp := post(t, url, payload)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// postStream reads SSE frames as they arrive, so a proxy that buffered the
// stream would be visible as a single chunk.
func postStream(t *testing.T, url string, payload map[string]any) []string {
	t.Helper()
	resp := post(t, url, payload)
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want an event stream", ct)
	}

	var frames []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") {
			frames = append(frames, strings.TrimPrefix(line, "data: "))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if len(frames) == 0 || frames[len(frames)-1] != "[DONE]" {
		t.Fatalf("stream did not terminate with [DONE]: %v", frames)
	}
	return frames
}

func post(t *testing.T, url string, payload map[string]any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer demo-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST %s = %d: %s", url, resp.StatusCode, b)
	}
	return resp
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func percentile(d []time.Duration, q float64) time.Duration {
	sorted := append([]time.Duration(nil), d...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(float64(len(sorted)-1)*q)]
}
