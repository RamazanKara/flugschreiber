package acceptance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The --pdf flag renders each document with only the built-in base fonts, for
// the recipient who accepts nothing else. The Markdown stays authoritative.
func TestReportRendersPDFs(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}

	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "evidence")
	addr := freeAddr(t)

	proc := startServe(t, bin, "--mock-upstream", "--data-dir", dataDir, "--listen", addr)
	waitHealthy(t, "http://"+addr+"/healthz")
	postJSON(t, "http://"+addr+"/v1/chat/completions", map[string]any{
		"model": "llama-3.1-8b", "messages": []any{msg("user", "hello")},
	})
	stopServe(t, proc)

	out := filepath.Join(work, "reports")
	cmdOut, err := run(t, bin, "report", "--dir", dataDir, "--out", out, "--pdf",
		"--organisation", "Muster GmbH", "--system-name", "Support Assistant")
	if err != nil {
		t.Fatalf("report --pdf failed: %v\n%s", err, cmdOut)
	}

	for _, name := range []string{
		"technical-documentation.pdf",
		"transparency-article-50-en.pdf",
		"transparency-article-50-de.pdf",
	} {
		body, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
		if !strings.HasPrefix(string(body), "%PDF-") {
			t.Errorf("%s does not start with a PDF header", name)
		}
		if len(body) < 2000 {
			t.Errorf("%s is suspiciously small (%d bytes)", name, len(body))
		}
	}

	// When a real PDF text extractor is available, prove one can read the
	// output, umlauts included. Its absence skips the assertion, not the test.
	if pdftotext, err := exec.LookPath("pdftotext"); err == nil {
		raw, err := exec.Command(pdftotext,
			filepath.Join(out, "transparency-article-50-de.pdf"), "-").Output()
		if err != nil {
			t.Fatalf("pdftotext could not read the generated PDF: %v", err)
		}
		if !strings.Contains(string(raw), "Transparenzpaket nach Artikel 50") {
			t.Errorf("extracted text is missing the German title:\n%.400s", raw)
		}
	}
}
