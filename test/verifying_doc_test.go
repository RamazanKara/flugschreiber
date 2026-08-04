package acceptance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The independent-verifier document ships a reference implementation in Python.
// Its whole value is that it reproduces the head hash of the frozen fixture, so
// a reader who runs it against their own log knows their event handling is
// right. This runs the code from the document, unedited, against the fixture,
// so the published reference cannot drift from the format.
//
// It skips rather than fails when Python is absent, because a missing
// interpreter on a CI runner is not a defect in the document.
func TestVerifyingDocReferenceImplementationIsCorrect(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}

	doc, err := os.ReadFile(filepath.Join("..", "docs", "VERIFYING.md"))
	if err != nil {
		t.Fatal(err)
	}
	code := firstPythonBlock(t, string(doc))
	if !strings.Contains(code, "def check_chain") {
		t.Fatalf("the reference implementation block is not the one expected:\n%s", code)
	}
	// Run it exactly as a reader would: python3 -c CODE FIXTURE, so the block's
	// own __main__ guard reads the fixture path from argv and prints its head.
	cmd := exec.Command(python, "-c", code, filepath.Join("..", "testdata", "conformance"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the reference implementation errored: %v\n%s", err, out)
	}

	got := headFromOutput(t, string(out))
	want := headHashFromExpected(t)
	if got != want {
		t.Errorf("the document's reference implementation computes head %s, the fixture heads at %s:\n"+
			"the published verifier no longer matches the format it describes", got, want)
	}
}

var pyFence = regexp.MustCompile("(?s)```python\\n(.*?)\\n```")

var docHead = regexp.MustCompile(`head ([0-9a-f]{64})`)

// headFromOutput pulls the head hash out of the reference implementation's
// printed line, so the test reads what a user would see rather than a value
// wired in for the test's convenience.
func headFromOutput(t *testing.T, out string) string {
	t.Helper()
	m := docHead.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the reference implementation printed no head:\n%s", out)
	}
	return m[1]
}

func firstPythonBlock(t *testing.T, doc string) string {
	t.Helper()
	m := pyFence.FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("no python code block in VERIFYING.md")
	}
	return m[1]
}

var headField = regexp.MustCompile(`"head_hash":\s*"([0-9a-f]+)"`)

func headHashFromExpected(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "conformance", "EXPECTED.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := headField.FindSubmatch(raw)
	if m == nil {
		t.Fatal("no head_hash in EXPECTED.json")
	}
	return string(m[1])
}
