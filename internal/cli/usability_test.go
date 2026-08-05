package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// runCLI captures stdout; the dispatcher's diagnostics go to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-out
}

// Operators run a dozen commands against the same directory, and serve already
// reads it from FLUGSCHREIBER_DATA_DIR. The reading commands honour the same
// variable, with the flag winning when both are given.
func TestDirFallsBackToTheDataDirEnvironment(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{EventType: evidence.EventInference, RequestID: "r-env"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FLUGSCHREIBER_DATA_DIR", dir)
	code, out := runCLI(t, "coverage")
	if code != 0 {
		t.Fatalf("coverage with only the environment set exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, dir) {
		t.Fatalf("coverage did not report on the directory the environment named:\n%s", out)
	}

	// The flag beats the environment, per the documented layering.
	other := t.TempDir()
	code, out = runCLI(t, "coverage", "--dir", other)
	if code != 0 {
		t.Fatalf("coverage --dir exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, other) {
		t.Fatalf("an explicit --dir lost to the environment:\n%s", out)
	}

	// With neither, the refusal names the variable so the fix is in the message.
	t.Setenv("FLUGSCHREIBER_DATA_DIR", "")
	var stderr string
	var codeNone int
	stderr = captureStderr(t, func() { codeNone = Main([]string{"coverage"}) })
	if codeNone != 1 {
		t.Fatalf("coverage with no directory at all exited %d, want 1", codeNone)
	}
	if !strings.Contains(stderr, "FLUGSCHREIBER_DATA_DIR") {
		t.Fatalf("the refusal does not name the environment variable:\n%s", stderr)
	}
}

// inspect calls it --request and erase calls it --request-id. Both names work
// on both commands, so nobody has to remember which command uses which.
func TestRequestFlagAliases(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{EventType: evidence.EventInference, RequestID: "r-alias", Status: 200}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	code, byRequest := runCLI(t, "inspect", "--dir", dir, "--request", "r-alias")
	if code != 0 {
		t.Fatalf("inspect --request exited %d:\n%s", code, byRequest)
	}
	code, byRequestID := runCLI(t, "inspect", "--dir", dir, "--request-id", "r-alias")
	if code != 0 {
		t.Fatalf("inspect --request-id exited %d:\n%s", code, byRequestID)
	}
	if byRequest != byRequestID {
		t.Fatalf("the alias reconstructs something different:\n--request:\n%s\n--request-id:\n%s", byRequest, byRequestID)
	}

	// On erase the alias must reach the selector. This log holds no encrypted
	// content, so the run reports nothing to erase; what matters is that the
	// value given as --request is the request the command looked for.
	code, eraseOut := runCLI(t, "erase", "--dir", dir, "--request", "r-alias")
	if code != 0 {
		t.Fatalf("erase --request exited %d:\n%s", code, eraseOut)
	}
	if !strings.Contains(eraseOut, "r-alias") {
		t.Fatalf("the --request alias did not reach erase's selector:\n%s", eraseOut)
	}
}

// A typo lands one edit from the real command more often than not, and the
// binary knows every command it has.
func TestUnknownCommandSuggestsTheNearestOne(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() { code = Main([]string{"verfy"}) })
	if code != 2 {
		t.Fatalf("unknown command exited %d, want 2", code)
	}
	if !strings.Contains(stderr, `Did you mean "verify"?`) {
		t.Fatalf("no suggestion for a one-letter typo:\n%s", stderr)
	}

	// Far from everything: a suggestion would be a guess, so there is none.
	stderr = captureStderr(t, func() { code = Main([]string{"frobnicate"}) })
	if code != 2 {
		t.Fatalf("unknown command exited %d, want 2", code)
	}
	if strings.Contains(stderr, "Did you mean") {
		t.Fatalf("suggested a command for something nothing resembles:\n%s", stderr)
	}
}
