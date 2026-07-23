package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestMainDispatch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments prints usage and fails", nil, 2},
		{"unknown command fails", []string{"frobnicate"}, 2},
		{"help succeeds", []string{"--help"}, 0},
		{"version succeeds", []string{"version"}, 0},
		{"verify without a directory fails", []string{"verify"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Main(tc.args); got != tc.want {
				t.Errorf("Main(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

// The full command set the README documents must exist. A command renamed in
// code but not in the docs fails here rather than in a user's terminal.
//
// serve is absent because it takes --data-dir rather than --dir and, with
// flag.ExitOnError, an unknown flag would exit the whole test binary. The
// acceptance suite runs serve for real.
func TestEveryDocumentedCommandDispatches(t *testing.T) {
	for _, cmd := range []string{"verify", "report", "export", "inspect", "coverage", "retention"} {
		t.Run(cmd, func(t *testing.T) {
			// Each command run without its required flags must fail with its
			// own error, not with "unknown command".
			if got := Main([]string{cmd, "--dir", ""}); got == 2 {
				t.Errorf("command %q is not wired into the dispatcher", cmd)
			}
		})
	}
}

// Verify and report run against a real directory through the same entry point
// the binary uses, which is what gives this package's coverage meaning.
func TestVerifyAndReportThroughMain(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(&evidence.Event{
		EventType: evidence.EventInference, RequestID: "r", Status: 200,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if got := Main([]string{"verify", "--dir", dir, "--quiet"}); got != 0 {
		t.Fatalf("verify on an intact log exited %d", got)
	}

	out := filepath.Join(t.TempDir(), "reports")
	if got := Main([]string{"report", "--dir", dir, "--out", out,
		"--now", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)}); got != 0 {
		t.Fatalf("report exited %d", got)
	}
	body, err := os.ReadFile(filepath.Join(out, "technical-documentation.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hash chain verified intact") {
		t.Error("generated documentation does not reflect the verified chain")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:     "512 B",
		2048:    "2.0 KiB",
		5 << 20: "5.0 MiB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
