package acceptance_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestSARIFExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}
	bin := buildBinary(t)
	for _, tc := range []struct {
		name     string
		damaged  bool
		keyGone  bool
		code     int
		complete bool
	}{
		{"intact", false, false, 0, true},
		{"damaged", true, false, 1, true},
		{"missing key", false, true, 2, false},
		{"mixed", true, true, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.keyGone {
				if _, err := evidence.LoadOrCreateKeyPair(dir); err != nil {
					t.Fatal(err)
				}
			}
			files, err := filepath.Glob("../testdata/conformance/*")
			if err != nil || len(files) == 0 {
				t.Fatalf("fixture: %v", err)
			}
			for _, path := range files {
				name := filepath.Base(path)
				if tc.keyGone && name == "public-key.pem" {
					continue
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if tc.damaged && name == "seg-00000001.jsonl" {
					data[0] = '['
				}
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := run(t, bin, "verify", "--dir", dir, "--format", "sarif")
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			var doc struct {
				Runs []struct {
					Invocations []struct {
						ExitCode            int
						ExecutionSuccessful bool
					}
				}
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
				t.Fatalf("invalid SARIF: %v\n%s", err, out)
			}
			inv := doc.Runs[0].Invocations[0]
			if code != tc.code || inv.ExitCode != code || inv.ExecutionSuccessful != tc.complete {
				t.Fatalf("exit %d, invocation %+v; want exit %d, complete %v", code, inv, tc.code, tc.complete)
			}
		})
	}
}

func TestShellCompletions(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}
	bin := buildBinary(t)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, shell := range []struct{ name, executable string }{{"bash", "bash"}, {"powershell", "pwsh"}} {
		t.Run(shell.name, func(t *testing.T) {
			executable, err := exec.LookPath(shell.executable)
			if err != nil {
				if shell.name == "powershell" {
					executable, err = exec.LookPath("powershell")
				}
				if err != nil {
					t.Skipf("%s is not installed", shell.name)
				}
			}
			script, err := run(t, bin, "completion", shell.name)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "completion.ps1")
			if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("FLUGSCHREIBER_COMPLETION_SCRIPT", path)
			for _, tc := range []struct{ line, want string }{
				{"flugschreiber ver", "verify\nversion"},
				{"flugschreiber verify --fo", "--format"},
				{"flugschreiber serve --check", "--check-config\n--checkpoint-interval"},
				{"flugschreiber keys ro", "rotate"},
				{"flugschreiber keys retire --ke", "--key"},
				{"flugschreiber completion po", "powershell"},
				{"flugschreiber verify ", ""},
				{"flugschreiber unknown --di", ""},
			} {
				t.Run(tc.line, func(t *testing.T) {
					var cmd *exec.Cmd
					if shell.name == "bash" {
						cmd = exec.Command(executable, "-c", `source "$FLUGSCHREIBER_COMPLETION_SCRIPT"
read -r -a COMP_WORDS <<< "$1"
[[ "$1" == *' ' ]] && COMP_WORDS+=("")
COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
_flugschreiber
printf '%s\n' "${COMPREPLY[@]}"`, "--", tc.line)
					} else {
						t.Setenv("FLUGSCHREIBER_COMPLETION_LINE", tc.line)
						cmd = exec.Command(executable, "-NoProfile", "-NonInteractive", "-Command", `. $env:FLUGSCHREIBER_COMPLETION_SCRIPT
$line = $env:FLUGSCHREIBER_COMPLETION_LINE
[System.Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches | ForEach-Object CompletionText`)
					}
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("completion failed: %v\n%s", err, out)
					}
					got := strings.TrimSpace(strings.ReplaceAll(string(out), "\r\n", "\n"))
					if tc.want != "" && got != tc.want || tc.want == "" && strings.Contains(got, "--dir") {
						t.Fatalf("completion = %q, want %q", got, tc.want)
					}
				})
			}
		})
	}
}
