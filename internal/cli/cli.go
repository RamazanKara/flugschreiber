// Package cli implements the commands, so that the full toolchain binary and
// the serve-only proxy binary share one implementation rather than drifting
// apart.
package cli

import (
	"fmt"
	"os"

	"github.com/RamazanKara/flugschreiber/internal/version"
)

const usage = `flugschreiber: audit and evidence layer for self-hosted LLM serving

Usage:
  flugschreiber <command> [flags]

Record:
  serve           Run the recording proxy in front of an OpenAI-compatible endpoint

Check:
  verify          Check the integrity of an evidence directory (no server needed)
  archive-verify  Check that the archive holds every sealed segment
  coverage        Report what was captured and at what fidelity

Hand over:
  report          Generate technical documentation and transparency artifacts
  export          Package the evidence as a bundle a third party can verify
  inspect         Reconstruct a session or request in readable form

Maintain:
  keys            Show or rotate the checkpoint signing key
  retention       Report on retention, enforce it, or place a legal hold
  erase           Destroy the stored content of a session (crypto-shredding)
  repair          Finish a write a power loss interrupted, so the server can start
  version         Print build information

Every command that reads evidence takes --dir, and falls back to
FLUGSCHREIBER_DATA_DIR when the flag is not given.

Run "flugschreiber <command> -h" for the flags of a command.

Flugschreiber produces evidence and documentation inputs. It does not make
anyone compliant with anything, and it is not legal advice.
`

// commandNames is what the did-you-mean suggestion searches. It includes the
// undocumented site command so that a maintainer's typo is corrected too.
var commandNames = []string{
	"serve", "verify", "report", "coverage", "inspect", "export",
	"retention", "keys", "archive-verify", "erase", "repair", "site", "version",
}

// Main dispatches the multi-command binary and returns a process exit code.
func Main(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	var err error
	switch args[0] {
	case "serve":
		err = Serve(args[1:])
	case "verify":
		err = Verify(args[1:])
	case "report":
		err = Report(args[1:])
	case "coverage":
		err = Coverage(args[1:])
	case "inspect":
		err = Inspect(args[1:])
	case "export":
		err = Export(args[1:])
	case "retention":
		err = Retention(args[1:])
	case "keys":
		err = Keys(args[1:])
	case "archive-verify":
		err = ArchiveVerify(args[1:])
	case "erase":
		err = Erase(args[1:])
	case "repair":
		err = Repair(args[1:])
	case "site":
		err = Site(args[1:])
	case "version":
		PrintVersion()
		return 0
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "flugschreiber: unknown command %q\n", args[0])
		if s := nearestCommand(args[0]); s != "" {
			fmt.Fprintf(os.Stderr, "Did you mean %q?\n", s)
		}
		fmt.Fprintf(os.Stderr, "\n%s", usage)
		return 2
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "flugschreiber: %v\n", err)
		return 1
	}
	return 0
}

// nearestCommand returns the command closest to s, or the empty string when
// nothing is close. Two edits is the cutoff: past that, a suggestion is a
// guess, and a wrong guess in front of an erase-capable binary is worse than
// no guess.
func nearestCommand(s string) string {
	best, bestDist := "", 3
	for _, c := range commandNames {
		if d := editDistance(s, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between two ASCII command words.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

// PrintVersion writes the build identity to stdout.
func PrintVersion() {
	fmt.Printf("flugschreiber %s\n", version.String())
	if version.Date != "" {
		fmt.Printf("built %s\n", version.Date)
	}
}
