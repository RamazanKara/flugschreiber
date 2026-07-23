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

Commands:
  serve     Run the recording proxy in front of an OpenAI-compatible endpoint
  verify    Check the integrity of an evidence directory (no server needed)
  report    Generate technical documentation and transparency artifacts
  export    Package the evidence as a bundle a third party can verify
  inspect   Reconstruct a session or request in readable form
  coverage  Report what was captured and at what fidelity
  retention Report on retention, enforce it, or place a legal hold
  keys      Show or rotate the checkpoint signing key
  archive-verify  Check that the archive holds every sealed segment
  erase     Destroy the stored content of a session (crypto-shredding)
  version   Print build information

Run "flugschreiber <command> -h" for the flags of a command.

Flugschreiber produces evidence and documentation inputs. It does not make
anyone compliant with anything, and it is not legal advice.
`

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
	case "version":
		PrintVersion()
		return 0
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "flugschreiber: unknown command %q\n\n%s", args[0], usage)
		return 2
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "flugschreiber: %v\n", err)
		return 1
	}
	return 0
}

// PrintVersion writes the build identity to stdout.
func PrintVersion() {
	fmt.Printf("flugschreiber %s\n", version.String())
	if version.Date != "" {
		fmt.Printf("built %s\n", version.Date)
	}
}
