package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/flugschreiber/flugschreiber/internal/evidence"
)

func Verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber verify [flags]

Checks that an evidence directory is internally consistent: every record hashes
to the value it carries, every record links to its predecessor, and no sequence
number is missing.

This reads only the files on disk. It needs no running server and no access to
the system that produced the log, so a third party can run it against a copy.

Exit status is 0 when the chain is intact and 1 when it is not.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "evidence directory to verify (required)")
		asJSON = fs.Bool("json", false, "emit the result as JSON")
		quiet  = fs.Bool("quiet", false, "print nothing; report the result through the exit status only")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("verify: --dir is required")
	}

	res, err := evidence.Verify(*dir)
	if err != nil {
		return err
	}

	switch {
	case *quiet:
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	default:
		printVerify(res)
	}

	if !res.OK() {
		os.Exit(1)
	}
	return nil
}

func printVerify(res *evidence.VerifyResult) {
	if res.OK() {
		fmt.Printf("hash chain intact\n\n")
	} else {
		fmt.Printf("HASH CHAIN VERIFICATION FAILED\n\n")
	}

	fmt.Printf("  directory   %s\n", res.Dir)
	fmt.Printf("  segments    %d\n", len(res.Segments))
	fmt.Printf("  records     %d\n", res.Records)
	if res.Records > 0 {
		fmt.Printf("  sequence    %d to %d\n", res.FirstSeq, res.LastSeq)
		fmt.Printf("  window      %s\n", res.FirstTime)
		fmt.Printf("              %s\n", res.LastTime)
		fmt.Printf("  head hash   %s\n", res.HeadHash)
	}
	fmt.Printf("  checked in  %s\n", res.Duration)

	if len(res.Problems) == 0 {
		return
	}

	fmt.Printf("\n%d problem(s) found:\n\n", len(res.Problems))
	var high int
	for _, p := range res.Problems {
		if p.Severity == evidence.SeverityHigh {
			high++
		}
		if p.Severity != "" {
			fmt.Printf("  [%s] %s\n", p.Severity, p)
			continue
		}
		fmt.Printf("  %s\n", p)
	}

	fmt.Printf("\nA broken chain does not by itself prove tampering, because an unclean\n")
	fmt.Printf("shutdown can truncate the final record. But the affected records can no\n")
	fmt.Printf("longer be relied on as evidence.\n")

	if high > 0 {
		fmt.Printf("\n%d problem(s) are high severity. A checkpoint that is validly signed\n", high)
		fmt.Printf("and disagrees with the chain, or a chain that contradicts its own prune\n")
		fmt.Printf("anchor, is what a rewritten log looks like. Preserve this directory as\n")
		fmt.Printf("it stands before doing anything else with it.\n")
	}
}
