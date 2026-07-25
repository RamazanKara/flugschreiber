package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Verify checks an evidence directory offline and reports through the exit
// status, which is what lets a CronJob or a script gate on it.
func Verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber verify [flags]

Checks that an evidence directory is internally consistent: every record hashes
to the value it carries, every record links to its predecessor, and no sequence
number is missing.

This reads only the files on disk. It needs no running server and no access to
the system that produced the log, so a third party can run it against a copy.

Exit status is 0 when the chain is intact and every check completed, 1 when the
chain is damaged, and 2 when verification could not be completed: the directory
is unreadable, or a key or a token needed for a check is not here. A scheduled
job that treats 2 as an outage rather than as tampering will be right.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "evidence directory to verify (required)")
		asJSON = fs.Bool("json", false, "emit the result as JSON")
		quiet  = fs.Bool("quiet", false, "print nothing; report the result through the exit status only")

		requireAttestation = fs.Bool("require-attestation", false,
			"fail when no checkpoint verifies; use it where the log is known to be signed, so removing the attestations is an error rather than a note")
		expectHead = fs.String("expect-head", "",
			"fail unless the chain head is this hash; compare against a head recorded somewhere the proxy cannot write to")
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

	// Both checks are the operator asserting something this directory cannot
	// know about itself: that it was signed, and what its head was when they
	// last looked. Neither can be inferred, which is why they are flags.
	if *requireAttestation && !res.Attested {
		res.Problems = append(res.Problems, evidence.Problem{
			Segment: evidence.CheckpointsFile,
			Kind:    evidence.ProblemAttestationsGone, Severity: evidence.SeverityHigh,
			Detail: "--require-attestation was given and no checkpoint both verified against a key here and matched the chain, so this log carries no attestation it can be held to",
		})
	}
	if *expectHead != "" && !strings.EqualFold(*expectHead, res.HeadHash) {
		res.Problems = append(res.Problems, evidence.Problem{
			Kind: evidence.ProblemCheckpointMismatch, Severity: evidence.SeverityHigh,
			Detail: fmt.Sprintf(
				"--expect-head was %s and this log heads at %s; if the expected value came from a place the proxy cannot write to, the log has been replaced",
				*expectHead, res.HeadHash),
		})
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

	switch {
	case res.OK():
	case !res.Intact():
		os.Exit(1)
	default:
		// Every problem was of the "could not check" kind, so the chain is
		// sound as far as it could be read. Saying 1 here would report
		// tampering because somebody forwarded a bundle without a key.
		os.Exit(2)
	}
	return nil
}

func printVerify(res *evidence.VerifyResult) {
	switch {
	case res.OK():
		fmt.Printf("hash chain intact\n\n")
	case !res.Intact():
		fmt.Printf("HASH CHAIN VERIFICATION FAILED\n\n")
	default:
		fmt.Printf("hash chain intact, but verification could not be completed\n\n")
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
	if res.Pruned {
		fmt.Printf("  pruned      through seq %d under a recorded anchor; unaltered since, not complete from the beginning\n", res.PrunedThroughSeq)
	}
	if res.Checkpoints > 0 {
		fmt.Printf("  checkpoints %d, %d verified against signature and chain\n", res.Checkpoints, res.CheckpointsVerified)
	}
	if res.Attested {
		fmt.Printf("  attestation attested, key id %s\n", res.KeyID)
	} else {
		fmt.Printf("  attestation none; the chain shows internal consistency only\n")
	}
	// Anchoring is reported only when there is anchoring, because a line saying
	// "none" on every log that never enabled it would read as a deficiency
	// rather than as a setting nobody chose.
	if res.Timestamps > 0 {
		fmt.Printf("  anchors     %d RFC 3161 token(s), %d matched to the checkpoint they cover\n",
			res.Timestamps, res.TimestampedCheckpoints)
		fmt.Printf("              the authority's own signature is not checked here; VERIFY.md has the openssl command\n")
	}
	fmt.Printf("  checked in  %s\n", res.Duration)

	// The notes carry the states the counters only hint at, and the most
	// important of them says the log carries no attestation at all.
	for _, n := range res.Notes {
		fmt.Printf("\n  note: %s\n", n)
	}

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
