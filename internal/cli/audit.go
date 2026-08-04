package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/audit"
	"github.com/RamazanKara/flugschreiber/internal/version"
)

// Coverage reports what share of recorded traffic was captured and at what
// fidelity.
func Coverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber coverage [flags]

Reports what is in an evidence log: how many records, at what content fidelity,
for which models and endpoints, and how complete the metadata is.

It surfaces the changes to the evidence itself, erasures, key rotations, repairs
and salt boundaries, so an audit can account for each. It also reports quiet
stretches, which are the only signal the log itself can give that the proxy may
not have been running.

It cannot report on traffic that never reached the proxy. Coverage of your
system is a network property, not something this command can observe.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir      = fs.String("dir", "", "evidence directory to analyse (required)")
		asJSON   = fs.Bool("json", false, "emit the result as JSON")
		gapAfter = fs.Duration("gap-threshold", audit.DefaultGapThreshold,
			"report stretches with no records longer than this")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("coverage: --dir is required")
	}

	c, err := audit.Analyse(*dir, *gapAfter)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}

	printCoverage(c)
	return nil
}

func printCoverage(c *audit.Coverage) {
	fmt.Printf("evidence coverage\n\n")
	fmt.Printf("  directory   %s\n", c.Dir)
	fmt.Printf("  records     %d\n", c.Records)
	if c.Records == 0 {
		fmt.Printf("\nNothing has been recorded in this directory.\n")
		return
	}
	fmt.Printf("  window      %s\n              %s\n", c.First, c.Last)
	if c.Duration != "" {
		fmt.Printf("  observed    %s\n", c.Duration)
	}
	if c.ChainVerified {
		fmt.Printf("  integrity   hash chain intact\n")
	} else {
		fmt.Printf("  integrity   FAILED, %d problem(s); run flugschreiber verify\n", c.ChainProblems)
	}

	section("records by type", c.ByEventType)
	if c.Inference > 0 {
		section("content fidelity", c.ByContentMode)
		section("endpoints", c.ByEndpoint)
		section("models", c.ByModel)
		section("status", c.ByStatusClass)

		fmt.Printf("\n  metadata completeness (of %d inference records)\n\n", c.Inference)
		completeness("token usage recorded", c.WithUsage, c.Inference)
		completeness("session id present", c.WithSession, c.Inference)
		completeness("caller identified", c.WithClient, c.Inference)
		completeness("model name recorded", c.WithModelName, c.Inference)
		fmt.Printf("    %-26s %d streamed, %d failed\n", "", c.Streamed, c.Failed)
	}

	if len(c.Lifecycle) > 0 {
		fmt.Printf("\n  changes to the evidence itself (%d)\n\n", len(c.Lifecycle))
		for _, l := range c.Lifecycle {
			who := ""
			if l.Actor != "" {
				who = " by " + l.Actor
			}
			sev := ""
			if l.Severity != "" {
				sev = " [" + l.Severity + "]"
			}
			fmt.Printf("    seq %d  %s%s%s\n", l.Seq, l.Type, sev, who)
			if l.Note != "" {
				fmt.Printf("      %s\n", truncate(l.Note, 76))
			}
		}
		fmt.Printf("\n  Erasures, rotations, repairs and salt changes are recorded here. An audit\n")
		fmt.Printf("  should account for each one.\n")
	}

	if len(c.Gaps) > 0 {
		fmt.Printf("\n  quiet stretches longer than %s\n\n", c.GapThreshold)
		for _, g := range c.Gaps {
			fmt.Printf("    %s of silence after seq %d (%s)\n", g.Duration, g.AfterSeq, g.After)
		}
		fmt.Printf("\n  A quiet stretch is not by itself a problem. It means either nothing was\n")
		fmt.Printf("  happening or the proxy was not recording. Only you can tell which.\n")
	}

	fmt.Printf("\n  This describes the log. It cannot describe traffic that bypassed the proxy.\n")
}

func section(title string, tallies []audit.Tally) {
	if len(tallies) == 0 {
		return
	}
	fmt.Printf("\n  %s\n\n", title)
	for _, t := range tallies {
		fmt.Printf("    %-40s %6d  %5.1f%%\n", truncate(t.Name, 40), t.Count, t.Percent)
	}
}

func completeness(label string, part, total int) {
	fmt.Printf("    %-26s %6d  %5.1f%%\n", label, part, audit.Percent(part, total))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Inspect reconstructs a session or a single request in readable form.
func Inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber inspect [flags]

Reconstructs what happened, in chain order: the model interactions and any human
decisions recorded around them.

How much can be shown depends on the content mode that was in force when the
records were written. In the default hash mode there is no transcript to show,
and the output says so rather than appearing empty.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir     = fs.String("dir", "", "evidence directory to read (required)")
		session = fs.String("session", "", "reconstruct one session by id")
		request = fs.String("request", "", "reconstruct one request, and anything referring to it")
		limit   = fs.Int("limit", 0, "stop after this many records (0 means no limit)")
		asJSON  = fs.Bool("json", false, "emit the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("inspect: --dir is required")
	}
	if *session != "" && *request != "" {
		return errors.New("inspect: use --session or --request, not both")
	}

	s, err := audit.Reconstruct(*dir, audit.Query{
		SessionID: *session,
		RequestID: *request,
		Limit:     *limit,
	})
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}

	var b strings.Builder
	s.Render(&b)
	fmt.Print(b.String())
	return nil
}

// Export writes an evidence bundle a third party can verify on their own
// machine.
func Export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber export [flags]

Writes a self-contained evidence bundle: the log segments, the signed
checkpoints, the public key, a manifest of SHA-256 digests, and instructions a
recipient can follow without knowing anything about this tool.

The signing key and the client identity salt are never included, so a recipient
can verify everything and reverse nothing.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir  = fs.String("dir", "", "evidence directory to export (required)")
		out  = fs.String("out", "", "path to write the bundle to (required)")
		note = fs.String("note", "", "a note to include in the bundle for its recipient")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		fs.Usage()
		return errors.New("export: --dir and --out are both required")
	}

	res, err := audit.Export(audit.ExportOptions{
		ToolVersion: version.String(),
		Dir:         *dir, Out: *out, Note: *note, Now: time.Now,
	})
	if err != nil {
		return err
	}

	m := res.Manifest

	// When the bundle itself is going to stdout, the summary cannot also go
	// there: the two interleave and the recipient gets an archive with prose
	// in the middle of it. Streaming out of a distroless pod is the shape the
	// Kubernetes handover uses, so it has to be the one that works.
	w := os.Stdout
	if isStreamPath(*out) {
		w = os.Stderr
	}
	fmt.Fprintf(w, "wrote %s\n\n", res.Path)
	fmt.Fprintf(w, "  files       %d (%s)\n", len(m.Files), humanBytes(m.TotalBytes))
	fmt.Fprintf(w, "  records     %d (sequence %d to %d)\n", m.Records, m.FirstSeq, m.LastSeq)
	if m.FirstRecord != "" {
		fmt.Fprintf(w, "  window      %s\n              %s\n", m.FirstRecord, m.LastRecord)
	}
	fmt.Fprintf(w, "  head hash   %s\n", m.HeadHash)
	if m.Checkpoints > 0 {
		fmt.Fprintf(w, "  checkpoints %d signed\n", m.Checkpoints)
	} else {
		fmt.Fprintf(w, "  checkpoints none; the chain shows internal consistency only\n")
	}
	if n := len(m.RetiredKeys); n > 0 {
		fmt.Fprintf(w, "  keys        %d retired public key(s) carried, so checkpoints signed before a rotation still verify\n", n)
	}
	if m.Timestamps > 0 {
		fmt.Fprintf(w, "  anchors     %d RFC 3161 token(s)\n", m.Timestamps)
	}
	if m.SealedRecords > 0 {
		fmt.Fprintf(w, "  sealed      %d record(s) carry encrypted content; the keys are not in the bundle\n", m.SealedRecords)
	}
	if m.Pruned {
		fmt.Fprintf(w, "  pruned      yes; pruned.json records what was removed and why\n")
	}
	if m.ChainVerified {
		fmt.Fprintf(w, "  integrity   verified intact at export\n")
	} else {
		fmt.Fprintf(w, "  integrity   FAILED at export, %d problem(s) recorded in the manifest\n", len(m.Problems))
	}

	fmt.Fprintf(w, "\nThe bundle contains no signing key, no client salt and no content keys.\n")
	return nil
}

// isStreamPath reports whether --out names a stream rather than a file to
// create. It mirrors the rule in internal/audit, deliberately by repeating it
// rather than exporting one: this decides where prose goes and that one decides
// how bytes are written, and they should be free to diverge.
func isStreamPath(out string) bool {
	return out == "-" || out == os.DevNull || strings.HasPrefix(filepath.ToSlash(out), "/dev/")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
