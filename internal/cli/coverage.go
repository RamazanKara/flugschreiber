package cli

import (
	"flag"
	"fmt"

	"github.com/RamazanKara/flugschreiber/internal/audit"
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
		dir      = fs.String("dir", "", "evidence directory to analyse (or FLUGSCHREIBER_DATA_DIR)")
		asJSON   = fs.Bool("json", false, "emit the result as JSON")
		gapAfter = fs.Duration("gap-threshold", audit.DefaultGapThreshold,
			"report stretches with no records longer than this")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "coverage", dir); err != nil {
		return err
	}

	c, err := audit.Analyse(*dir, *gapAfter)
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(c)
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
