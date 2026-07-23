package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/config"
	"github.com/flugschreiber/flugschreiber/internal/report"
	"github.com/flugschreiber/flugschreiber/internal/version"
)

func Report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber report [flags]

Reads an evidence directory and generates documentation artifacts pre-filled
from the traffic that was actually observed:

  technical-documentation.md        Annex IV-shaped skeleton
  transparency-article-50-en.md     Article 50 transparency pack, English
  transparency-article-50-de.md     Article 50 transparency pack, German

Sections that can be filled in from evidence and configuration are filled in.
Everything else is marked TODO with one sentence on what belongs there. The
output is documentation input, not a compliance statement.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir        = fs.String("dir", "", "evidence directory to read (required)")
		out        = fs.String("out", "reports", "directory to write the artifacts into")
		configPath = fs.String("config", "", "JSON config file to read deployment metadata from")
		org        = fs.String("organisation", "", "organisation name")
		system     = fs.String("system-name", "", "system name")
		purpose    = fs.String("purpose", "", "intended purpose of the system")
		contact    = fs.String("contact", "", "accountable contact")
		role       = fs.String("role", "", "role under the AI Act: provider, deployer, importer or distributor")
		env        = fs.String("environment", "", "environment the evidence came from")
		mode       = fs.String("content-mode", "", "content mode to describe (defaults to the mode seen in the log)")
		retention  = fs.Int("retention-days", 0, "retention to describe (default 180)")
		nowFlag    = fs.String("now", "", "override the generation timestamp, RFC3339 (for reproducible output)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("report: --dir is required")
	}

	cfg := config.Default()
	if *configPath != "" {
		if err := cfg.LoadFile(*configPath); err != nil {
			return err
		}
	}
	if err := cfg.ApplyEnv(); err != nil {
		return err
	}
	setString(&cfg.Deployment.Organisation, *org)
	setString(&cfg.Deployment.SystemName, *system)
	setString(&cfg.Deployment.Purpose, *purpose)
	setString(&cfg.Deployment.Contact, *contact)
	setString(&cfg.Deployment.Role, *role)
	setString(&cfg.Deployment.Environment, *env)
	setString(&cfg.ContentMode, *mode)
	if *retention != 0 {
		cfg.RetentionDays = *retention
	}

	now := time.Now()
	if *nowFlag != "" {
		parsed, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			return fmt.Errorf("report: --now: %w", err)
		}
		now = parsed
	}

	summary, err := report.Summarise(*dir, now)
	if err != nil {
		return err
	}

	// The mode recorded in the log is authoritative over the mode configured
	// now: the documentation should describe what was actually captured, not
	// what the current flags happen to say.
	contentMode := cfg.ContentMode
	if *mode == "" && len(summary.ContentModes) > 0 {
		contentMode = summary.ContentModes[0].Name
	}

	generated, err := report.Generate(report.Input{
		Summary:        summary,
		Deployment:     cfg.Deployment,
		ContentMode:    contentMode,
		RedactPatterns: cfg.RedactPatterns,
		RetentionDays:  cfg.RetentionDays,
		DataDir:        *dir,
		Version:        version.String(),
		Now:            now,
	})
	if err != nil {
		return err
	}

	paths, err := generated.Write(*out)
	if err != nil {
		return err
	}

	fmt.Printf("generated %d artifact(s) from %d record(s):\n\n", len(paths), summary.Records)
	for i, p := range paths {
		fmt.Printf("  %-46s %s\n", p, generated.Artifacts[i].Title)
	}

	fmt.Printf("\n")
	if summary.ChainVerified {
		fmt.Printf("  evidence chain    intact (%d records, %s)\n", summary.Records, summary.Window())
	} else {
		fmt.Printf("  evidence chain    FAILED VERIFICATION — see section 3.4 of the technical documentation\n")
	}
	if summary.Observed() {
		fmt.Printf("  models observed   %s\n", modelList(summary))
		fmt.Printf("  content mode      %s\n", contentMode)
	} else {
		fmt.Printf("  no inference traffic recorded — most sections are marked TODO\n")
	}

	todos := countTODOs(generated)
	fmt.Printf("\n%d section(s) need a human. They are marked TODO with a note on what belongs there.\n", todos)
	fmt.Printf("These artifacts are documentation inputs. They do not make anyone compliant.\n")
	return nil
}

func modelList(s *report.Summary) string {
	seen := map[string]bool{}
	var out []string
	for _, m := range s.Models {
		name := m.Served
		if name == "" {
			name = m.Requested
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

func countTODOs(g *report.Generated) int {
	n := 0
	for _, a := range g.Artifacts {
		n += strings.Count(string(a.Content), "**TODO:**")
	}
	return n
}
