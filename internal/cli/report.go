package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/report"
	"github.com/RamazanKara/flugschreiber/internal/version"
)

// Report generates the documentation artifacts from an evidence directory.
func Report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber report [flags]

Reads an evidence directory and generates documentation artifacts pre-filled
from the traffic that was actually observed:

  technical-documentation.md        Annex IV-shaped skeleton (English)
  technical-documentation-de.md     Annex IV-shaped skeleton (German)
  transparency-article-50-en.md     Article 50 transparency pack, English
  transparency-article-50-de.md     Article 50 transparency pack, German

Use --lang to select editions: en, de, or both (the default). Each Markdown
document is also written as HTML, and with --pdf as PDF.

Each of those is also written as a standalone HTML page under the same name
with a .html extension, for reading and printing without a Markdown tool, and,
with --pdf, as a PDF. The Markdown is the source of truth; the other renderings
carry no additional content.

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
		pdfFlag    = fs.Bool("pdf", false, "also render each document as a PDF, using only the built-in base fonts")
		lang       = fs.String("lang", "both", "language editions to produce: en, de, or both")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("report: --dir is required")
	}
	if !report.ValidLang(*lang) {
		return fmt.Errorf("report: --lang %q must be en, de, or both", *lang)
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
		Lang:           *lang,
	})
	if err != nil {
		return err
	}

	paths, err := generated.Write(*out)
	if err != nil {
		return err
	}

	var pdfWarnings []string
	if *pdfFlag {
		pdfPaths, warnings, err := writePDFs(*out, cfg.Deployment.Organisation, "Flugschreiber "+version.String(), generated, now)
		if err != nil {
			return err
		}
		paths = append(paths, pdfPaths...)
		pdfWarnings = warnings
	}

	fmt.Printf("generated %d artifact(s) from %d record(s):\n\n", len(paths), summary.Records)
	for i, p := range paths {
		title := ""
		if i < len(generated.Artifacts) {
			title = generated.Artifacts[i].Title
		} else {
			title = "PDF rendering"
		}
		fmt.Printf("  %-46s %s\n", p, title)
	}
	for _, w := range pdfWarnings {
		fmt.Printf("\n  warning: %s\n", w)
	}

	fmt.Printf("\n")
	if summary.ChainVerified {
		fmt.Printf("  evidence chain    intact (%d records, %s)\n", summary.Records, summary.Window())
	} else {
		fmt.Printf("  evidence chain    FAILED VERIFICATION, see section 3.4 of the technical documentation\n")
	}
	if summary.Observed() {
		fmt.Printf("  models observed   %s\n", modelList(summary))
		fmt.Printf("  content mode      %s\n", contentMode)
	} else {
		fmt.Printf("  no inference traffic recorded, so most sections are marked TODO\n")
	}

	fmt.Printf("\n%d section(s) need a human. They are marked TODO with a note on what belongs there.\n", generated.TODOs())
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
