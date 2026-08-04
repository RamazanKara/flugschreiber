package cli

import (
	"errors"
	"flag"
	"fmt"

	"github.com/RamazanKara/flugschreiber/internal/site"
)

// Site builds the project website from the repository's own Markdown. It exists
// so that the site is a build artifact checked by the same suite as everything
// else, rather than a pile of hand-maintained HTML that drifts from the docs.
func Site(args []string) error {
	fs := flag.NewFlagSet("site", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber site --out DIR [flags]

Renders the project website into DIR, using the same Markdown renderer that
produces the compliance documents. The pages reference nothing external: no
CDN, no web font, no script. The build fails on a link that resolves nowhere.

This is a developer command, not part of an evidence workflow.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		out     = fs.String("out", "", "directory to write the site into (required)")
		root    = fs.String("root", ".", "repository root the Markdown is read from")
		version = fs.String("version", "", "release shown in the footer (default: newest in CHANGELOG.md)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		fs.Usage()
		return errors.New("site: --out is required")
	}

	if err := site.Build(site.Options{RepoRoot: *root, Out: *out, Version: *version}); err != nil {
		return err
	}
	fmt.Printf("built the site into %s\n", *out)
	return nil
}
