package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/pdf"
	"github.com/RamazanKara/flugschreiber/internal/report"
)

// writePDFs renders each generated Markdown artifact as a PDF beside it.
//
// The Markdown stays the source of truth, as it does for the HTML pages. PDF
// exists because the person a compliance document is finally handed to often
// accepts nothing else, and asking an operator to install a converter at that
// moment is how documents end up rendered by whatever was closest.
func writePDFs(outDir, author, creator string, generated *report.Generated, now time.Time) (paths, warnings []string, err error) {
	for _, a := range generated.Artifacts {
		if !strings.HasSuffix(a.Filename, ".md") {
			continue
		}

		lang := "en"
		if strings.HasSuffix(strings.TrimSuffix(a.Filename, ".md"), "-de") {
			lang = "de"
		}

		name := strings.TrimSuffix(a.Filename, ".md") + ".pdf"
		path := filepath.Join(outDir, name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, err
		}

		subs, renderErr := pdf.Render(f, pdf.ParseMarkdown(a.Content), pdf.Options{
			Title:   a.Title,
			Author:  author,
			Creator: creator,
			Lang:    lang,
			// The report timestamp, not the wall clock, so that --now produces
			// byte-identical PDFs the way it does for Markdown and HTML.
			Created: now,
		})
		closeErr := f.Close()
		if renderErr != nil {
			return nil, nil, fmt.Errorf("report: render %s: %w", name, renderErr)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("report: write %s: %w", name, closeErr)
		}

		paths = append(paths, path)
		if len(subs) > 0 {
			total := 0
			for _, s := range subs {
				total += s.Count
			}
			warnings = append(warnings, fmt.Sprintf(
				"%s: %d character(s) have no glyph in the PDF base fonts and were printed as [U+XXXX] markers; the Markdown file remains authoritative", name, total))
		}
	}
	return paths, warnings, nil
}
