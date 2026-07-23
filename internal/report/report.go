// Package report turns an evidence log into the documentation artifacts an EU
// AI Act preparation effort needs as inputs.
//
// Nothing this package produces establishes compliance. It produces a filled-in
// starting point built from what actually happened on the wire, so that the
// people who do the compliance work argue with a draft instead of a blank page.
package report

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/config"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// Artifact is one generated document.
type Artifact struct {
	Filename string
	Title    string
	Content  []byte
}

// Input is everything the templates render from.
type Input struct {
	Summary        *Summary
	Deployment     config.Deployment
	ContentMode    string
	RedactPatterns []string
	RetentionDays  int
	DataDir        string
	Version        string
	Now            time.Time
}

// Generated is the full set of documents from one run.
type Generated struct {
	Artifacts []Artifact
}

var artifacts = []struct {
	template string
	filename string
	title    string
}{
	{"technical-documentation.md.tmpl", "technical-documentation.md", "Annex IV technical documentation skeleton"},
	{"transparency-en.md.tmpl", "transparency-article-50-en.md", "Article 50 transparency pack (English)"},
	{"transparency-de.md.tmpl", "transparency-article-50-de.md", "Article 50 transparency pack (German)"},
}

// Generate renders every artifact.
func Generate(in Input) (*Generated, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	in.Now = in.Now.UTC()

	out := &Generated{}
	for _, a := range artifacts {
		tmpl, err := template.New(a.template).Funcs(funcs()).ParseFS(templateFS, "templates/"+a.template)
		if err != nil {
			return nil, fmt.Errorf("report: parse %s: %w", a.template, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, in); err != nil {
			return nil, fmt.Errorf("report: render %s: %w", a.template, err)
		}
		out.Artifacts = append(out.Artifacts, Artifact{
			Filename: a.filename,
			Title:    a.title,
			Content:  normalise(buf.Bytes()),
		})
	}
	return out, nil
}

// Write saves the artifacts into dir.
func (g *Generated) Write(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(g.Artifacts))
	for _, a := range g.Artifacts {
		path := filepath.Join(dir, a.Filename)
		if err := os.WriteFile(path, a.Content, 0o640); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// normalise collapses runs of blank lines left by template conditionals, so
// the output looks hand-written rather than generated.
func normalise(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	var out []string
	blanks := 0
	for _, l := range lines {
		l = strings.TrimRight(l, " \t")
		if l == "" {
			blanks++
			if blanks > 1 {
				continue
			}
		} else {
			blanks = 0
		}
		out = append(out, l)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

func funcs() template.FuncMap {
	return template.FuncMap{
		// fill renders a configured value, or a clearly marked gap with one
		// sentence explaining what belongs there.
		"fill": func(value, guidance string) string {
			if strings.TrimSpace(value) != "" {
				return value
			}
			return "**TODO:** " + guidance
		},
		"todo": func(guidance string) string {
			return "> **TODO:** " + guidance
		},
		"date":  func(t time.Time) string { return t.Format("2006-01-02") },
		"stamp": func(t time.Time) string { return t.Format(time.RFC3339) },
		"join":  func(sep string, items []string) string { return strings.Join(items, sep) },
		"joinCounts": func(items []Count) string {
			parts := make([]string, 0, len(items))
			for _, c := range items {
				parts = append(parts, fmt.Sprintf("%s (%d)", c.Name, c.Count))
			}
			return strings.Join(parts, ", ")
		},
		"names": func(items []Count) string {
			parts := make([]string, 0, len(items))
			for _, c := range items {
				parts = append(parts, c.Name)
			}
			sort.Strings(parts)
			return strings.Join(parts, ", ")
		},
		"ms":  func(f float64) string { return fmt.Sprintf("%.1f ms", f) },
		"pct": percentString,
		"orNone": func(s string) string {
			if s == "" {
				return "none"
			}
			return s
		},
		"orDash": func(s string) string {
			if s == "" {
				return "—"
			}
			return s
		},
		"months": func(days int) string { return fmt.Sprintf("%.1f", float64(days)/30.0) },
	}
}

func percentString(part, total int) string {
	if total == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.0f%%", float64(part)*100/float64(total))
}
