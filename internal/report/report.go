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

	"github.com/RamazanKara/flugschreiber/internal/config"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// Format names a rendering of a document. Every document is written twice, and
// a caller counting gaps or listing what it produced has to be able to tell the
// source from the page built out of it.
const (
	FormatMarkdown = "markdown"
	FormatHTML     = "html"
)

// Artifact is one generated document in one rendering.
type Artifact struct {
	Filename string
	Title    string
	Format   string // FormatMarkdown or FormatHTML
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

	// Lang selects which language editions to produce: "en", "de", or "both".
	// Empty means both, which is the historical behaviour.
	Lang string
}

// Generated is the full set of documents from one run.
type Generated struct {
	Artifacts []Artifact
}

// Language selectors accepted by Generate and the report command.
const (
	LangEnglish = "en"
	LangGerman  = "de"
	LangBoth    = "both"
)

// ValidLang reports whether l is an accepted language selector.
func ValidLang(l string) bool {
	switch l {
	case LangEnglish, LangGerman, LangBoth:
		return true
	}
	return false
}

var artifacts = []struct {
	template string
	filename string
	title    string
	lang     string
}{
	{"technical-documentation.md.tmpl", "technical-documentation.md", "Annex IV technical documentation skeleton", "en"},
	{"technical-documentation-de.md.tmpl", "technical-documentation-de.md", "Annex IV technical documentation skeleton (German)", "de"},
	{"transparency-en.md.tmpl", "transparency-article-50-en.md", "Article 50 transparency pack (English)", "en"},
	{"transparency-de.md.tmpl", "transparency-article-50-de.md", "Article 50 transparency pack (German)", "de"},
}

// wants reports whether an artifact in the given language should be produced for
// the requested selector. An empty selector means both, so an unset Input.Lang
// keeps the historical behaviour of emitting every edition.
func wants(selector, lang string) bool {
	switch selector {
	case "", LangBoth:
		return true
	default:
		return selector == lang
	}
}

// Generate renders every artifact for the requested language.
func Generate(in Input) (*Generated, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	in.Now = in.Now.UTC()

	out := &Generated{}
	var langs []string
	for _, a := range artifacts {
		if !wants(in.Lang, a.lang) {
			continue
		}
		langs = append(langs, a.lang)
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
			Format:   FormatMarkdown,
			Content:  normalise(buf.Bytes()),
		})
	}

	// Each document is also rendered to a standalone HTML page. The Markdown
	// stays the source of truth, so the pages are appended after it rather than
	// interleaved: the first artifacts are still the documents themselves.
	pages := make([]Artifact, 0, len(out.Artifacts))
	for i, a := range out.Artifacts {
		page, err := RenderHTML(a.Content, HTMLOptions{
			Title:      a.Title,
			Lang:       langs[i],
			SourceFile: a.Filename,
			Version:    in.Version,
			Generated:  in.Now,
		})
		if err != nil {
			return nil, err
		}
		pages = append(pages, Artifact{
			Filename: strings.TrimSuffix(a.Filename, ".md") + ".html",
			// The page carries the document's own title inside it, taken from
			// the Markdown heading. The artifact title is what an operator sees
			// in a list of files, so it has to say which of the two this is.
			Title:   a.Title + ", HTML rendering",
			Format:  FormatHTML,
			Content: page,
		})
	}
	out.Artifacts = append(out.Artifacts, pages...)

	return out, nil
}

// TODOs counts the passages that still need a human.
//
// Only the Markdown documents are counted. Each HTML page is a rendering of one
// of them and carries the same markers, so counting every artifact would report
// each gap twice and tell an operator to go and fill in work that does not
// exist.
func (g *Generated) TODOs() int {
	n := 0
	for _, a := range g.Artifacts {
		if a.Format == FormatMarkdown {
			n += strings.Count(string(a.Content), todoMarker)
		}
	}
	return n
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
		// orNA fills a table cell the log had no value for. It reads the same in
		// Markdown, in the rendered page and when a cell is read aloud, which a
		// dash does not.
		"orNA": func(s string) string {
			if s == "" {
				return "n/a"
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
