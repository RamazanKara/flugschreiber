package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// HTMLOptions describes the page built around a rendered Markdown document.
type HTMLOptions struct {
	// Title is used for the browser title when the document has no level-1
	// heading of its own.
	Title string
	// Lang is a BCP 47 tag for the html element. It defaults to "en". The
	// German pack sets "de" so that screen readers pronounce it and browsers
	// hyphenate it as German.
	Lang string
	// SourceFile names the Markdown the page was rendered from, so a reader
	// holding only the HTML knows which file is authoritative.
	SourceFile string
	Version    string
	Generated  time.Time
}

type pageData struct {
	Lang       string
	Title      string
	Version    string
	Generated  string
	SourceFile string
	TODOs      int
	Headings   []Heading
	Chrome     chrome
	TitleHTML  template.HTML
	Body       template.HTML
}

// chrome is the text the page contributes around the document, as opposed to
// the document itself. It is language-dependent because the packs are: a German
// transparency pack exists to be handed to a German reader, and English
// furniture around it is the kind of detail that stops a document being
// forwarded.
type chrome struct {
	// Contents titles the table of contents.
	Contents string
	// GapsOne and GapsMany follow the count of remaining TODO passages and
	// agree with it in number. GapsNote says what a reader should do about
	// them, and NoGaps replaces all three when there are none.
	GapsOne  string
	GapsMany string
	GapsNote string
	NoGaps   string
	// The colophon reads: From <file> With Flugschreiber <version> On
	// <timestamp>. SourceOfTruth Disclaimer
	From          string
	With          string
	On            string
	SourceOfTruth string
	Disclaimer    string
}

var chromeEN = chrome{
	Contents:      "Contents",
	GapsOne:       "passage in this document is marked TODO.",
	GapsMany:      "passages in this document are marked TODO.",
	GapsNote:      "Each one says what belongs there and needs a person who knows the system.",
	NoGaps:        "Nothing in this document is marked TODO.",
	From:          "Rendered from",
	With:          "by",
	On:            "on",
	SourceOfTruth: "The Markdown file is the source of truth; this page is a rendering of it and holds no additional content.",
	Disclaimer:    "This is a documentation input. It does not establish compliance, and it is not legal advice.",
}

var chromeDE = chrome{
	Contents:      "Inhaltsverzeichnis",
	GapsOne:       "Stelle in diesem Dokument ist mit TODO gekennzeichnet.",
	GapsMany:      "Stellen in diesem Dokument sind mit TODO gekennzeichnet.",
	GapsNote:      "Jede benennt, was dort einzutragen ist, und setzt eine Person voraus, die das System kennt.",
	NoGaps:        "Keine Stelle in diesem Dokument ist mit TODO gekennzeichnet.",
	From:          "Erzeugt aus",
	With:          "mit",
	On:            "am",
	SourceOfTruth: "Maßgeblich ist die Markdown-Datei; diese Seite gibt sie lediglich wieder und enthält keine zusätzlichen Inhalte.",
	Disclaimer:    "Dies ist eine Dokumentationsgrundlage. Sie stellt keine Konformität her und ist keine Rechtsberatung.",
}

// chromeFor picks the page furniture for a document's language tag. An
// untranslated language falls back to English rather than to nothing, because a
// label in the wrong language is a flaw and a missing label is a broken page.
func chromeFor(lang string) chrome {
	primary, _, _ := strings.Cut(lang, "-")
	if strings.EqualFold(primary, "de") {
		return chromeDE
	}
	return chromeEN
}

// RenderHTML renders a Markdown document as a standalone HTML page.
//
// The page carries its own stylesheet and references nothing external: no CDN,
// no web font, no script. These documents are emailed to people who will open
// them offline, and a compliance artifact that phones home when it is opened is
// both a privacy problem and a dependency on a server nobody promised to keep
// running. Output is a pure function of the input, because report generation is
// golden-file tested.
func RenderHTML(md []byte, opts HTMLOptions) ([]byte, error) {
	doc := RenderMarkdown(md)

	title := doc.Title
	if strings.TrimSpace(title) == "" {
		title = opts.Title
	}
	lang := opts.Lang
	if lang == "" {
		lang = "en"
	}

	// The level-1 heading is the document title and is already shown above the
	// contents, so listing it again would only add a line that points at itself.
	var toc []Heading
	for _, h := range doc.Headings {
		if h.Level >= 2 && h.Level <= 4 {
			toc = append(toc, h)
		}
	}

	generated := ""
	if !opts.Generated.IsZero() {
		generated = opts.Generated.UTC().Format(time.RFC3339)
	}

	data := pageData{
		Lang:       lang,
		Title:      title,
		Version:    opts.Version,
		Generated:  generated,
		SourceFile: opts.SourceFile,
		TODOs:      strings.Count(string(md), todoMarker),
		Headings:   toc,
		Chrome:     chromeFor(lang),
		// Marking these as trusted HTML is the one place in this package where
		// escaping is bypassed, and it is safe only because RenderMarkdown
		// escapes every byte of document text and emits nothing but the fixed
		// set of tags it constructs itself. Nothing else may be assigned here.
		TitleHTML: template.HTML(doc.TitleHTML),
		Body:      template.HTML(doc.Body),
	}

	tmpl, err := template.New("page.html.tmpl").ParseFS(templateFS, "templates/page.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("report: parse page.html.tmpl: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("report: render %s as HTML: %w", opts.SourceFile, err)
	}
	return buf.Bytes(), nil
}
