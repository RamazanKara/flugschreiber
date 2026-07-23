package report

import (
	"html"
	"sort"
	"strings"
	"testing"
)

// allowedTags is every tag the renderer is permitted to produce. The escaping
// tests assert that no input can add to this set, which is the property that
// matters: an injected tag in a document that goes to a regulator is a real
// vulnerability, not a cosmetic bug.
var allowedTags = map[string]bool{
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"p": true, "hr": true, "blockquote": true, "pre": true, "code": true,
	"div": true, "table": true, "thead": true, "tbody": true, "tr": true,
	"th": true, "td": true, "ul": true, "ol": true, "li": true, "input": true,
	"strong": true, "em": true, "a": true,
	// the page shell
	"html": true, "head": true, "meta": true, "title": true, "style": true,
	"body": true, "article": true, "nav": true, "footer": true,
}

// tagsIn returns every tag name in the document, including closing tags.
func tagsIn(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		j := i + 1
		if j < len(s) && s[j] == '/' {
			j++
		}
		start := j
		for j < len(s) && isTagByte(s[j]) {
			j++
		}
		if j > start {
			out = append(out, strings.ToLower(s[start:j]))
		}
	}
	sort.Strings(out)
	return out
}

func isTagByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// textOf strips markup and resolves entities, leaving what a reader sees.
func textOf(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '<':
			depth++
		case s[i] == '>' && depth > 0:
			depth--
		case depth == 0:
			b.WriteByte(s[i])
		}
	}
	return html.UnescapeString(b.String())
}

// renderAll renders a document and puts the title back in front of the body,
// which is what a page template does.
func renderAll(src string) string {
	doc := RenderMarkdown([]byte(src))
	return doc.TitleHTML + doc.Body
}

func assertOnlyAllowedTags(t *testing.T, out string) {
	t.Helper()
	for _, tag := range tagsIn(out) {
		if !allowedTags[tag] {
			t.Errorf("renderer emitted the tag %q, which no input is allowed to introduce\n%s", tag, out)
		}
	}
}

func TestHostileInputNeverBecomesMarkup(t *testing.T) {
	// Every value here reaches a document through configuration or through
	// recorded traffic, so all of it is attacker-influenceable in practice.
	tests := []struct {
		name     string
		markdown string
		survives string
	}{
		{
			name:     "script tag in a paragraph",
			markdown: "<script>alert(1)</script>",
			survives: "<script>alert(1)</script>",
		},
		{
			name:     "event handler in a table cell",
			markdown: "| Field | Value |\n| --- | --- |\n| Organisation | <img src=x onerror=alert(1)> |",
			survives: "<img src=x onerror=alert(1)>",
		},
		{
			name:     "tag in a heading",
			markdown: "# <svg onload=alert(1)>Acme",
			survives: "<svg onload=alert(1)>Acme",
		},
		{
			name:     "tag inside a code span",
			markdown: "The model `<b onmouseover=alert(1)>x</b>` was served.",
			survives: "<b onmouseover=alert(1)>x</b>",
		},
		{
			name:     "fence break-out attempt",
			markdown: "```\n</code></pre><script>alert(1)</script>\n```",
			survives: "</code></pre><script>alert(1)</script>",
		},
		{
			name:     "tag inside bold",
			markdown: "**<iframe src=evil></iframe>**",
			survives: "<iframe src=evil></iframe>",
		},
		{
			name:     "tag inside a TODO callout",
			markdown: "> **TODO:** name the system <script>alert(1)</script>",
			survives: "<script>alert(1)</script>",
		},
		{
			name:     "tag inside a task list item",
			markdown: "- [ ] <object data=evil></object>",
			survives: "<object data=evil></object>",
		},
		{
			name:     "raw html block",
			markdown: "<div onclick=\"steal()\">hello</div>",
			survives: "<div onclick=\"steal()\">hello</div>",
		},
		{
			name:     "attribute breakout in a link destination",
			markdown: `[click](https://example.test/a"onmouseover="alert(1))`,
			survives: "click",
		},
		{
			name:     "quotes in a contact address",
			markdown: `Contact: "><script>alert(1)</script>`,
			survives: `"><script>alert(1)</script>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := renderAll(tc.markdown)
			assertOnlyAllowedTags(t, out)
			if got := textOf(out); !strings.Contains(got, tc.survives) {
				t.Errorf("hostile input was altered or dropped instead of shown as text\n want text containing: %q\n got: %q", tc.survives, got)
			}
			if strings.Contains(out, "<script") || strings.Contains(out, "onerror=") && !strings.Contains(out, "&lt;") {
				t.Errorf("unescaped markup reached the output:\n%s", out)
			}
		})
	}
}

func TestExecutableLinkSchemesAreRefused(t *testing.T) {
	tests := []struct {
		name     string
		markdown string
		wantLink bool
	}{
		{"javascript", "[click](javascript:alert(1))", false},
		{"javascript mixed case", "[click](JaVaScRiPt:alert(1))", false},
		{"data url", "[click](data:text/html;base64,PHNjcmlwdD4=)", false},
		{"vbscript", "[click](vbscript:msgbox(1))", false},
		{"file", "[click](file:///etc/passwd)", false},
		{"image with a javascript destination", "![alt](javascript:alert(1))", false},
		{"https", "[click](https://example.test/x)", true},
		{"http", "[click](http://example.test/x)", true},
		{"mailto", "[mail](mailto:ai@example.test)", true},
		{"fragment", "[section](#3-4-integrity-mechanism)", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte(tc.markdown)).Body
			if got := strings.Contains(out, "<a href="); got != tc.wantLink {
				t.Errorf("link rendered = %v, want %v\n%s", got, tc.wantLink, out)
			}
			for _, scheme := range []string{"javascript:", "data:", "vbscript:", "file:"} {
				if strings.Contains(out, `href="`+scheme) {
					t.Errorf("a %s destination survived into an href:\n%s", scheme, out)
				}
			}
			if !tc.wantLink && !strings.Contains(textOf(out), "click") && !strings.Contains(textOf(out), "alt") {
				t.Errorf("a refused link lost its text instead of degrading to plain text:\n%s", out)
			}
		})
	}
}

// These pages promise to fetch nothing when they are opened. A destination
// beginning with two slashes names another host and borrows whatever scheme the
// page was opened with, so it is an external request with the scheme left off
// rather than a relative path. Browsers read a backslash in a URL as a slash,
// which is why the variants are here too.
func TestProtocolRelativeDestinationsAreRefused(t *testing.T) {
	tests := []struct {
		name     string
		markdown string
		wantLink bool
	}{
		{"two slashes", "[click](//evil.test/x)", false},
		{"slash backslash", `[click](/\evil.test/x)`, false},
		{"two backslashes", `[click](\\evil.test\x)`, false},
		{"backslash slash", `[click](\/evil.test/x)`, false},
		{"an ordinary absolute path still links", "[click](/reports/index.html)", true},
		{"a relative path still links", "[click](./technical-documentation.html)", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte(tc.markdown)).Body
			if got := strings.Contains(out, "<a href="); got != tc.wantLink {
				t.Errorf("link rendered = %v, want %v\n%s", got, tc.wantLink, out)
			}
			if !tc.wantLink && !strings.Contains(textOf(out), "click") {
				t.Errorf("a refused link lost its text instead of degrading to plain text:\n%s", out)
			}
			if strings.Contains(out, "evil.test") && !tc.wantLink && strings.Contains(out, "href=") {
				t.Errorf("an external host survived into an href:\n%s", out)
			}
		})
	}
}

func TestHeadingsGetUniqueAnchorsAndAppearInHeadings(t *testing.T) {
	doc := RenderMarkdown([]byte("# Title\n\n## 3.4 Integrity mechanism\n\n### Retention\n\n## Retention\n"))

	want := []Heading{
		{Level: 1, Text: "Title", ID: "title"},
		{Level: 2, Text: "3.4 Integrity mechanism", ID: "3-4-integrity-mechanism"},
		{Level: 3, Text: "Retention", ID: "retention"},
		{Level: 2, Text: "Retention", ID: "retention-2"},
	}
	if len(doc.Headings) != len(want) {
		t.Fatalf("got %d headings, want %d: %+v", len(doc.Headings), len(want), doc.Headings)
	}
	for i := range want {
		if doc.Headings[i] != want[i] {
			t.Errorf("heading %d = %+v, want %+v", i, doc.Headings[i], want[i])
		}
	}
	if doc.Title != "Title" || !strings.Contains(doc.TitleHTML, "<h1 ") {
		t.Errorf("the level-1 heading was not split out: title=%q titleHTML=%q", doc.Title, doc.TitleHTML)
	}
	if strings.Contains(doc.Body, "<h1 ") {
		t.Error("the title is still in the body, so a page template would render it twice")
	}
}

func TestHeadingTextInTheTableOfContentsHasNoMarkup(t *testing.T) {
	doc := RenderMarkdown([]byte("## **TODO:** name `the` *system*\n"))
	if got := doc.Headings[0].Text; got != "TODO: name the system" {
		t.Errorf("heading text = %q, want the plain text with markup removed", got)
	}
}

func TestTableAlignmentBecomesAClass(t *testing.T) {
	tests := []struct {
		name      string
		delimiter string
		want      string
	}{
		{"default", "| --- |", "<th>"},
		{"left", "| :--- |", `<th class="left">`},
		{"right", "| ---: |", `<th class="right">`},
		{"centre", "| :---: |", `<th class="center">`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte("| Requests |\n" + tc.delimiter + "\n| 5 |\n")).Body
			if !strings.Contains(out, tc.want) {
				t.Errorf("want a header cell rendered as %s\n%s", tc.want, out)
			}
		})
	}
}

func TestTableRowsAreAlignedToTheHeader(t *testing.T) {
	out := RenderMarkdown([]byte("| A | B | C |\n| --- | --- | --- |\n| 1 |\n| 1 | 2 | 3 | 4 |\n")).Body
	if n := strings.Count(out, "<td"); n != 6 {
		t.Errorf("got %d body cells, want 6: short rows pad and long rows fold\n%s", n, out)
	}
}

// A configured value is free to contain a pipe, and the templates do not escape
// one. The row still has to line up with its header, but nothing the reader was
// meant to see is allowed to disappear on the way.
func TestAnUnescapedPipeInAValueDoesNotDeleteText(t *testing.T) {
	tests := []struct {
		name string
		md   string
		want string
	}{
		{
			name: "escaped pipe stays one cell",
			md:   "| Field | Value |\n| --- | --- |\n| Organisation | Data \\| Analytics GmbH |\n",
			want: "Data | Analytics GmbH",
		},
		{
			name: "unescaped pipe folds into the last column",
			md:   "| Field | Value |\n| --- | --- |\n| Organisation | Data | Analytics GmbH |\n",
			want: "Data | Analytics GmbH",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte(tc.md)).Body
			if n := strings.Count(out, "<td"); n != 2 {
				t.Errorf("got %d body cells, want 2: the row must line up with the header\n%s", n, out)
			}
			if got := textOf(out); !strings.Contains(got, tc.want) {
				t.Errorf("want the cell text %q, got %q", tc.want, got)
			}
		})
	}
}

// The fence info string is the only input that reaches a class attribute, so it
// is the only place where a value could break out of an attribute.
func TestFenceInfoStringCannotBreakOutOfTheClassAttribute(t *testing.T) {
	tests := []struct {
		name string
		info string
		want string
	}{
		{"plain language", "go", `<pre><code class="language-go">`},
		{"language followed by attributes", `go title="x"`, `<pre><code class="language-go">`},
		{"language followed by a highlight range", "go {1,3-5}", `<pre><code class="language-go">`},
		{"empty", "", "<pre><code>"},
		{"only attributes", `title="x"`, "<pre><code>"},
		{"quote and attribute", `go" onmouseover="alert(1)`, "<pre><code>"},
		{"angle bracket", "go><script", "<pre><code>"},
		{"overlong", strings.Repeat("a", 33), "<pre><code>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte("```" + tc.info + "\nx\n```\n")).Body
			if !strings.HasPrefix(out, tc.want) {
				t.Errorf("want the block to open with %s\n%s", tc.want, out)
			}
			assertOnlyAllowedTags(t, out)
		})
	}
}

func TestFencedCodeIsNotInterpretedAsMarkdown(t *testing.T) {
	out := RenderMarkdown([]byte("```\n**not bold** and `not code` and | not | a | table |\n```\n")).Body
	if strings.Contains(out, "<strong>") || strings.Contains(out, "<table>") {
		t.Errorf("fence contents were interpreted:\n%s", out)
	}
	if !strings.Contains(out, "**not bold** and `not code`") {
		t.Errorf("fence contents were altered:\n%s", out)
	}
}

func TestListsRenderAccordingToTheirShape(t *testing.T) {
	tests := []struct {
		name     string
		markdown string
		want     []string
		absent   []string
	}{
		{
			name:     "tight bullet list stays inline",
			markdown: "- one\n- two\n",
			want:     []string{"<ul>", "<li>one</li>"},
			absent:   []string{"<p>one</p>"},
		},
		{
			name:     "ordered list keeps its numbering element",
			markdown: "1. one\n2. two\n",
			want:     []string{"<ol>", "<li>one</li>", "<li>two</li>"},
		},
		{
			name:     "continuation lines belong to their item",
			markdown: "- one\n  still one\n- two\n",
			want:     []string{"<li>one\nstill one</li>"},
		},
		{
			name:     "a blank line inside an item makes the whole list loose",
			markdown: "- one\n\n  second paragraph\n- two\n",
			want:     []string{"<p>one</p>", "<p>second paragraph</p>", "<p>two</p>"},
		},
		{
			name:     "a nested bullet list becomes a nested list",
			markdown: "- one\n  - nested a\n  - nested b\n- two\n",
			want:     []string{"<li>one\n<ul>\n<li>nested a</li>\n<li>nested b</li>\n</ul>\n</li>"},
			absent:   []string{"- nested a"},
		},
		{
			name:     "a nested ordered list keeps its own numbering element",
			markdown: "1. one\n   1. nested\n2. two\n",
			want:     []string{"<li>one\n<ol>\n<li>nested</li>\n</ol>\n</li>"},
			absent:   []string{"1. nested"},
		},
		{
			name:     "list kinds can be mixed across the nesting",
			markdown: "- one\n  1. nested\n- two\n",
			want:     []string{"<ul>", "<ol>", "<li>nested</li>"},
			absent:   []string{"1. nested"},
		},
		{
			name:     "nesting goes deeper than one level",
			markdown: "- one\n  - two\n    - three\n",
			want:     []string{"<li>three</li>"},
			absent:   []string{"- two", "- three"},
		},
		{
			name:     "text after a nested list stays with the parent item",
			markdown: "- one\n  - nested\n- two\n",
			want:     []string{"<li>two</li>"},
		},
		{
			name:     "a nested list inside a loose item is still a list",
			markdown: "- one\n\n  - nested\n- two\n",
			want:     []string{"<p>one</p>", "<li>nested</li>"},
			absent:   []string{"- nested"},
		},
		{
			name:     "task items become disabled checkboxes",
			markdown: "- [ ] open\n- [x] done\n",
			want: []string{
				`<ul class="task-list">`,
				`<li class="task"><input type="checkbox" disabled> open</li>`,
				`<li class="task"><input type="checkbox" disabled checked> done</li>`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte(tc.markdown)).Body
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in\n%s", w, out)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(out, a) {
					t.Errorf("unexpected %q in\n%s", a, out)
				}
			}
		})
	}
}

func TestTodoCalloutsAreMarkedForTheStylesheet(t *testing.T) {
	out := RenderMarkdown([]byte("> **TODO:** describe the oversight step\n\n> A plain note.\n")).Body
	if !strings.Contains(out, `<blockquote class="todo">`) {
		t.Errorf("a TODO callout must be distinguishable from an ordinary quote:\n%s", out)
	}
	if strings.Count(out, "<blockquote>") != 1 {
		t.Errorf("an ordinary quote must not be marked as a TODO:\n%s", out)
	}
	if !strings.Contains(out, `<strong class="gap">TODO:</strong>`) {
		t.Errorf("the inline TODO marker must be marked too, because fill() emits it inside table cells:\n%s", out)
	}
}

func TestBlockquoteKeepsItsInternalParagraphs(t *testing.T) {
	out := RenderMarkdown([]byte("> first\n>\n> second\n")).Body
	if strings.Count(out, "<p>") != 2 {
		t.Errorf("a quote separated by a bare marker is two paragraphs:\n%s", out)
	}
}

func TestUnsupportedConstructsSurviveAsText(t *testing.T) {
	// The subset is bounded on purpose. Anything outside it has to remain
	// visible to a reader rather than vanish, because a silently dropped
	// sentence in a compliance document is worse than an ugly one.
	tests := []struct {
		name     string
		markdown string
		survives string
	}{
		{"setext heading", "Title\n=====\n", "Title\n====="},
		{"image", "![a diagram](diagram.png)", "![a diagram](diagram.png)"},
		{"footnote reference", "See the note.[^1]", "[^1]"},
		{"html comment", "<!-- internal note -->", "<!-- internal note -->"},
		{"definition list", "Term\n:   definition\n", ":   definition"},
		{"unterminated fence", "```\nstill shown\n", "still shown"},
		{"autolink", "See <https://example.test/x>.", "<https://example.test/x>"},
		{"reference link", "See [the annex][annex].", "[the annex][annex]"},
		{"strikethrough", "This is ~~wrong~~ right.", "~~wrong~~"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown([]byte(tc.markdown)).Body
			assertOnlyAllowedTags(t, out)
			if got := textOf(out); !strings.Contains(got, tc.survives) {
				t.Errorf("want text containing %q, got %q", tc.survives, got)
			}
		})
	}
}

func TestRenderMarkdownIsDeterministic(t *testing.T) {
	src := []byte("# T\n\n## A\n\n## A\n\n| x | y |\n| ---: | :--- |\n| 1 | 2 |\n\n- [ ] a\n- [x] b\n\n> **TODO:** something\n")
	first := RenderMarkdown(src)
	for i := 0; i < 50; i++ {
		again := RenderMarkdown(src)
		if again.Body != first.Body || again.TitleHTML != first.TitleHTML {
			t.Fatal("two renders of the same Markdown produced different HTML")
		}
	}
}

func TestThematicBreakIsNotConfusedWithTableSyntax(t *testing.T) {
	out := RenderMarkdown([]byte("text\n\n---\n\n| a |\n| --- |\n| 1 |\n")).Body
	if strings.Count(out, "<hr>") != 1 {
		t.Errorf("want exactly one horizontal rule\n%s", out)
	}
	if !strings.Contains(out, "<table>") {
		t.Errorf("the table delimiter row was treated as a rule\n%s", out)
	}
}
