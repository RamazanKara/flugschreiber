package pdf

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func lineText(l line) string {
	var b []byte
	for _, r := range l.runs {
		b = append(b, r.b...)
	}
	return string(b)
}

// contentStreams returns the body of every content stream in a rendered file,
// which for these documents is one per page.
func contentStreams(t *testing.T, data []byte) []string {
	t.Helper()
	s, err := parsePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := 1; i <= s.size; i++ {
		body, ok := s.objects[i]
		if !ok {
			continue
		}
		if j := bytes.Index(body, []byte("\nstream\n")); j >= 0 {
			out = append(out, string(body[j+len("\nstream\n"):]))
		}
	}
	return out
}

var showText = regexp.MustCompile(`\(((?:[^()\\]|\\.)*)\) Tj`)

// pageText returns the text of every show operator in content order, joined by
// a single space. It is enough to find a notice the layout wrapped over several
// lines, which searching a raw stream for a phrase is not.
func pageText(t *testing.T, data []byte) string {
	t.Helper()
	var parts []string
	for _, s := range contentStreams(t, data) {
		for _, m := range showText.FindAllStringSubmatch(s, -1) {
			parts = append(parts, m[1])
		}
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

type point struct{ x, y float64 }

var (
	textMatrix = regexp.MustCompile(`1 0 0 1 (-?[\d.]+) (-?[\d.]+) Tm`)
	rectOp     = regexp.MustCompile(`q ([\d.]+) g (-?[\d.]+) (-?[\d.]+) ([\d.]+) ([\d.]+) re f Q`)
)

func textOrigins(stream string) []point {
	var out []point
	for _, m := range textMatrix.FindAllStringSubmatch(stream, -1) {
		x, _ := strconv.ParseFloat(m[1], 64)
		y, _ := strconv.ParseFloat(m[2], 64)
		out = append(out, point{x, y})
	}
	return out
}

func TestWrappingNeverExceedsTheColumnWidth(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		width float64
	}{
		{"prose", "Article 19 expects automatically generated logs to be kept for at least six months where they are under the provider's control.", 200},
		{"german prose", "Die folgenden Textbausteine sind Entwurfsgrundlagen, keine Rechtsberatung und keine freigegebenen Texte.", 140},
		{"one long token", strings.Repeat("b7f3", 40), 120},
		{"token then prose", "hash " + strings.Repeat("a", 200) + " end", 90},
		{"narrow column", "Model requested", 30},
		{"single character column", "abcdef", 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := wrap(tokenize(Text(tc.text), 10, 0, nil), tc.width)
			if len(lines) == 0 {
				t.Fatal("wrapping produced no lines")
			}
			for i, l := range lines {
				// A line holding a single character may exceed the
				// column, because there is nowhere narrower to put it.
				if l.w > tc.width && len(lineText(l)) > 1 {
					t.Errorf("line %d is %.1f wide, column is %.1f: %q", i, l.w, tc.width, lineText(l))
				}
			}
		})
	}
}

func TestWrappingKeepsEveryCharacter(t *testing.T) {
	cases := []struct{ name, text string }{
		{"german prose", "Prüfen Sie den Wortlaut, „so wie hier zitiert“, und halten Sie das Ergebnis fest."},
		{"one long token", strings.Repeat("0123456789", 12)},
		{"runs of spaces", "a b  c   d"},
		{"trailing spaces", "trailing spaces   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := strings.Join(strings.Fields(string(encode(tc.text, nil))), "")
			var got strings.Builder
			for _, l := range wrap(tokenize(Text(tc.text), 10, 0, nil), 60) {
				got.WriteString(strings.Join(strings.Fields(lineText(l)), ""))
			}
			if got.String() != want {
				t.Errorf("wrapping lost or invented characters:\n got %q\nwant %q", got.String(), want)
			}
		})
	}
}

func TestWrappingPreservesInlineStyleBoundaries(t *testing.T) {
	spans := []Span{
		{Text: "The mode is "},
		{Text: "hash", Style: Mono},
		{Text: " and it is "},
		{Text: "the default", Style: Bold},
		{Text: "."},
	}
	lines := wrap(tokenize(spans, 10, 0, nil), 1000)
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %d", len(lines))
	}
	var styles []Style
	for _, r := range lines[0].runs {
		styles = append(styles, r.style)
	}
	want := []Style{0, Mono, 0, Bold, 0}
	if !slices.Equal(styles, want) {
		t.Errorf("runs carry styles %v, want %v", styles, want)
	}
}

func TestSplittingAnOverlongWordAlwaysMakesProgress(t *testing.T) {
	a := atom{b: []byte("abcdef"), size: 10}
	for _, width := range []float64{0, -5, 0.1, 1, 3} {
		head, tail := splitAt(a, width)
		if len(head.b) == 0 {
			t.Fatalf("splitting at width %v produced an empty head, which would loop forever", width)
		}
		if len(head.b)+len(tail.b) != len(a.b) {
			t.Fatalf("splitting at width %v lost characters", width)
		}
	}
}

func TestTableHeaderRepeatsAfterAPageBreak(t *testing.T) {
	rows := make([][]Cell, 90)
	for i := range rows {
		rows[i] = []Cell{{Text: Text(fmt.Sprintf("row %d", i))}, {Text: Text("value")}}
	}
	doc := Doc{Blocks: []Block{Table{
		Header: []Cell{{Text: Text("Kopfzeile")}, {Text: Text("Wert")}},
		Rows:   rows,
	}}}
	data, _ := render(t, doc, Options{Title: "Tabelle"})
	streams := contentStreams(t, data)
	if len(streams) < 2 {
		t.Fatalf("the table was expected to span pages, it fit on %d", len(streams))
	}
	for i, s := range streams {
		if !strings.Contains(s, escapeForContent("Kopfzeile")) {
			t.Errorf("page %d continues the table without its header, which makes the columns unreadable", i+1)
		}
	}
}

func TestNoTextIsPlacedOutsideTheMargins(t *testing.T) {
	opt := Options{Title: "Sample", Lang: "de", Created: fixedTime}
	data, _ := render(t, sampleDoc(t), opt)
	full := opt.withDefaults()
	// The footer sits inside the bottom margin by design; nothing may go
	// below its baseline, and nothing may cross the other three edges.
	minY := full.MarginBottom + 3
	maxY := full.Size.Height - full.MarginTop
	maxX := full.Size.Width - full.MarginRight
	for i, s := range contentStreams(t, data) {
		for _, p := range textOrigins(s) {
			if p.y < minY || p.y > maxY {
				t.Errorf("page %d places text at y=%.1f, outside the %.1f to %.1f band", i+1, p.y, minY, maxY)
			}
			if p.x < full.MarginLeft-0.01 || p.x > maxX {
				t.Errorf("page %d places text at x=%.1f, outside the %.1f to %.1f margins", i+1, p.x, full.MarginLeft, maxX)
			}
		}
	}
}

func TestCodeBlockShrinksToFitBeforeBreakingALine(t *testing.T) {
	cmd := "flugschreiber verify --dir /var/lib/flugschreiber --format json --strict"
	data, _ := render(t, Doc{Blocks: []Block{Code{Lines: []string{cmd}}}}, Options{Title: "x"})
	if !bytes.Contains(data, []byte(escapeForContent(cmd))) {
		t.Error("a command that would fit if the block were shrunk was broken instead, which makes it easy to copy wrongly")
	}
}

func TestAnUnbreakableCodeLineIsMarkedWhereItContinues(t *testing.T) {
	data, _ := render(t, Doc{Blocks: []Block{Code{Lines: []string{strings.Repeat("x", 400)}}}}, Options{Title: "x"})
	// The mark is a guillemot in the gutter, outside the code itself, so it
	// cannot be mistaken for a character the author wrote.
	if !bytes.Contains(data, []byte(`(\273)`)) {
		t.Error("a broken code line carries no continuation mark, so a reader cannot tell the break from a real newline")
	}
}

func TestQuoteRuleIsDrawnOnEveryPageTheQuoteTouches(t *testing.T) {
	var inner []Block
	for i := 0; i < 60; i++ {
		inner = append(inner, Paragraph{Text: Text(fmt.Sprintf("Hinweis %d, mit genug Text, um die Seite zu fuellen und einen Umbruch zu erzwingen.", i))})
	}
	data, _ := render(t, Doc{Blocks: []Block{Quote{Blocks: inner}}}, Options{Title: "x"})
	streams := contentStreams(t, data)
	if len(streams) < 2 {
		t.Fatalf("expected the quote to span pages, it fit on %d", len(streams))
	}
	for i, s := range streams {
		found := false
		for _, m := range rectOp.FindAllStringSubmatch(s, -1) {
			if w, _ := strconv.ParseFloat(m[4], 64); w == quoteBarWidth {
				found = true
			}
		}
		if !found {
			t.Errorf("page %d shows part of a blockquote with no rule beside it", i+1)
		}
	}
}

// A bullet on one page and its text on the next reads as two separate
// mistakes. The item's first block runs a larger ensure than one body line, so
// there is a band of remaining space that clears the bullet's requirement and
// not the item's, and the boundary has to be swept to land in it.
func TestABulletIsNeverLeftOnThePageBeforeItsItem(t *testing.T) {
	const itemHeading = "Abschnitt im Listeneintrag"
	const itemBody = "Der zugehoerige Text des Eintrags."

	for fillers := 20; fillers <= 60; fillers++ {
		blocks := make([]Block, 0, fillers+1)
		for i := 0; i < fillers; i++ {
			blocks = append(blocks, Paragraph{Text: Text(fmt.Sprintf("Fuellabsatz %d.", i))})
		}
		blocks = append(blocks, List{Items: []Item{{Blocks: []Block{
			Heading{Level: 2, Text: Text(itemHeading)},
			Paragraph{Text: Text(itemBody)},
		}}}})

		data, _ := render(t, Doc{Blocks: blocks}, Options{Title: "x"})
		bulletPage, headingPage := -1, -1
		for i, s := range contentStreams(t, data) {
			if strings.Contains(s, `(\225)`) {
				bulletPage = i
			}
			if strings.Contains(s, escapeForContent(itemHeading)) {
				headingPage = i
			}
		}
		if bulletPage < 0 {
			t.Fatalf("%d fillers: the bullet was never drawn", fillers)
		}
		if bulletPage != headingPage {
			t.Errorf("%d fillers: the bullet is on page %d and the item it marks starts on page %d",
				fillers, bulletPage+1, headingPage+1)
		}
	}
}

// The bullet sits on the baseline of the line it marks, whatever size that
// line is set at, rather than on a baseline guessed from the body leading.
func TestABulletSitsOnTheBaselineOfTheLineItMarks(t *testing.T) {
	doc := Doc{Blocks: []Block{List{Items: []Item{
		{Blocks: []Block{Paragraph{Text: Text("Ein gewoehnlicher Eintrag.")}}},
		{Blocks: []Block{Heading{Level: 3, Text: Text("Eintrag mit Ueberschrift")}}},
	}}}}
	data, _ := render(t, doc, Options{Title: "x"})
	streams := contentStreams(t, data)
	if len(streams) != 1 {
		t.Fatalf("expected one page, got %d", len(streams))
	}

	origins := textOrigins(streams[0])
	bullets := map[float64]int{}
	texts := map[float64]int{}
	for _, m := range regexp.MustCompile(`1 0 0 1 (-?[\d.]+) (-?[\d.]+) Tm\n(\([^\n]*\)) Tj`).FindAllStringSubmatch(streams[0], -1) {
		y, _ := strconv.ParseFloat(m[2], 64)
		if m[3] == `(\225)` {
			bullets[y]++
			continue
		}
		texts[y]++
	}
	if len(origins) == 0 || len(bullets) != 2 {
		t.Fatalf("expected two bullets, found %d", len(bullets))
	}
	for y := range bullets {
		if texts[y] == 0 {
			t.Errorf("a bullet sits at y=%.2f with no text on that baseline", y)
		}
	}
}

// Silently dropping a table from a document offered as evidence is the same
// failure as silently dropping cells from one.
func TestATableThatCannotBeLaidOutSaysSoOnThePage(t *testing.T) {
	wide := make([]Cell, 16)
	for i := range wide {
		wide[i] = Cell{Text: Text(fmt.Sprintf("c%d", i))}
	}

	tests := []struct {
		name  string
		opt   Options
		table Table
		want  []string
	}{
		{
			name: "more columns than the padding fits in",
			// The narrowest column validate allows: sixteen columns need 128
			// points of padding alone.
			opt:   Options{Title: "x", MarginLeft: 237, MarginRight: 237},
			table: Table{Header: wide, Rows: [][]Cell{wide}},
			want:  []string{"table of 16 columns omitted", "128 points"},
		},
		{
			name:  "no columns at all",
			opt:   Options{Title: "x"},
			table: Table{},
			want:  []string{"table omitted", "no columns"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := Doc{Blocks: []Block{
				Paragraph{Text: Text("davor")},
				tt.table,
				Paragraph{Text: Text("danach")},
			}}
			data, _ := render(t, doc, tt.opt)
			text := pageText(t, data)
			for _, w := range tt.want {
				if !strings.Contains(text, w) {
					t.Errorf("the page does not say %q, so the table went missing without a word:\n%s", w, text)
				}
			}
			// The blocks either side are still there, so the notice stands in
			// for the table rather than replacing the page.
			for _, w := range []string{"davor", "danach"} {
				if !strings.Contains(text, w) {
					t.Errorf("%q was lost along with the table", w)
				}
			}
		})
	}
}

func TestNumFormatsCoordinatesTheSameEverywhere(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{10.5, "10.5"},
		{595.276, "595.28"},
		{0.125, "0.12"}, // ties go to even, which is what strconv does

		{-3.5, "-3.5"},
		{100, "100"},
	}
	for _, tc := range cases {
		if got := num(tc.in); got != tc.want {
			t.Errorf("num(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandTabsKeepsCodeAligned(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\tb", "a   b"},
		{"\tindent", "    indent"},
		{"ab\tc", "ab  c"},
		{"no tabs", "no tabs"},
	}
	for _, tc := range cases {
		if got := expandTabs(tc.in); got != tc.want {
			t.Errorf("expandTabs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
