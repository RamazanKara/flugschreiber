package pdf

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, src string) []Block {
	t.Helper()
	return ParseMarkdown([]byte(src)).Blocks
}

func TestParseMarkdownRecognisesEachBlockKind(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []Block
	}{
		{
			name: "heading",
			src:  "## 1. General description\n",
			want: []Block{Heading{Level: 2, Text: []Span{{Text: "1. General description"}}}},
		},
		{
			name: "paragraph joins its lines",
			src:  "Article 19 expects logs\nto be kept for six months.\n",
			want: []Block{Paragraph{Text: []Span{{Text: "Article 19 expects logs to be kept for six months."}}}},
		},
		{
			name: "fenced code keeps its lines verbatim",
			src:  "```\nflugschreiber verify --dir x\n  indented\n```\n",
			want: []Block{Code{Lines: []string{"flugschreiber verify --dir x", "  indented"}}},
		},
		{
			name: "thematic break",
			src:  "---\n",
			want: []Block{Rule{}},
		},
		{
			name: "blockquote with two paragraphs",
			src:  "> First warning.\n>\n> Second warning.\n",
			want: []Block{Quote{Blocks: []Block{
				Paragraph{Text: []Span{{Text: "First warning."}}},
				Paragraph{Text: []Span{{Text: "Second warning."}}},
			}}},
		},
		{
			name: "bullet list",
			src:  "- one\n- two\n",
			want: []Block{List{Start: 1, Items: []Item{
				{Blocks: []Block{Paragraph{Text: []Span{{Text: "one"}}}}},
				{Blocks: []Block{Paragraph{Text: []Span{{Text: "two"}}}}},
			}}},
		},
		{
			name: "numbered list keeps its first number",
			src:  "3. three\n4. four\n",
			want: []Block{List{Ordered: true, Start: 3, Items: []Item{
				{Blocks: []Block{Paragraph{Text: []Span{{Text: "three"}}}}},
				{Blocks: []Block{Paragraph{Text: []Span{{Text: "four"}}}}},
			}}},
		},
		{
			name: "list item with a follow-on paragraph",
			src:  "- first line\n  wrapped\n\n  second paragraph\n- next item\n",
			want: []Block{List{Start: 1, Items: []Item{
				{Blocks: []Block{
					Paragraph{Text: []Span{{Text: "first line wrapped"}}},
					Paragraph{Text: []Span{{Text: "second paragraph"}}},
				}},
				{Blocks: []Block{Paragraph{Text: []Span{{Text: "next item"}}}}},
			}}},
		},
		{
			name: "table with alignment",
			src:  "| Model | Requests |\n| --- | ---: |\n| a | 2 |\n",
			want: []Block{Table{
				Header: []Cell{{Text: []Span{{Text: "Model"}}}, {Text: []Span{{Text: "Requests"}}}},
				Rows:   [][]Cell{{{Text: []Span{{Text: "a"}}}, {Text: []Span{{Text: "2"}}}}},
				Align:  []Align{AlignLeft, AlignRight},
			}},
		},
		{
			name: "checkbox items stay literal text",
			src:  "- [ ] Hinweis erscheint zuerst\n",
			want: []Block{List{Start: 1, Items: []Item{
				{Blocks: []Block{Paragraph{Text: []Span{{Text: "[ ] Hinweis erscheint zuerst"}}}}},
			}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parse(t, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parsed\n got %#v\nwant %#v", got, tc.want)
			}
		})
	}
}

func TestInlineMarkupBecomesStyledSpans(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []Span
	}{
		{"plain", "nothing here", []Span{{Text: "nothing here"}}},
		{"bold", "**TODO:** do it", []Span{{Text: "TODO:", Style: Bold}, {Text: " do it"}}},
		{"italic", "marked *observed* here", []Span{{Text: "marked "}, {Text: "observed", Style: Italic}, {Text: " here"}}},
		{"code", "the `hash` mode", []Span{{Text: "the "}, {Text: "hash", Style: Mono}, {Text: " mode"}}},
		{"italic inside bold", "**a *b* c**", []Span{
			{Text: "a ", Style: Bold},
			{Text: "b", Style: Bold | Italic},
			{Text: " c", Style: Bold},
		}},
		// Emphasis that opens or closes against a space is left alone, so
		// bold inside italic is not recognised. That is the documented
		// trade for never mangling a stray asterisk in generated prose.
		{"bold inside italic is left literal", "*a **b** c*", []Span{
			{Text: "*a "},
			{Text: "b", Style: Bold},
			{Text: " c*"},
		}},
		{"markers inside code are literal", "`**not bold**`", []Span{{Text: "**not bold**", Style: Mono}}},
		{"link keeps its target visible", "see [MAPPING.md](https://x.invalid/m)", []Span{
			{Text: "see "},
			{Text: "MAPPING.md"},
			{Text: " (https://x.invalid/m)"},
		}},
		{"a bracketed reference is not a link", "see annex [1] and the rest", []Span{{Text: "see annex [1] and the rest"}}},
		{"a bracketed reference does not swallow a later link", "annex [1] and [MAPPING.md](m.md)", []Span{
			{Text: "annex [1] and "},
			{Text: "MAPPING.md"},
			{Text: " (m.md)"},
		}},
		{"escaped marker", `a \* b`, []Span{{Text: "a * b"}}},
		{"stray asterisk stays literal", "2 * 3 = 6", []Span{{Text: "2 * 3 = 6"}}},
		{"unclosed bold stays literal", "**unclosed", []Span{{Text: "**unclosed"}}},
		{"umlauts survive", "Prüfen Sie „das“", []Span{{Text: "Prüfen Sie „das“"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inline(tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("inline(%q) =\n got %#v\nwant %#v", tc.src, got, tc.want)
			}
		})
	}
}

func TestParsingKeepsEveryWordOfTheFixture(t *testing.T) {
	src := string(mustRead(t, "testdata/sample.md"))
	doc := ParseMarkdown([]byte(src))

	var got strings.Builder
	var walk func([]Block)
	walk = func(bs []Block) {
		for _, b := range bs {
			switch v := b.(type) {
			case Heading:
				got.WriteString(plain(v.Text) + " ")
			case Paragraph:
				got.WriteString(plain(v.Text) + " ")
			case Code:
				got.WriteString(strings.Join(v.Lines, " ") + " ")
			case Quote:
				walk(v.Blocks)
			case List:
				for _, it := range v.Items {
					walk(it.Blocks)
				}
			case Table:
				for _, c := range v.Header {
					got.WriteString(plain(c.Text) + " ")
				}
				for _, row := range v.Rows {
					for _, c := range row {
						got.WriteString(plain(c.Text) + " ")
					}
				}
			}
		}
	}
	walk(doc.Blocks)
	parsed := got.String()

	// Every word of the source must survive parsing. Markup punctuation is
	// excluded by starting each word at a letter or a digit.
	words := regexp.MustCompile(`[\p{L}\p{N}][\p{L}\p{N}._/@:-]*`)
	found := 0
	for _, word := range words.FindAllString(src, -1) {
		if !strings.Contains(parsed, word) {
			t.Errorf("the word %q from the source is not in any parsed block", word)
		}
		found++
	}
	if found < 200 {
		t.Fatalf("only %d words were checked, the fixture or the extraction is not doing its job", found)
	}
}

func TestParserMakesProgressOnAwkwardInput(t *testing.T) {
	cases := []string{
		"",
		"\n\n\n",
		"|",
		"| a |",
		"```\nunterminated fence",
		">",
		"- ",
		"#",
		"####### too deep",
		"1.",
		strings.Repeat("> ", 50) + "deep",
		"| a | b |\n| --- | --- |",
	}
	for i, src := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			done := make(chan []Block, 1)
			go func() { done <- ParseMarkdown([]byte(src)).Blocks }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("parsing %q did not terminate", src)
			}
		})
	}
}
