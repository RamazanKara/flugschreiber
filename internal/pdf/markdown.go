package pdf

import (
	"strconv"
	"strings"
)

// ParseMarkdown reads the Markdown subset the generated documents are written
// in and returns a document ready to render.
//
// It is not a CommonMark implementation and does not try to be. It handles
// headings, paragraphs, fenced code, blockquotes, pipe tables, bullet and
// numbered lists, thematic breaks, and inline bold, italic, code and links.
// Anything else survives as literal text rather than being reinterpreted,
// because in a document that will be filed as evidence a character that
// arrives unchanged is better than a character a parser was clever about.
//
// Emphasis has to hug its text, so an asterisk with a space beside it stays an
// asterisk. Italic can therefore appear inside bold but not the other way
// round. Nested lists and setext headings are not recognised.
func ParseMarkdown(src []byte) Doc {
	s := strings.TrimPrefix(string(src), "\uFEFF")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return Doc{Blocks: parseBlocks(strings.Split(s, "\n"))}
}

func parseBlocks(lines []string) []Block {
	var out []Block
	for i := 0; i < len(lines); {
		l := lines[i]
		switch {
		case isBlank(l):
			i++
		case isFence(l):
			out, i = appendCode(out, lines, i)
		case headingLevel(l) > 0:
			level := headingLevel(l)
			text := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(l), "#"))
			out = append(out, Heading{Level: level, Text: inline(text)})
			i++
		case isThematicBreak(l):
			out = append(out, Rule{})
			i++
		case isQuote(l):
			out, i = appendQuote(out, lines, i)
		case isTableRow(l) && i+1 < len(lines) && isDelimiterRow(lines[i+1]):
			out, i = appendTable(out, lines, i)
		case listItemAt(l).ok:
			out, i = appendList(out, lines, i)
		default:
			out, i = appendParagraph(out, lines, i)
		}
	}
	return out
}

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }

func indentOf(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

func isFence(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")
}

func headingLevel(s string) int {
	t := strings.TrimSpace(s)
	n := 0
	for n < len(t) && t[n] == '#' {
		n++
	}
	if n == 0 || n > 6 || n >= len(t) || t[n] != ' ' {
		return 0
	}
	return n
}

func isThematicBreak(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 3 {
		return false
	}
	c := t[0]
	if c != '-' && c != '*' && c != '_' {
		return false
	}
	return strings.Count(t, string(c)) == len(t)
}

func isQuote(s string) bool {
	t := strings.TrimLeft(s, " \t")
	return strings.HasPrefix(t, ">")
}

func isTableRow(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "|") }

func isDelimiterRow(s string) bool {
	cells := splitRow(s)
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		c = strings.TrimSpace(c)
		c = strings.TrimPrefix(c, ":")
		c = strings.TrimSuffix(c, ":")
		if c == "" || strings.Trim(c, "-") != "" {
			return false
		}
	}
	return true
}

// startsBlock reports whether a line would begin a new block, and so must not
// be swallowed as the continuation of a paragraph.
func startsBlock(s string) bool {
	return isBlank(s) || isFence(s) || headingLevel(s) > 0 || isThematicBreak(s) ||
		isQuote(s) || isTableRow(s) || listItemAt(s).ok
}

func appendCode(out []Block, lines []string, i int) ([]Block, int) {
	marker := strings.TrimSpace(lines[i])[:3]
	i++
	var body []string
	for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), marker) {
		body = append(body, lines[i])
		i++
	}
	if i < len(lines) {
		i++ // closing fence
	}
	return append(out, Code{Lines: body}), i
}

func appendQuote(out []Block, lines []string, i int) ([]Block, int) {
	var body []string
	for i < len(lines) {
		if isQuote(lines[i]) {
			t := strings.TrimLeft(lines[i], " \t")
			t = t[1:]
			body = append(body, strings.TrimPrefix(t, " "))
			i++
			continue
		}
		// A non-blank line straight after a quoted line continues it.
		// Tolerating this costs nothing and matches what people write.
		if len(body) > 0 && !isBlank(lines[i]) && !startsBlock(lines[i]) {
			body = append(body, lines[i])
			i++
			continue
		}
		break
	}
	return append(out, Quote{Blocks: parseBlocks(body)}), i
}

func appendTable(out []Block, lines []string, i int) ([]Block, int) {
	header := cellsOf(splitRow(lines[i]))
	aligns := alignsOf(splitRow(lines[i+1]))
	i += 2
	var rows [][]Cell
	for i < len(lines) && isTableRow(lines[i]) {
		rows = append(rows, cellsOf(splitRow(lines[i])))
		i++
	}
	return append(out, Table{Header: header, Rows: rows, Align: aligns}), i
}

func cellsOf(raw []string) []Cell {
	out := make([]Cell, len(raw))
	for i, c := range raw {
		out[i] = Cell{Text: inline(strings.TrimSpace(c))}
	}
	return out
}

func alignsOf(raw []string) []Align {
	out := make([]Align, len(raw))
	for i, c := range raw {
		c = strings.TrimSpace(c)
		left := strings.HasPrefix(c, ":")
		right := strings.HasSuffix(c, ":")
		switch {
		case left && right:
			out[i] = AlignCenter
		case right:
			out[i] = AlignRight
		default:
			out[i] = AlignLeft
		}
	}
	return out
}

// splitRow divides a pipe table row into cells, honouring a backslash escaped
// pipe so a cell can contain one.
func splitRow(s string) []string {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, "|")
	t = strings.TrimSuffix(t, "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(t); i++ {
		if t[i] == '\\' && i+1 < len(t) && t[i+1] == '|' {
			cur.WriteByte('|')
			i++
			continue
		}
		if t[i] == '|' {
			cells = append(cells, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(t[i])
	}
	cells = append(cells, cur.String())
	return cells
}

// itemMark describes a list marker found at the start of a line.
type itemMark struct {
	ok      bool
	indent  int // columns before the marker
	content int // columns before the item text
	ordered bool
	number  int
}

func listItemAt(s string) itemMark {
	ind := indentOf(s)
	if ind > 3 {
		return itemMark{}
	}
	rest := s[ind:]
	if len(rest) >= 2 && (rest[0] == '-' || rest[0] == '*' || rest[0] == '+') && rest[1] == ' ' {
		return itemMark{ok: true, indent: ind, content: ind + 2}
	}
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	if n > 0 && n+1 < len(rest) && (rest[n] == '.' || rest[n] == ')') && rest[n+1] == ' ' {
		v, _ := strconv.Atoi(rest[:n])
		return itemMark{ok: true, indent: ind, content: ind + n + 2, ordered: true, number: v}
	}
	return itemMark{}
}

func appendList(out []Block, lines []string, i int) ([]Block, int) {
	first := listItemAt(lines[i])
	list := List{Ordered: first.ordered, Start: first.number}
	if !list.Ordered {
		list.Start = 1
	}
	for i < len(lines) {
		m := listItemAt(lines[i])
		if !m.ok || m.ordered != list.Ordered {
			break
		}
		raw := []string{lines[i][m.content:]}
		i++
		for i < len(lines) {
			if isBlank(lines[i]) {
				j := i
				for j < len(lines) && isBlank(lines[j]) {
					j++
				}
				// A blank line only stays inside the item if what
				// follows is indented under it.
				if j < len(lines) && indentOf(lines[j]) >= m.content && !listItemAt(lines[j]).ok {
					raw = append(raw, "")
					i = j
					continue
				}
				break
			}
			if listItemAt(lines[i]).ok {
				break
			}
			if indentOf(lines[i]) >= m.content {
				raw = append(raw, lines[i][m.content:])
				i++
				continue
			}
			if !startsBlock(lines[i]) {
				raw = append(raw, strings.TrimSpace(lines[i]))
				i++
				continue
			}
			break
		}
		list.Items = append(list.Items, Item{Blocks: parseBlocks(raw)})
	}
	return append(out, list), i
}

func appendParagraph(out []Block, lines []string, i int) ([]Block, int) {
	parts := []string{strings.TrimSpace(lines[i])}
	i++
	for i < len(lines) && !startsBlock(lines[i]) {
		parts = append(parts, strings.TrimSpace(lines[i]))
		i++
	}
	return append(out, Paragraph{Text: inline(strings.Join(parts, " "))}), i
}

// inline splits a line into styled spans.
func inline(s string) []Span { return inlineStyled(s, 0) }

func inlineStyled(s string, base Style) []Span {
	var out []Span
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, Span{Text: lit.String(), Style: base})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			lit.WriteByte(s[i+1])
			i += 2
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:], '`'); j > 0 {
				flush()
				out = append(out, Span{Text: s[i+1 : i+1+j], Style: base | Mono})
				i += j + 2
				continue
			}
			lit.WriteByte(s[i])
			i++
		case strings.HasPrefix(s[i:], "**"):
			if j := strings.Index(s[i+2:], "**"); j > 0 {
				flush()
				out = append(out, inlineStyled(s[i+2:i+2+j], base|Bold)...)
				i += j + 4
				continue
			}
			lit.WriteString("**")
			i += 2
		case s[i] == '*':
			// Require the emphasis to hug its text, so that a stray
			// asterisk in prose stays an asterisk.
			if j := strings.IndexByte(s[i+1:], '*'); j > 0 && s[i+1] != ' ' && s[i+j] != ' ' {
				flush()
				out = append(out, inlineStyled(s[i+1:i+1+j], base|Italic)...)
				i += j + 2
				continue
			}
			lit.WriteByte(s[i])
			i++
		case s[i] == '[':
			if text, url, n, ok := matchLink(s[i:]); ok {
				flush()
				out = append(out, inlineStyled(text, base)...)
				out = append(out, Span{Text: " (" + url + ")", Style: base})
				i += n
				continue
			}
			lit.WriteByte(s[i])
			i++
		default:
			lit.WriteByte(s[i])
			i++
		}
	}
	flush()
	return out
}

// matchLink matches [text](url) at the start of s. The URL is kept and printed
// after the text, because a link a reader cannot see is a reference lost the
// moment the document is printed.
//
// Only the first closing bracket can end the link text. Searching for the
// first "](" anywhere in the line would let a plain bracketed reference such
// as "[1]" swallow everything up to the next real link.
func matchLink(s string) (text, url string, n int, ok bool) {
	sep := strings.IndexByte(s, ']')
	if sep < 1 || sep+1 >= len(s) || s[sep+1] != '(' {
		return "", "", 0, false
	}
	end := strings.IndexByte(s[sep+2:], ')')
	if end < 0 {
		return "", "", 0, false
	}
	return s[1:sep], s[sep+2 : sep+2+end], sep + 2 + end + 1, true
}
