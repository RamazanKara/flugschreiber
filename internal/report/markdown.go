package report

import (
	"html"
	"strconv"
	"strings"
	"unicode"
)

// Heading is one heading found while rendering, with the anchor the renderer
// gave it.
type Heading struct {
	Level int
	Text  string // plain text, with inline markup removed
	ID    string
}

// Document is a Markdown document rendered to HTML. The first level-1 heading
// is kept separate from the rest so that a page template can put a table of
// contents between the document title and its body, which is where a reader of
// a printed report expects to find one.
type Document struct {
	Title     string // plain text of the first level-1 heading
	TitleHTML string // the rendered heading, empty if the document has none
	Body      string
	Headings  []Heading
}

// todoMarker is how the templates mark a gap that needs a human. It is matched
// verbatim rather than parsed, because the same marker is what the CLI counts.
const todoMarker = "**TODO:**"

// RenderMarkdown renders the Markdown subset that this package's templates
// emit. The subset is the contract, so it is written out here in full.
//
// Supported: ATX headings, paragraphs, thematic breaks, fenced code delimited
// by backticks or tildes with a leading language word, pipe tables with
// per-column alignment, bullet and ordered lists including nested ones, task
// list items, blockquotes including nested ones, bold, italic, inline code, and
// links whose destination is a document fragment, a relative path, or an http,
// https or mailto URL.
//
// Not supported, and therefore escaped and emitted as text rather than turned
// into markup: setext headings, indented code blocks, images, raw HTML, HTML
// comments, autolinks, reference links, footnotes, definition lists and
// strikethrough.
//
// A link this renderer will not vouch for keeps its text and loses only the
// link, so the sentence still reads and no unchecked destination reaches an
// href. That covers any other scheme, a protocol-relative destination, and a
// destination carrying a title. A hard line break written as two trailing
// spaces is the one construct that disappears entirely, because trailing
// whitespace leaves no text to show.
//
// The scope is bounded on purpose. A general CommonMark implementation is
// thousands of lines of edge cases, and every one of them is an opportunity to
// emit markup nobody intended into a document that goes to a regulator. Input
// outside the subset is escaped and emitted as text rather than guessed at, so
// an unsupported construct shows up in the output instead of silently
// disappearing or turning into HTML. Raw HTML in the source is escaped for the
// same reason: the documents carry organisation names, contact addresses and
// model identifiers that come from configuration and from traffic, and none of
// that is allowed to become markup.
func RenderMarkdown(src []byte) Document {
	r := &renderer{slugs: map[string]int{}, titleFrom: -1}
	r.blocks(splitLines(string(src)))

	full := r.out.String()
	doc := Document{Headings: r.headings, Body: full}
	if r.titleFrom >= 0 {
		doc.Title = r.title
		doc.TitleHTML = full[r.titleFrom:r.titleTo]
		doc.Body = full[:r.titleFrom] + full[r.titleTo:]
	}
	return doc
}

type renderer struct {
	out      strings.Builder
	headings []Heading
	slugs    map[string]int
	depth    int

	title     string
	titleFrom int
	titleTo   int
}

func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

func (r *renderer) blocks(lines []string) {
	r.depth++
	defer func() { r.depth-- }()

	for i := 0; i < len(lines); {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			i++
		case isFence(trimmed):
			i = r.codeBlock(lines, i)
		case headingLevel(line) > 0:
			r.heading(line)
			i++
		case isThematicBreak(trimmed):
			r.out.WriteString("<hr>\n")
			i++
		case strings.HasPrefix(strings.TrimLeft(line, " "), ">"):
			i = r.blockquote(lines, i)
		case isTableStart(lines, i):
			i = r.table(lines, i)
		case isListStart(lines, i):
			i = r.list(lines, i)
		default:
			i = r.paragraph(lines, i)
		}
	}
}

func (r *renderer) startsBlock(lines []string, i int) bool {
	line := lines[i]
	trimmed := strings.TrimSpace(line)
	return isFence(trimmed) ||
		headingLevel(line) > 0 ||
		isThematicBreak(trimmed) ||
		strings.HasPrefix(strings.TrimLeft(line, " "), ">") ||
		isTableStart(lines, i) ||
		isListStart(lines, i)
}

func (r *renderer) paragraph(lines []string, i int) int {
	var buf []string
	for i < len(lines) {
		if strings.TrimSpace(lines[i]) == "" {
			break
		}
		if len(buf) > 0 && r.startsBlock(lines, i) {
			break
		}
		buf = append(buf, strings.TrimSpace(lines[i]))
		i++
	}
	r.out.WriteString("<p>" + inlineHTML(strings.Join(buf, "\n")) + "</p>\n")
	return i
}

func (r *renderer) heading(line string) {
	line = strings.TrimLeft(line, " ")
	level := headingLevel(line)
	text := strings.TrimSpace(line[level:])
	text = strings.TrimSpace(strings.TrimRight(text, "#"))

	plain := inlineText(text)
	id := r.slug(plain)
	r.headings = append(r.headings, Heading{Level: level, Text: plain, ID: id})

	from := r.out.Len()
	lvl := strconv.Itoa(level)
	r.out.WriteString("<h" + lvl + ` id="` + html.EscapeString(id) + `">` + inlineHTML(text) + "</h" + lvl + ">\n")

	if level == 1 && r.depth == 1 && r.titleFrom < 0 {
		r.title = plain
		r.titleFrom = from
		r.titleTo = r.out.Len()
	}
}

// slug builds an anchor from heading text. Duplicate headings get a numeric
// suffix so that every anchor in a document resolves to exactly one place.
func (r *renderer) slug(text string) string {
	var b strings.Builder
	pending := false
	for _, ch := range strings.ToLower(text) {
		switch {
		case unicode.IsLetter(ch) || unicode.IsDigit(ch):
			if pending && b.Len() > 0 {
				b.WriteByte('-')
			}
			pending = false
			b.WriteRune(ch)
		default:
			pending = true
		}
	}
	s := b.String()
	if s == "" {
		s = "section"
	}
	r.slugs[s]++
	if n := r.slugs[s]; n > 1 {
		s += "-" + strconv.Itoa(n)
	}
	return s
}

func (r *renderer) blockquote(lines []string, i int) int {
	var content []string
	for i < len(lines) {
		line := strings.TrimLeft(lines[i], " ")
		if !strings.HasPrefix(line, ">") {
			break
		}
		content = append(content, strings.TrimPrefix(strings.TrimPrefix(line, ">"), " "))
		i++
	}

	class := ""
	for _, l := range content {
		if t := strings.TrimSpace(l); t != "" {
			// The TODO callouts are the whole point of the document: they are
			// what still needs a human. They get their own class so the
			// stylesheet can make them impossible to skim past.
			if strings.HasPrefix(t, todoMarker) {
				class = ` class="todo"`
			}
			break
		}
	}

	r.out.WriteString("<blockquote" + class + ">\n")
	r.blocks(content)
	r.out.WriteString("</blockquote>\n")
	return i
}

func (r *renderer) codeBlock(lines []string, i int) int {
	open := strings.TrimSpace(lines[i])
	ch := open[0]
	n := runLen(open, 0, ch)
	info := sanitiseInfo(strings.TrimSpace(open[n:]))
	i++

	var body []string
	for i < len(lines) {
		t := strings.TrimSpace(lines[i])
		if len(t) > 0 && t[0] == ch && runLen(t, 0, ch) >= n && strings.Trim(t, string(ch)) == "" {
			i++
			break
		}
		body = append(body, lines[i])
		i++
	}

	// An unterminated fence runs to the end of the document rather than
	// failing: showing the text is more useful to a reader than losing it.
	class := ""
	if info != "" {
		class = ` class="language-` + info + `"`
	}
	r.out.WriteString("<pre><code" + class + ">")
	for _, l := range body {
		r.out.WriteString(html.EscapeString(l))
		r.out.WriteString("\n")
	}
	r.out.WriteString("</code></pre>\n")
	return i
}

func (r *renderer) table(lines []string, i int) int {
	header := splitRow(lines[i])
	aligns := parseAlignments(lines[i+1], len(header))
	i += 2

	var rows [][]string
	for i < len(lines) {
		t := strings.TrimSpace(lines[i])
		if t == "" || !strings.HasPrefix(t, "|") {
			break
		}
		rows = append(rows, splitRow(lines[i]))
		i++
	}

	// The wrapper scrolls instead of the page: the model table is seven
	// columns wide and the page still has to be readable on a phone.
	r.out.WriteString("<div class=\"table-wrap\">\n<table>\n<thead>\n<tr>")
	for c, cell := range header {
		r.out.WriteString("<th" + alignAttr(aligns, c) + ">" + inlineHTML(cell) + "</th>")
	}
	r.out.WriteString("</tr>\n</thead>\n<tbody>\n")
	last := len(header) - 1
	for _, row := range rows {
		r.out.WriteString("<tr>")
		for c := range header {
			cell := ""
			switch {
			// A configured value containing an unescaped pipe splits into extra
			// cells. Folding the surplus back into the last column keeps the row
			// aligned with the header without deleting text: a silently dropped
			// organisation name in a document that goes to a regulator is worse
			// than an ugly one.
			case c == last && len(row) > len(header):
				cell = strings.Join(row[c:], " | ")
			case c < len(row):
				cell = row[c]
			}
			r.out.WriteString("<td" + alignAttr(aligns, c) + ">" + inlineHTML(cell) + "</td>")
		}
		r.out.WriteString("</tr>\n")
	}
	r.out.WriteString("</tbody>\n</table>\n</div>\n")
	return i
}

type listItem struct {
	lines   []string
	task    bool
	checked bool
}

func (r *renderer) list(lines []string, i int) int {
	first, _ := listMarker(lines[i])
	ordered := first.ordered

	var items []listItem
	loose := false
	anyTask := false

	for i < len(lines) {
		m, ok := listMarker(lines[i])
		if !ok || m.ordered != ordered {
			break
		}

		item := listItem{lines: []string{lines[i][m.width:]}}
		if task, checked, rest, isTask := taskPrefix(item.lines[0]); isTask {
			item.task, item.checked, item.lines[0] = task, checked, rest
			anyTask = true
		}
		i++

		for i < len(lines) {
			if strings.TrimSpace(lines[i]) == "" {
				k := i
				for k < len(lines) && strings.TrimSpace(lines[k]) == "" {
					k++
				}
				if k < len(lines) && indentOf(lines[k]) >= m.width {
					loose = true
					for ; i < k; i++ {
						item.lines = append(item.lines, "")
					}
					continue
				}
				if k < len(lines) {
					if _, next := listMarker(lines[k]); next {
						loose = true
					}
				}
				i = k
				break
			}
			if indentOf(lines[i]) >= m.width {
				item.lines = append(item.lines, dedent(lines[i], m.width))
				i++
				continue
			}
			break
		}
		items = append(items, item)
	}

	tag := "ul"
	class := ""
	if ordered {
		tag = "ol"
	}
	if anyTask {
		// A checklist is rendered tight even when it is loose, because a
		// checkbox followed by a paragraph reads as a checkbox with no label.
		loose = false
		class = ` class="task-list"`
	}

	r.out.WriteString("<" + tag + class + ">\n")
	for _, item := range items {
		r.out.WriteString("<li" + itemClass(item) + ">")
		if item.task {
			r.out.WriteString(`<input type="checkbox" disabled`)
			if item.checked {
				r.out.WriteString(" checked")
			}
			r.out.WriteString("> ")
		}
		if loose {
			r.out.WriteString("\n")
			r.blocks(item.lines)
		} else {
			r.tightItem(item.lines)
		}
		r.out.WriteString("</li>\n")
	}
	r.out.WriteString("</" + tag + ">\n")
	return i
}

// tightItem renders one item of a tight list. Its own text stays inline, so a
// short bullet does not grow a paragraph around it, but a nested list beneath
// it is a block and has to be rendered as one: treating it as more of the
// parent's text puts its markers in front of the reader as literal characters.
func (r *renderer) tightItem(lines []string) {
	nested := len(lines)
	for i := range lines {
		if _, ok := listMarker(lines[i]); ok {
			nested = i
			break
		}
	}
	if nested > 0 {
		r.out.WriteString(inlineHTML(strings.TrimSpace(strings.Join(lines[:nested], "\n"))))
	}
	if nested < len(lines) {
		r.out.WriteString("\n")
		r.blocks(lines[nested:])
	}
}

func itemClass(item listItem) string {
	if item.task {
		return ` class="task"`
	}
	return ""
}

type marker struct {
	ordered bool
	width   int // column at which the item's content starts
}

func listMarker(line string) (marker, bool) {
	ind := indentOf(line)
	if ind >= 4 || ind >= len(line) {
		return marker{}, false
	}
	rest := line[ind:]
	switch rest[0] {
	case '-', '*', '+':
		if len(rest) > 1 && rest[1] == ' ' {
			return marker{width: ind + 2}, true
		}
	default:
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		if digits == 0 || digits > 9 || digits+1 >= len(rest) {
			return marker{}, false
		}
		if (rest[digits] == '.' || rest[digits] == ')') && rest[digits+1] == ' ' {
			return marker{ordered: true, width: ind + digits + 2}, true
		}
	}
	return marker{}, false
}

func isListStart(lines []string, i int) bool {
	_, ok := listMarker(lines[i])
	return ok
}

func taskPrefix(s string) (task, checked bool, rest string, ok bool) {
	if len(s) < 3 || s[0] != '[' || s[2] != ']' {
		return false, false, s, false
	}
	switch s[1] {
	case ' ':
		return true, false, strings.TrimPrefix(s[3:], " "), true
	case 'x', 'X':
		return true, true, strings.TrimPrefix(s[3:], " "), true
	}
	return false, false, s, false
}

func indentOf(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

func dedent(line string, n int) string {
	i := 0
	for i < n && i < len(line) && line[i] == ' ' {
		i++
	}
	return line[i:]
}

func headingLevel(line string) int {
	line = strings.TrimLeft(line, " ")
	n := runLen(line, 0, '#')
	if n < 1 || n > 6 {
		return 0
	}
	if len(line) == n || line[n] == ' ' {
		return n
	}
	return 0
}

func isFence(trimmed string) bool {
	return strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
}

func isThematicBreak(trimmed string) bool {
	s := strings.ReplaceAll(trimmed, " ", "")
	if len(s) < 3 {
		return false
	}
	switch s[0] {
	case '-', '*', '_':
		return strings.Trim(s, string(s[0])) == ""
	}
	return false
}

func isTableStart(lines []string, i int) bool {
	if !strings.HasPrefix(strings.TrimSpace(lines[i]), "|") || i+1 >= len(lines) {
		return false
	}
	next := strings.TrimSpace(lines[i+1])
	if !strings.HasPrefix(next, "|") {
		return false
	}
	cells := splitRow(next)
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		c = strings.TrimPrefix(strings.TrimSuffix(c, ":"), ":")
		if c == "" || strings.Trim(c, "-") != "" {
			return false
		}
	}
	return true
}

// splitRow splits a table row on unescaped pipes. Writers are strict but
// parsers are tolerant: a row with too few cells is padded against the header
// rather than rejected.
func splitRow(line string) []string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")

	var cells []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '|':
			cur.WriteByte('|')
			i++
		case s[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

func parseAlignments(line string, n int) []string {
	cells := splitRow(line)
	out := make([]string, n)
	for i := 0; i < n && i < len(cells); i++ {
		c := cells[i]
		left := strings.HasPrefix(c, ":")
		right := strings.HasSuffix(c, ":")
		switch {
		case left && right:
			out[i] = "center"
		case right:
			out[i] = "right"
		case left:
			out[i] = "left"
		}
	}
	return out
}

func alignAttr(aligns []string, c int) string {
	if c < len(aligns) && aligns[c] != "" {
		return ` class="` + aligns[c] + `"`
	}
	return ""
}

// sanitiseInfo reduces a fence info string to the language word at its front,
// which is the only part of it this renderer has a use for. Everything after
// that word is dropped rather than escaped: writers put titles and highlight
// ranges there, none of which this package renders, and losing the language
// class as well would be a second loss for no reason. A first word that could
// not be part of a class name yields nothing at all.
func sanitiseInfo(info string) string {
	fields := strings.Fields(info)
	if len(fields) == 0 {
		return ""
	}
	lang := fields[0]
	if len(lang) > 32 {
		return ""
	}
	for i := 0; i < len(lang); i++ {
		c := lang[i]
		ok := c == '-' || c == '_' || c == '+' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return ""
		}
	}
	return lang
}

func inlineHTML(s string) string { return inlineWalk(s, false) }

func inlineText(s string) string { return inlineWalk(s, true) }

// inlineWalk renders inline markup. With plain set it produces the text with
// markup removed, which is what the table of contents needs.
//
// Every byte that is not part of a construct this function recognises is
// escaped before it reaches the output, so no input can introduce a tag or an
// attribute. Scanning is byte-wise, which is safe for UTF-8 because only ASCII
// bytes are ever treated as syntax.
func inlineWalk(s string, plain bool) string {
	var b strings.Builder
	lit := 0
	emit := func(end int) {
		if end > lit {
			if plain {
				b.WriteString(s[lit:end])
			} else {
				b.WriteString(html.EscapeString(s[lit:end]))
			}
		}
	}

	for i := 0; i < len(s); {
		switch s[i] {
		case '`':
			n := runLen(s, i, '`')
			if end := findRun(s, i+n, '`', n); end >= 0 {
				emit(i)
				code := s[i+n : end]
				if plain {
					b.WriteString(code)
				} else {
					b.WriteString("<code>" + html.EscapeString(code) + "</code>")
				}
				i = end + n
				lit = i
				continue
			}
		case '*':
			if strings.HasPrefix(s[i:], "**") {
				if end := strings.Index(s[i+2:], "**"); end > 0 {
					inner := s[i+2 : i+2+end]
					emit(i)
					if plain {
						b.WriteString(inlineWalk(inner, true))
					} else {
						b.WriteString("<strong" + gapClass(inner) + ">" + inlineWalk(inner, false) + "</strong>")
					}
					i += 2 + end + 2
					lit = i
					continue
				}
			} else if end := strings.IndexByte(s[i+1:], '*'); end > 0 {
				inner := s[i+1 : i+1+end]
				emit(i)
				if plain {
					b.WriteString(inlineWalk(inner, true))
				} else {
					b.WriteString("<em>" + inlineWalk(inner, false) + "</em>")
				}
				i += 1 + end + 1
				lit = i
				continue
			}
		case '[':
			// Images are not supported. Leaving the "!" behind and linking the
			// alt text would be a worse lie than showing the source.
			if i > 0 && s[i-1] == '!' {
				break
			}
			if text, dest, next, ok := parseLink(s, i); ok {
				emit(i)
				href, safe := safeURL(dest)
				switch {
				case plain || !safe:
					b.WriteString(inlineWalk(text, plain))
				default:
					b.WriteString(`<a href="` + html.EscapeString(href) + `">` + inlineWalk(text, false) + "</a>")
				}
				i = next
				lit = i
				continue
			}
		}
		i++
	}
	emit(len(s))
	return b.String()
}

// gapClass marks the inline TODO marker so that gaps are visible in table cells
// and paragraphs, not only in the callouts.
func gapClass(inner string) string {
	if inner == "TODO:" {
		return ` class="gap"`
	}
	return ""
}

func parseLink(s string, i int) (text, dest string, next int, ok bool) {
	label := strings.IndexByte(s[i:], ']')
	if label < 0 {
		return "", "", 0, false
	}
	label += i
	if label+1 >= len(s) || s[label+1] != '(' {
		return "", "", 0, false
	}
	end := strings.IndexByte(s[label+2:], ')')
	if end < 0 {
		return "", "", 0, false
	}
	end += label + 2
	return s[i+1 : label], s[label+2 : end], end + 1, true
}

// safeURL allows only schemes that cannot execute. A link destination reaches
// this from configuration or from recorded traffic, so "javascript:" and
// "data:" have to be refused rather than escaped: escaping an attribute value
// does not stop the browser from running it when the link is clicked.
func safeURL(dest string) (string, bool) {
	u := strings.TrimSpace(dest)
	if u == "" {
		return "", false
	}
	for _, r := range u {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return "", false
		}
	}
	// A destination that starts with two slashes inherits the scheme of the page
	// and points at another host. These documents promise to make no external
	// request when they are opened, so such a link is refused rather than
	// silently turned into one. Browsers read a backslash in a URL as a slash,
	// so //host, /\host and \\host all have to be caught here.
	if protocolRelative(u) {
		return "", false
	}
	if strings.HasPrefix(u, "#") || strings.HasPrefix(u, "/") ||
		strings.HasPrefix(u, "./") || strings.HasPrefix(u, "../") {
		return u, true
	}
	if i := strings.IndexAny(u, ":/?#"); i >= 0 && u[i] == ':' {
		switch strings.ToLower(u[:i]) {
		case "http", "https", "mailto":
			return u, true
		}
		return "", false
	}
	return u, true
}

func protocolRelative(u string) bool {
	slash := func(c byte) bool { return c == '/' || c == '\\' }
	return len(u) >= 2 && slash(u[0]) && slash(u[1])
}

func runLen(s string, i int, ch byte) int {
	n := 0
	for i+n < len(s) && s[i+n] == ch {
		n++
	}
	return n
}

// findRun returns the index of the next run of exactly n ch bytes at or after i.
func findRun(s string, i int, ch byte, n int) int {
	for i < len(s) {
		if s[i] != ch {
			i++
			continue
		}
		m := runLen(s, i, ch)
		if m == n {
			return i
		}
		i += m
	}
	return -1
}
