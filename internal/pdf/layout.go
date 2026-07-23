package pdf

import (
	"bytes"
	"fmt"
	"strings"
)

// atom is the smallest unit the line breaker moves around: one word, or one
// run of spaces, in a single style at a single size.
type atom struct {
	b     []byte
	style Style
	size  float64
	w     float64
	space bool
}

// run is a maximal sequence of atoms sharing a style and size, ready to be
// written as one Tj operator.
type run struct {
	b     []byte
	style Style
	size  float64
	w     float64
}

// line is one laid-out line of text and its total width.
type line struct {
	runs []run
	w    float64
}

// monoScale shrinks inline code so that Courier, which has a large body for
// its point size, does not tower over the surrounding Helvetica.
const monoScale = 0.92

// tokenize encodes spans and splits them into atoms measured at size. extra is
// or-ed into every span's style, which is how a heading makes its whole run
// bold without the caller having to say so on each span.
//
// subs may be nil, which measures without recording substitutions. Every piece
// of text must be tokenized exactly once with a non-nil subs, or the report of
// what could not be represented will be wrong.
func tokenize(spans []Span, size float64, extra Style, subs map[rune]int) []atom {
	var out []atom
	for _, sp := range spans {
		st := sp.Style | extra
		sz := size
		if st&Mono != 0 {
			sz = size * monoScale
		}
		f := fontFor(st)
		b := encode(sp.Text, subs)
		for i := 0; i < len(b); {
			j := i
			isSpace := b[i] == ' '
			for j < len(b) && (b[j] == ' ') == isSpace {
				j++
			}
			piece := b[i:j]
			out = append(out, atom{
				b:     piece,
				style: st,
				size:  sz,
				w:     f.advance(piece, sz),
				space: isSpace,
			})
			i = j
		}
	}
	return out
}

// splitAt divides an overlong atom so that the head is as wide as it can be
// without exceeding width. It always moves at least one byte, so a caller
// looping on the tail cannot spin.
func splitAt(a atom, width float64) (head, tail atom) {
	f := fontFor(a.style)
	n := 0
	w := 0.0
	for n < len(a.b) {
		cw := f.advance(a.b[n:n+1], a.size)
		if n > 0 && w+cw > width {
			break
		}
		w += cw
		n++
	}
	head = atom{b: a.b[:n], style: a.style, size: a.size, w: w}
	tail = atom{b: a.b[n:], style: a.style, size: a.size}
	tail.w = f.advance(tail.b, a.size)
	return head, tail
}

// merge collapses atoms into runs so that consecutive text in the same style
// becomes a single string in the content stream.
func merge(atoms []atom) []run {
	var out []run
	for _, a := range atoms {
		if n := len(out); n > 0 && out[n-1].style == a.style && out[n-1].size == a.size {
			out[n-1].b = append(out[n-1].b, a.b...)
			out[n-1].w += a.w
			continue
		}
		b := make([]byte, len(a.b))
		copy(b, a.b)
		out = append(out, run{b: b, style: a.style, size: a.size, w: a.w})
	}
	return out
}

// wrap breaks atoms into lines no wider than width. A word wider than the
// whole column is split by character rather than allowed to run off the page,
// because a line that leaves the media box is a line the reader never sees.
func wrap(atoms []atom, width float64) []line {
	var out []line
	var cur []atom
	curW := 0.0

	flush := func() {
		for len(cur) > 0 && cur[len(cur)-1].space {
			curW -= cur[len(cur)-1].w
			cur = cur[:len(cur)-1]
		}
		if len(cur) > 0 {
			out = append(out, line{runs: merge(cur), w: curW})
		}
		cur, curW = nil, 0
	}

	for _, a := range atoms {
		if a.space {
			if len(cur) == 0 {
				continue
			}
			cur = append(cur, a)
			curW += a.w
			continue
		}
		for {
			if curW+a.w <= width {
				cur = append(cur, a)
				curW += a.w
				break
			}
			if len(cur) > 0 {
				flush()
				continue
			}
			head, tail := splitAt(a, width)
			cur = append(cur, head)
			curW += head.w
			flush()
			a = tail
			if len(a.b) == 0 {
				break
			}
		}
	}
	flush()
	return out
}

// plain concatenates the text of spans, for uses outside the page body such as
// bookmark titles, which are not limited to what WinAnsi can encode.
func plain(spans []Span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString(s.Text)
	}
	return b.String()
}

// pageBuf accumulates one page's content stream.
type pageBuf struct {
	body bytes.Buffer
}

// drawLine writes one laid-out line with its baseline at y.
func (p *pageBuf) drawLine(x, y float64, l line, grey float64) {
	if len(l.runs) == 0 {
		return
	}
	p.body.WriteString("BT\n")
	fmt.Fprintf(&p.body, "%s g\n", num(grey))
	cx := x
	curFont := ""
	curSize := 0.0
	for _, r := range l.runs {
		f := fontFor(r.style)
		if f.resource != curFont || r.size != curSize {
			fmt.Fprintf(&p.body, "/%s %s Tf\n", f.resource, num(r.size))
			curFont, curSize = f.resource, r.size
		}
		fmt.Fprintf(&p.body, "1 0 0 1 %s %s Tm\n%s Tj\n", num(cx), num(y), literal(r.b))
		cx += r.w
	}
	p.body.WriteString("ET\n")
}

// rect fills an axis-aligned rectangle. Rules and backgrounds are filled
// rectangles rather than strokes so that line width, cap and join state can
// never affect where the ink lands.
func (p *pageBuf) rect(x, y, w, h, grey float64) {
	if w <= 0 || h <= 0 {
		return
	}
	fmt.Fprintf(&p.body, "q %s g %s %s %s %s re f Q\n", num(grey), num(x), num(y), num(w), num(h))
}

// barState is an open blockquote rule. It is redrawn per page because the
// quote it marks may cross a page boundary.
type barState struct {
	x, top float64
}

// headRef is a heading recorded during layout, used to build the bookmarks.
type headRef struct {
	level int
	title string
	page  int
	y     float64
}

// pendingMark is a list bullet waiting for the item it belongs to to settle.
// Where the item lands cannot be known when the bullet is composed, because the
// item's first block runs its own, larger ensure and may start a new page.
type pendingMark struct {
	x    float64
	line line
	grey float64
}

type renderer struct {
	opt   Options
	subs  map[rune]int
	pages []*pageBuf
	y     float64
	left  float64
	right float64
	bars  []barState
	heads []headRef
	marks []pendingMark
}

// place draws one line of body text, first placing any list bullet that was
// waiting for a line to settle on a page. Every line in the body goes through
// here, so a bullet can never end up on a different page from its item, and it
// sits on the baseline the item's first line actually got rather than on a
// baseline guessed from the body leading.
func (r *renderer) place(x, y float64, l line, grey float64) {
	p := r.cur()
	for _, m := range r.marks {
		p.drawLine(m.x, y, m.line, m.grey)
	}
	r.marks = r.marks[:0]
	p.drawLine(x, y, l, grey)
}

type headingStyle struct {
	scale, before, after float64
}

// headingStyles is indexed by heading level. Level 1 is the document title.
var headingStyles = [7]headingStyle{
	1: {scale: 1.8, before: 0, after: 11},
	2: {scale: 1.4, before: 18, after: 7},
	3: {scale: 1.15, before: 13, after: 5},
	4: {scale: 1.0, before: 11, after: 4},
	5: {scale: 1.0, before: 10, after: 3},
	6: {scale: 1.0, before: 10, after: 3},
}

const (
	bodyLeadFactor = 1.42
	paraGap        = 6.0
	quoteIndent    = 13.0
	quoteBarWidth  = 2.5
	listIndent     = 16.0
	codePad        = 6.0
	codeLeadFactor = 1.3
	codeMinSize    = 6.5
	tableHPad      = 4.0
	tableVPad      = 3.5
	footerReserve  = 28.0
)

func (r *renderer) cur() *pageBuf  { return r.pages[len(r.pages)-1] }
func (r *renderer) width() float64 { return r.right - r.left }
func (r *renderer) contentTop() float64 {
	return r.opt.Size.Height - r.opt.MarginTop
}
func (r *renderer) contentBottom() float64 {
	return r.opt.MarginBottom + footerReserve
}
func (r *renderer) bodyLead() float64 { return r.opt.BodySize * bodyLeadFactor }

// gap advances the cursor, except at the top of a page where leading space
// would show up as an unexplained indent.
func (r *renderer) gap(h float64) {
	if r.y < r.contentTop() {
		r.y -= h
	}
}

// ensure starts a new page when h points do not remain.
func (r *renderer) ensure(h float64) {
	if r.y-h < r.contentBottom() && r.y < r.contentTop() {
		r.newPage()
	}
}

func (r *renderer) newPage() {
	for i := range r.bars {
		r.drawBar(r.bars[i])
	}
	r.pages = append(r.pages, &pageBuf{})
	r.y = r.contentTop()
	for i := range r.bars {
		r.bars[i].top = r.y
	}
}

func (r *renderer) drawBar(b barState) {
	if h := b.top - r.y; h > 0 {
		r.cur().rect(b.x, r.y, quoteBarWidth, h, 0.7)
	}
}

func (r *renderer) blocks(bs []Block) {
	for _, b := range bs {
		switch v := b.(type) {
		case Heading:
			r.heading(v)
		case Paragraph:
			r.paragraph(v)
		case Code:
			r.code(v)
		case List:
			r.list(v)
		case Quote:
			r.quote(v)
		case Table:
			r.table(v)
		case Rule:
			r.rule()
		}
	}
}

func (r *renderer) heading(h Heading) {
	level := h.Level
	if level < 1 {
		level = 1
	}
	if level > 6 {
		level = 6
	}
	st := headingStyles[level]
	size := r.opt.BodySize * st.scale
	leading := size * 1.22
	r.gap(st.before)

	lines := wrap(tokenize(h.Text, size, Bold, r.subs), r.width())
	// Keep a heading with the first two lines of what it introduces. A
	// heading stranded at the foot of a page reads as a mistake.
	r.ensure(float64(len(lines))*leading + st.after + r.bodyLead()*2)
	r.heads = append(r.heads, headRef{level: level, title: plain(h.Text), page: len(r.pages) - 1, y: r.y})

	for _, l := range lines {
		r.ensure(leading)
		r.y -= leading
		r.place(r.left, r.y, l, 0)
	}
	if level == 1 {
		r.y -= 5
		r.cur().rect(r.left, r.y, r.width(), 0.8, 0.3)
	}
	r.gap(st.after)
}

func (r *renderer) paragraph(p Paragraph) {
	leading := r.bodyLead()
	for _, l := range wrap(tokenize(p.Text, r.opt.BodySize, 0, r.subs), r.width()) {
		r.ensure(leading)
		r.y -= leading
		r.place(r.left, r.y, l, 0)
	}
	r.gap(paraGap)
}

func (r *renderer) rule() {
	r.gap(8)
	r.ensure(6)
	r.y -= 4
	r.cur().rect(r.left, r.y, r.width(), 0.5, 0.75)
	r.gap(10)
}

// codeRow is one physical line of a code block. cont marks a line the layout
// had to break, so the mark can be drawn in the padding where it cannot be
// mistaken for part of the code.
type codeRow struct {
	b    []byte
	cont bool
}

func (r *renderer) code(c Code) {
	if len(c.Lines) == 0 {
		return
	}
	r.gap(paraGap)

	inner := r.width() - 2*codePad
	f := fontFor(Mono)
	size := r.opt.BodySize * 0.88

	encoded := make([][]byte, len(c.Lines))
	longest := 0.0
	for i, ln := range c.Lines {
		encoded[i] = encode(expandTabs(ln), r.subs)
		if w := f.advance(encoded[i], size); w > longest {
			longest = w
		}
	}
	// Shrink the block to fit before breaking any line. A code block in
	// these documents is usually a command someone is meant to copy, and a
	// wrapped command is easy to copy wrongly.
	if longest > inner && longest > 0 {
		size *= inner / longest
		if size < codeMinSize {
			size = codeMinSize
		}
	}
	leading := size * codeLeadFactor

	var rows []codeRow
	for _, b := range encoded {
		for first := true; ; first = false {
			if f.advance(b, size) <= inner || len(b) <= 1 {
				rows = append(rows, codeRow{b: b, cont: !first})
				break
			}
			head, tail := splitAt(atom{b: b, style: Mono, size: size}, inner)
			rows = append(rows, codeRow{b: head.b, cont: !first})
			b = tail.b
		}
	}

	for off := 0; off < len(rows); {
		r.ensure(leading + 2*codePad)
		avail := r.y - r.contentBottom() - 2*codePad
		n := int(avail / leading)
		if n < 1 {
			n = 1
		}
		if n > len(rows)-off {
			n = len(rows) - off
		}
		h := float64(n)*leading + 2*codePad
		r.cur().rect(r.left, r.y-h, r.width(), h, 0.94)
		y := r.y - codePad
		for _, row := range rows[off : off+n] {
			y -= leading
			r.place(r.left+codePad, y, line{runs: []run{{b: row.b, style: Mono, size: size, w: f.advance(row.b, size)}}}, 0.1)
			if row.cont {
				mark := []byte{0xBB} // guillemotright
				r.cur().drawLine(r.left+1, y, line{runs: []run{{b: mark, style: 0, size: size, w: 0}}}, 0.55)
			}
		}
		r.y -= h
		off += n
	}
	r.gap(paraGap)
}

func (r *renderer) quote(q Quote) {
	r.gap(paraGap)
	r.ensure(r.bodyLead() * 2)
	r.bars = append(r.bars, barState{x: r.left, top: r.y})
	r.left += quoteIndent
	r.blocks(q.Blocks)
	r.left -= quoteIndent
	b := r.bars[len(r.bars)-1]
	r.bars = r.bars[:len(r.bars)-1]
	r.drawBar(b)
	r.gap(paraGap)
}

func (r *renderer) list(l List) {
	start := l.Start
	if start == 0 {
		start = 1
	}
	leading := r.bodyLead()
	for i, item := range l.Items {
		var mark []byte
		if l.Ordered {
			mark = encode(fmt.Sprintf("%d.", start+i), nil)
		} else {
			mark = []byte{0x95} // bullet
		}
		// The marker belongs on the baseline of the item's first line, and
		// where that is cannot be settled here: the item's first block runs
		// its own ensure, which asks for more room than one body line and can
		// start a new page. Fixing the bullet now put it on one page and its
		// text on the next whenever the space left cleared one requirement but
		// not the other. It is queued instead, and place draws it against the
		// first line the item actually puts down.
		f := fontFor(0)
		r.marks = append(r.marks, pendingMark{
			x:    r.left,
			line: line{runs: []run{{b: mark, style: 0, size: r.opt.BodySize, w: f.advance(mark, r.opt.BodySize)}}},
			grey: 0.25,
		})

		r.left += listIndent
		r.blocks(item.Blocks)
		r.left -= listIndent

		// An item that laid nothing out, or whose content is only rules and
		// rectangles, still shows its bullet rather than losing it.
		if len(r.marks) > 0 {
			r.ensure(leading)
			r.y -= leading
			r.place(r.left, r.y, line{}, 0)
		}
	}
}

// columns reports how many columns a table has, taking the widest row so that
// a ragged table still renders every cell it contains.
func columns(t Table) int {
	n := len(t.Header)
	for _, row := range t.Rows {
		if len(row) > n {
			n = len(row)
		}
	}
	return n
}

// columnWidths distributes the available width across columns. It measures
// with a nil substitution collector, because these cells are measured here and
// encoded again when they are drawn, and a substitution must be counted once.
func columnWidths(t Table, n int, avail, size float64) []float64 {
	minw := make([]float64, n)
	maxw := make([]float64, n)
	consider := func(cells []Cell, extra Style) {
		for i, c := range cells {
			if i >= n {
				break
			}
			total, widest := 0.0, 0.0
			for _, a := range tokenize(c.Text, size, extra, nil) {
				total += a.w
				if !a.space && a.w > widest {
					widest = a.w
				}
			}
			if total > maxw[i] {
				maxw[i] = total
			}
			if widest > minw[i] {
				minw[i] = widest
			}
		}
	}
	consider(t.Header, Bold)
	for _, row := range t.Rows {
		consider(row, 0)
	}

	// One pathological token, a 64 character hash for instance, must not be
	// allowed to squeeze every other column to nothing. Capping its floor
	// lets it break instead, which costs one wrapped cell rather than a
	// whole unreadable table.
	floorCap := avail * 0.45
	sumMax, sumMin := 0.0, 0.0
	for i := range maxw {
		if maxw[i] < 1 {
			maxw[i] = 1
		}
		if minw[i] > maxw[i] {
			minw[i] = maxw[i]
		}
		if minw[i] > floorCap {
			minw[i] = floorCap
		}
		sumMax += maxw[i]
		sumMin += minw[i]
	}

	out := make([]float64, n)
	switch {
	case sumMax <= avail:
		// Stretch to the full column so the table reads as a table.
		for i := range out {
			out[i] = maxw[i] + (avail-sumMax)*maxw[i]/sumMax
		}
	case sumMin <= avail:
		// Take the excess out of the columns that have slack.
		slack := sumMax - sumMin
		excess := sumMax - avail
		for i := range out {
			out[i] = maxw[i] - excess*(maxw[i]-minw[i])/slack
		}
	default:
		// Even the longest single words do not fit. Scale down and let
		// the line breaker split them rather than lose any of them.
		for i := range out {
			out[i] = avail * minw[i] / sumMin
		}
	}
	return out
}

// note draws a bracketed notice in place of an element that could not be laid
// out. Dropping a table from a document offered as evidence is the same class
// of failure as dropping cells from one, so the reader is told that something
// was there and an operator is told what stopped it.
func (r *renderer) note(format string, args ...any) {
	r.paragraph(Paragraph{Text: []Span{{Text: fmt.Sprintf(format, args...), Style: Bold}}})
}

func (r *renderer) table(t Table) {
	n := columns(t)
	if n == 0 {
		r.note("[table omitted: it has no columns]")
		return
	}
	size := r.opt.BodySize * 0.9
	leading := size * 1.3
	pad := float64(n) * 2 * tableHPad
	avail := r.width() - pad
	if avail <= 0 {
		r.note("[table of %d columns omitted: the cell padding alone needs %.0f points and the column is %.0f points wide]",
			n, pad, r.width())
		return
	}
	widths := columnWidths(t, n, avail, size)

	aligns := make([]Align, n)
	copy(aligns, t.Align)

	wrapRow := func(cells []Cell, extra Style) [][]line {
		out := make([][]line, n)
		for i := 0; i < n; i++ {
			if i < len(cells) {
				out[i] = wrap(tokenize(cells[i].Text, size, extra, r.subs), widths[i])
			}
		}
		return out
	}

	r.gap(paraGap)

	var header [][]line
	if len(t.Header) > 0 {
		header = wrapRow(t.Header, Bold)
	}
	// Keep the header with at least one body row.
	r.ensure(rowHeight(header, leading) + leading + 4*tableVPad)

	drawHeader := func() {
		if header == nil {
			return
		}
		r.drawRow(header, widths, aligns, leading, nil)
		r.tableRule(widths, n, 0.7, 0.35)
	}
	drawHeader()

	for _, row := range t.Rows {
		cells := wrapRow(row, 0)
		h := rowHeight(cells, leading)
		// Move a row that would split to the next page, unless it is
		// taller than a page, in which case splitting is the only way to
		// show all of it.
		if r.y-h < r.contentBottom() && h < r.contentTop()-r.contentBottom()-rowHeight(header, leading) {
			r.newPage()
			drawHeader()
		}
		r.drawRow(cells, widths, aligns, leading, drawHeader)
		r.tableRule(widths, n, 0.35, 0.72)
	}
	r.gap(paraGap + 2)
}

func rowHeight(cells [][]line, leading float64) float64 {
	if cells == nil {
		return 0
	}
	max := 1
	for _, c := range cells {
		if len(c) > max {
			max = len(c)
		}
	}
	return float64(max)*leading + 2*tableVPad
}

// drawRow places one row, continuing on the next page when the row is taller
// than the space left. repeat, when set, redraws the header after a break.
func (r *renderer) drawRow(cells [][]line, widths []float64, aligns []Align, leading float64, repeat func()) {
	maxLines := 1
	for _, c := range cells {
		if len(c) > maxLines {
			maxLines = len(c)
		}
	}
	for off := 0; off < maxLines; {
		r.ensure(leading + 2*tableVPad)
		avail := r.y - r.contentBottom() - 2*tableVPad
		n := int(avail / leading)
		if n < 1 {
			n = 1
		}
		if n > maxLines-off {
			n = maxLines - off
		}
		x := r.left
		for ci, col := range cells {
			y := r.y - tableVPad
			for li := off; li < off+n && li < len(col); li++ {
				y -= leading
				cx := x + tableHPad
				switch aligns[ci] {
				case AlignRight:
					cx += widths[ci] - col[li].w
				case AlignCenter:
					cx += (widths[ci] - col[li].w) / 2
				}
				r.place(cx, y, col[li], 0)
			}
			x += widths[ci] + 2*tableHPad
		}
		r.y -= float64(n)*leading + 2*tableVPad
		off += n
		if off < maxLines {
			r.newPage()
			if repeat != nil {
				repeat()
			}
		}
	}
}

func (r *renderer) tableRule(widths []float64, n int, thickness, grey float64) {
	total := float64(n) * 2 * tableHPad
	for _, w := range widths {
		total += w
	}
	r.cur().rect(r.left, r.y, total, thickness, grey)
	r.y -= thickness
}

// footers stamps every page once the total is known. It runs after layout so
// that "page 3 of 12" can say twelve.
func (r *renderer) footers() {
	total := len(r.pages)
	f := fontFor(0)
	size := 7.8
	y := r.opt.MarginBottom + 4
	contentW := r.opt.Size.Width - r.opt.MarginLeft - r.opt.MarginRight
	// The running head and the page label come from Options, so an operator
	// supplied organisation or title can carry a rune the standard fonts
	// cannot set. Both are counted once rather than once per page: each is a
	// single piece of text that happens to be stamped repeatedly.
	title := encode(r.opt.Title, r.subs)
	if w := f.advance(title, size); w > contentW*0.62 {
		for len(title) > 1 && f.advance(title, size) > contentW*0.62-f.advance([]byte("..."), size) {
			title = title[:len(title)-1]
		}
		title = append(title, "..."...)
	}
	for i, p := range r.pages {
		p.rect(r.opt.MarginLeft, y+11, contentW, 0.4, 0.8)
		p.drawLine(r.opt.MarginLeft, y, line{runs: []run{{b: title, style: 0, size: size, w: f.advance(title, size)}}}, 0.45)
		labelSubs := map[rune]int(nil)
		if i == 0 {
			labelSubs = r.subs
		}
		label := encode(fmt.Sprintf(r.opt.PageLabel, i+1, total), labelSubs)
		lw := f.advance(label, size)
		p.drawLine(r.opt.MarginLeft+contentW-lw, y, line{runs: []run{{b: label, style: 0, size: size, w: lw}}}, 0.45)
	}
}

// expandTabs makes code blocks lay out the way their author saw them. A tab
// inside a content stream would otherwise become a single space.
func expandTabs(s string) string {
	if !strings.ContainsRune(s, '\t') {
		return s
	}
	var b strings.Builder
	col := 0
	for _, r := range s {
		if r == '\t' {
			n := 4 - col%4
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		col++
	}
	return b.String()
}
