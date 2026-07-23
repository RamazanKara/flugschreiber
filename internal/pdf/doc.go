package pdf

// Doc is a document as a flat sequence of blocks. It is deliberately a plain
// data structure with no rendering state, so a caller can build one from
// Markdown, from a template, or by hand, and so tests can assert on it.
type Doc struct {
	Blocks []Block
}

// Block is one laid-out element of a document. The set is closed: it covers
// exactly what the generated documents contain, because a renderer that
// silently ignores a block type it does not know is a renderer that drops
// evidence.
type Block interface {
	block()
}

// Span is a run of text in one inline style.
type Span struct {
	Text  string
	Style Style
}

// Text builds a single unstyled span, which is the common case.
func Text(s string) []Span { return []Span{{Text: s}} }

// Align is the horizontal alignment of a table column.
type Align uint8

// The supported column alignments.
const (
	AlignLeft Align = iota
	AlignCenter
	AlignRight
)

// Heading is a section heading. Level 1 is the document title.
type Heading struct {
	Level int
	Text  []Span
}

// Paragraph is a run of prose.
type Paragraph struct {
	Text []Span
}

// Code is a preformatted block. Lines are never re-wrapped at spaces, and are
// broken only when they cannot be made to fit at the smallest allowed size.
type Code struct {
	Lines []string
}

// Item is one entry in a list. It holds blocks rather than spans so that an
// item can carry a follow-on paragraph, which the generated documents use.
type Item struct {
	Blocks []Block
}

// List is a bullet or numbered list. Start is the first number of an ordered
// list and defaults to 1.
type List struct {
	Ordered bool
	Start   int
	Items   []Item
}

// Quote is a callout. The generated documents use these for the standing
// warnings and for every TODO, so they need to read as set apart from prose.
type Quote struct {
	Blocks []Block
}

// Cell is one table cell.
type Cell struct {
	Text []Span
}

// Table is a header row plus body rows. Align has one entry per column; a
// short Align is padded with AlignLeft.
type Table struct {
	Header []Cell
	Rows   [][]Cell
	Align  []Align
}

// Rule is a horizontal divider.
type Rule struct{}

func (Heading) block()   {}
func (Paragraph) block() {}
func (Code) block()      {}
func (List) block()      {}
func (Quote) block()     {}
func (Table) block()     {}
func (Rule) block()      {}
