// Package pdf writes text documents as PDF using nothing but the standard
// library.
//
// It exists because the generated documentation is more useful to the people
// who have to read it, lawyers, auditors and risk owners, as a paginated file
// than as Markdown, and because taking on a PDF library would put a third
// party between the evidence and the document that describes it. See D1 in
// DECISIONS.md.
//
// The scope is deliberately narrow. It sets text in the 14 standard PDF fonts,
// which need no embedding, and so it can represent exactly what
// WinAnsiEncoding can represent. Anything outside that range is printed as a
// visible marker and reported through the return value of Render, never
// dropped: a document offered as evidence must not quietly lose characters.
//
// Nothing this package produces establishes compliance. It typesets a document
// that someone else wrote.
package pdf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// PageSize is a page in PostScript points, 72 to the inch.
type PageSize struct {
	Width, Height float64
}

// The page sizes the CLI is likely to want. A4 is the default because the
// audience for these documents is in the EU.
var (
	A4     = PageSize{595.28, 841.89}
	Letter = PageSize{612, 792}
)

// Options configures a render. The zero value is usable: it produces an A4
// document with 20 mm side margins at 10 point.
type Options struct {
	Size PageSize

	// The page margins in points. A zero field means "not set", and takes the
	// default of 20 mm at the sides and 56 points top and bottom. Use NoMargin
	// to ask for an edge, which is a decision rather than an unset field.
	MarginLeft   float64
	MarginRight  float64
	MarginTop    float64
	MarginBottom float64

	// BodySize is the point size of body text. Headings, tables and code
	// are sized relative to it.
	BodySize float64

	Title    string
	Author   string
	Subject  string
	Creator  string
	Producer string

	// Lang is a BCP 47 tag recorded in the catalog, which is what lets a
	// screen reader pick the right pronunciation. It also selects the
	// default page label.
	Lang string

	// Created is the timestamp recorded in the document metadata. It
	// defaults to the current time, which makes the output non
	// reproducible; set it explicitly when byte-for-byte reproducibility
	// matters.
	Created time.Time

	// PageLabel is a format string taking the current page and the total,
	// in that order.
	PageLabel string
}

const (
	defaultMarginX = 56.7 // 20 mm
	defaultMarginY = 56.0
	defaultBody    = 10.0
	minContent     = 120.0
)

// NoMargin asks for a margin of zero. The margin fields of Options use their
// zero value to mean "unset, take the default", so a caller who wants an edge
// needs a value that cannot be mistaken for a field nobody filled in. Any
// negative margin is read the same way.
const NoMargin = -1

// margin resolves one margin field, where zero means the field was never set.
func margin(v, def float64) float64 {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

func (o Options) withDefaults() Options {
	if o.Size.Width == 0 || o.Size.Height == 0 {
		o.Size = A4
	}
	o.MarginLeft = margin(o.MarginLeft, defaultMarginX)
	o.MarginRight = margin(o.MarginRight, defaultMarginX)
	o.MarginTop = margin(o.MarginTop, defaultMarginY)
	o.MarginBottom = margin(o.MarginBottom, defaultMarginY)
	if o.BodySize == 0 {
		o.BodySize = defaultBody
	}
	if o.Producer == "" {
		o.Producer = "Flugschreiber"
	}
	if o.Creator == "" {
		o.Creator = "Flugschreiber"
	}
	if o.PageLabel == "" {
		o.PageLabel = "Page %d of %d"
		if strings.HasPrefix(strings.ToLower(o.Lang), "de") {
			o.PageLabel = "Seite %d von %d"
		}
	}
	if o.Created.IsZero() {
		o.Created = time.Now()
	}
	return o
}

func (o Options) validate() error {
	if o.Size.Width <= 0 || o.Size.Height <= 0 {
		return fmt.Errorf("pdf: page size %gx%g is not a page, set Options.Size to A4, Letter or a positive size", o.Size.Width, o.Size.Height)
	}
	w := o.Size.Width - o.MarginLeft - o.MarginRight
	h := o.Size.Height - o.MarginTop - o.MarginBottom - footerReserve
	if w < minContent {
		return fmt.Errorf("pdf: margins leave %.0f points of column width, which is below the %.0f point minimum, reduce MarginLeft or MarginRight", w, minContent)
	}
	if h < minContent {
		return fmt.Errorf("pdf: margins leave %.0f points of page height, which is below the %.0f point minimum, reduce MarginTop or MarginBottom", h, minContent)
	}
	if o.BodySize < 4 || o.BodySize > 36 {
		return fmt.Errorf("pdf: body size %.1f is outside the supported 4 to 36 point range", o.BodySize)
	}
	return nil
}

// Render lays doc out and writes a PDF to w.
//
// The returned substitutions list every rune the standard PDF fonts could not
// represent, with the marker printed in its place. Callers are expected to
// report them; an empty list means the document renders every character it was
// given.
func Render(w io.Writer, doc Doc, opt Options) ([]Substitution, error) {
	if w == nil {
		return nil, errors.New("pdf: no destination to write to")
	}
	opt = opt.withDefaults()
	if err := opt.validate(); err != nil {
		return nil, err
	}

	r := &renderer{
		opt:   opt,
		subs:  map[rune]int{},
		left:  opt.MarginLeft,
		right: opt.Size.Width - opt.MarginRight,
	}
	r.pages = []*pageBuf{{}}
	r.y = r.contentTop()
	r.blocks(doc.Blocks)
	r.footers()

	data, err := r.assemble()
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("pdf: write document: %w", err)
	}
	return substitutions(r.subs), nil
}

// assemble turns the laid-out pages into a complete file.
func (r *renderer) assemble() ([]byte, error) {
	w := &writer{}
	catalog := w.reserve()
	pages := w.reserve()
	info := w.reserve()

	// Every standard font is declared whether or not this document uses it.
	// Eight small dictionaries cost nothing and remove the possibility of a
	// content stream naming a resource the page does not offer.
	var fontRefs strings.Builder
	fontRefs.WriteString("<< ")
	for i := range fonts {
		f := &fonts[i]
		n := w.addf("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", f.base)
		fmt.Fprintf(&fontRefs, "/%s %d 0 R ", f.resource, n)
	}
	fontRefs.WriteString(">>")
	resources := w.addf("<< /Font %s /ProcSet [/PDF /Text] >>", fontRefs.String())

	pageObjs := make([]int, len(r.pages))
	for i := range r.pages {
		pageObjs[i] = w.reserve()
	}
	mediaBox := fmt.Sprintf("[0 0 %s %s]", num(r.opt.Size.Width), num(r.opt.Size.Height))
	kids := make([]string, len(pageObjs))
	for i, p := range r.pages {
		content := w.addStream("", p.body.Bytes())
		w.set(pageObjs[i], fmt.Appendf(nil,
			"<< /Type /Page /Parent %d 0 R /MediaBox %s /Resources %d 0 R /Contents %d 0 R >>",
			pages, mediaBox, resources, content))
		kids[i] = fmt.Sprintf("%d 0 R", pageObjs[i])
	}
	w.set(pages, fmt.Appendf(nil, "<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kids, " "), len(pageObjs)))

	var cat strings.Builder
	fmt.Fprintf(&cat, "<< /Type /Catalog /Pages %d 0 R", pages)
	if outlines := r.writeOutline(w, pageObjs); outlines != 0 {
		fmt.Fprintf(&cat, " /Outlines %d 0 R /PageMode /UseOutlines", outlines)
	}
	if r.opt.Lang != "" {
		fmt.Fprintf(&cat, " /Lang %s", textString(r.opt.Lang))
	}
	cat.WriteString(" >>")
	w.set(catalog, []byte(cat.String()))

	var meta strings.Builder
	meta.WriteString("<<")
	addMeta := func(key, value string) {
		if value != "" {
			fmt.Fprintf(&meta, " /%s %s", key, textString(value))
		}
	}
	addMeta("Title", r.opt.Title)
	addMeta("Author", r.opt.Author)
	addMeta("Subject", r.opt.Subject)
	addMeta("Creator", r.opt.Creator)
	addMeta("Producer", r.opt.Producer)
	stamp := pdfDate(r.opt.Created)
	fmt.Fprintf(&meta, " /CreationDate %s /ModDate %s >>", literal([]byte(stamp)), literal([]byte(stamp)))
	w.set(info, []byte(meta.String()))

	// The file identifier is a hash of the objects rather than a random
	// value, so that rendering the same document twice produces the same
	// bytes. An evidence tool that cannot reproduce its own output is
	// asking to be taken on trust.
	sum := sha256.Sum256(w.fingerprint())
	return w.serialise(catalog, info, sum[:16])
}

// outlineNode is one bookmark.
type outlineNode struct {
	title    string
	page     int
	y        float64
	children []*outlineNode
}

// writeOutline emits the bookmark tree and returns the /Outlines object, or 0
// when the document has no headings.
func (r *renderer) writeOutline(w *writer, pageObjs []int) int {
	roots := outlineTree(r.heads)
	if len(roots) == 0 {
		return 0
	}
	root := w.reserve()
	first, last, total := writeOutlineLevel(w, roots, root, pageObjs, r.opt.MarginLeft)
	w.set(root, fmt.Appendf(nil, "<< /Type /Outlines /First %d 0 R /Last %d 0 R /Count %d >>", first, last, total))
	return root
}

// outlineTree nests headings by level. Levels that skip a step, an h3 directly
// under an h1, are attached where they land rather than rejected, because the
// bookmark panel is a convenience and should never be the thing that fails a
// render.
func outlineTree(heads []headRef) []*outlineNode {
	var roots []*outlineNode
	type frame struct {
		level int
		node  *outlineNode
	}
	var stack []frame
	for _, h := range heads {
		n := &outlineNode{title: h.title, page: h.page, y: h.y}
		for len(stack) > 0 && stack[len(stack)-1].level >= h.level {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			p := stack[len(stack)-1].node
			p.children = append(p.children, n)
		}
		stack = append(stack, frame{level: h.level, node: n})
	}
	return roots
}

// writeOutlineLevel writes one level of bookmarks and returns the first and
// last object numbers plus the number of entries in the subtree. Every entry is
// written open, so /Count is the full descendant count and is positive.
func writeOutlineLevel(w *writer, nodes []*outlineNode, parent int, pageObjs []int, x float64) (first, last, total int) {
	if len(nodes) == 0 {
		return 0, 0, 0
	}
	nums := make([]int, len(nodes))
	for i := range nodes {
		nums[i] = w.reserve()
	}
	for i, n := range nodes {
		cf, cl, ct := writeOutlineLevel(w, n.children, nums[i], pageObjs, x)
		var b strings.Builder
		fmt.Fprintf(&b, "<< /Title %s /Parent %d 0 R", textString(n.title), parent)
		if i > 0 {
			fmt.Fprintf(&b, " /Prev %d 0 R", nums[i-1])
		}
		if i < len(nodes)-1 {
			fmt.Fprintf(&b, " /Next %d 0 R", nums[i+1])
		}
		if cf != 0 {
			fmt.Fprintf(&b, " /First %d 0 R /Last %d 0 R /Count %d", cf, cl, ct)
		}
		fmt.Fprintf(&b, " /Dest [%d 0 R /XYZ %s %s null] >>", pageObjs[n.page], num(x), num(n.y))
		w.set(nums[i], []byte(b.String()))
		total += 1 + ct
	}
	return nums[0], nums[len(nums)-1], total
}
