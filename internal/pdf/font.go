package pdf

import (
	"fmt"
	"sort"
	"strings"
)

// Style is a set of inline text attributes. Styles combine with bitwise or, so
// bold italic is Bold|Italic.
type Style uint8

// The inline styles. Anything not listed here renders as regular body text.
const (
	Bold Style = 1 << iota
	Italic
	Mono
)

const styleMask = Bold | Italic | Mono

// font is one of the 14 standard PDF fonts. Those need no embedding, which is
// what makes a writer with no dependencies possible at all: a viewer supplies
// the glyphs and the only thing it cannot tell us is how wide they are, which
// is what the tables in metrics.go are for.
type font struct {
	base     string
	resource string
	widths   *[256]uint16
	// fixed is the advance every glyph gets in a monospaced face, in
	// thousandths of the font size. Zero means consult widths.
	fixed uint16
}

var fonts = [8]font{
	0:                    {base: "Helvetica", resource: "F1", widths: &helveticaWidths},
	Bold:                 {base: "Helvetica-Bold", resource: "F2", widths: &helveticaBoldWidths},
	Italic:               {base: "Helvetica-Oblique", resource: "F3", widths: &helveticaObliqueWidths},
	Bold | Italic:        {base: "Helvetica-BoldOblique", resource: "F4", widths: &helveticaBoldObliqueWidths},
	Mono:                 {base: "Courier", resource: "F5", fixed: 600},
	Mono | Bold:          {base: "Courier-Bold", resource: "F6", fixed: 600},
	Mono | Italic:        {base: "Courier-Oblique", resource: "F7", fixed: 600},
	Mono | Bold | Italic: {base: "Courier-BoldOblique", resource: "F8", fixed: 600},
}

func fontFor(s Style) *font { return &fonts[s&styleMask] }

// advance returns the width of b, already encoded as WinAnsi bytes, when set
// at size points.
func (f *font) advance(b []byte, size float64) float64 {
	if f.fixed != 0 {
		return float64(len(b)) * float64(f.fixed) * size / 1000
	}
	total := 0
	for _, c := range b {
		total += int(f.widths[c])
	}
	return float64(total) * size / 1000
}

// winAnsi maps a rune to its byte in WinAnsiEncoding (PDF 1.7 Annex D.2).
// Printable ASCII is the identity and is therefore not listed. Every glyph
// named here is present in all 14 standard fonts, so no substitution table or
// font descriptor is needed.
var winAnsi = map[rune]byte{
	0x20AC: 0x80, // Euro
	0x201A: 0x82, // quotesinglbase
	0x0192: 0x83, // florin
	0x201E: 0x84, // quotedblbase
	0x2026: 0x85, // ellipsis
	0x2020: 0x86, // dagger
	0x2021: 0x87, // daggerdbl
	0x02C6: 0x88, // circumflex
	0x2030: 0x89, // perthousand
	0x0160: 0x8A, // Scaron
	0x2039: 0x8B, // guilsinglleft
	0x0152: 0x8C, // OE
	0x017D: 0x8E, // Zcaron
	0x2018: 0x91, // quoteleft
	0x2019: 0x92, // quoteright
	0x201C: 0x93, // quotedblleft
	0x201D: 0x94, // quotedblright
	0x2022: 0x95, // bullet
	0x2013: 0x96, // endash
	0x2014: 0x97, // emdash
	0x02DC: 0x98, // tilde
	0x2122: 0x99, // trademark
	0x0161: 0x9A, // scaron
	0x203A: 0x9B, // guilsinglright
	0x0153: 0x9C, // oe
	0x017E: 0x9E, // zcaron
	0x0178: 0x9F, // Ydieresis
	0x00A0: 0xA0, // space, kept distinct so a non-breaking space still prints
	0x00A1: 0xA1, // exclamdown
	0x00A2: 0xA2, // cent
	0x00A3: 0xA3, // sterling
	0x00A4: 0xA4, // currency
	0x00A5: 0xA5, // yen
	0x00A6: 0xA6, // brokenbar
	0x00A7: 0xA7, // section
	0x00A8: 0xA8, // dieresis
	0x00A9: 0xA9, // copyright
	0x00AA: 0xAA, // ordfeminine
	0x00AB: 0xAB, // guillemotleft
	0x00AC: 0xAC, // logicalnot
	0x00AE: 0xAE, // registered
	0x00AF: 0xAF, // macron
	0x00B0: 0xB0, // degree
	0x00B1: 0xB1, // plusminus
	0x00B2: 0xB2, // twosuperior
	0x00B3: 0xB3, // threesuperior
	0x00B4: 0xB4, // acute
	0x00B5: 0xB5, // mu
	0x00B6: 0xB6, // paragraph
	0x00B7: 0xB7, // periodcentered
	0x00B8: 0xB8, // cedilla
	0x00B9: 0xB9, // onesuperior
	0x00BA: 0xBA, // ordmasculine
	0x00BB: 0xBB, // guillemotright
	0x00BC: 0xBC, // onequarter
	0x00BD: 0xBD, // onehalf
	0x00BE: 0xBE, // threequarters
	0x00BF: 0xBF, // questiondown
	0x00C0: 0xC0, // Agrave
	0x00C1: 0xC1, // Aacute
	0x00C2: 0xC2, // Acircumflex
	0x00C3: 0xC3, // Atilde
	0x00C4: 0xC4, // Adieresis
	0x00C5: 0xC5, // Aring
	0x00C6: 0xC6, // AE
	0x00C7: 0xC7, // Ccedilla
	0x00C8: 0xC8, // Egrave
	0x00C9: 0xC9, // Eacute
	0x00CA: 0xCA, // Ecircumflex
	0x00CB: 0xCB, // Edieresis
	0x00CC: 0xCC, // Igrave
	0x00CD: 0xCD, // Iacute
	0x00CE: 0xCE, // Icircumflex
	0x00CF: 0xCF, // Idieresis
	0x00D0: 0xD0, // Eth
	0x00D1: 0xD1, // Ntilde
	0x00D2: 0xD2, // Ograve
	0x00D3: 0xD3, // Oacute
	0x00D4: 0xD4, // Ocircumflex
	0x00D5: 0xD5, // Otilde
	0x00D6: 0xD6, // Odieresis
	0x00D7: 0xD7, // multiply
	0x00D8: 0xD8, // Oslash
	0x00D9: 0xD9, // Ugrave
	0x00DA: 0xDA, // Uacute
	0x00DB: 0xDB, // Ucircumflex
	0x00DC: 0xDC, // Udieresis
	0x00DD: 0xDD, // Yacute
	0x00DE: 0xDE, // Thorn
	0x00DF: 0xDF, // germandbls
	0x00E0: 0xE0, // agrave
	0x00E1: 0xE1, // aacute
	0x00E2: 0xE2, // acircumflex
	0x00E3: 0xE3, // atilde
	0x00E4: 0xE4, // adieresis
	0x00E5: 0xE5, // aring
	0x00E6: 0xE6, // ae
	0x00E7: 0xE7, // ccedilla
	0x00E8: 0xE8, // egrave
	0x00E9: 0xE9, // eacute
	0x00EA: 0xEA, // ecircumflex
	0x00EB: 0xEB, // edieresis
	0x00EC: 0xEC, // igrave
	0x00ED: 0xED, // iacute
	0x00EE: 0xEE, // icircumflex
	0x00EF: 0xEF, // idieresis
	0x00F0: 0xF0, // eth
	0x00F1: 0xF1, // ntilde
	0x00F2: 0xF2, // ograve
	0x00F3: 0xF3, // oacute
	0x00F4: 0xF4, // ocircumflex
	0x00F5: 0xF5, // otilde
	0x00F6: 0xF6, // odieresis
	0x00F7: 0xF7, // divide
	0x00F8: 0xF8, // oslash
	0x00F9: 0xF9, // ugrave
	0x00FA: 0xFA, // uacute
	0x00FB: 0xFB, // ucircumflex
	0x00FC: 0xFC, // udieresis
	0x00FD: 0xFD, // yacute
	0x00FE: 0xFE, // thorn
	0x00FF: 0xFF, // ydieresis
}

// spaceFolds are runes whose only content is "there is a gap here". Rendering
// them as an ordinary space preserves everything the character carried, so
// these are folded quietly rather than reported as substitutions.
var spaceFolds = map[rune]byte{
	'\t':   ' ',
	'\n':   ' ',
	'\r':   ' ',
	0x2002: ' ', // en space
	0x2003: ' ', // em space
	0x2007: ' ', // figure space
	0x2009: ' ', // thin space
	0x200A: ' ', // hair space
	0x202F: ' ', // narrow no-break space
}

// invisible are runes that mark a position rather than print one. WinAnsi has a
// byte for the soft hyphen at 0xAD, and the standard fonts draw it as an
// ordinary hyphen: a soft hyphen only shows where a line breaks at it, and this
// layout does not hyphenate, so setting it would put a hyphen in the middle of
// a word its author never wrote. They contribute nothing to see, so removing
// them loses nothing and they are not reported as substitutions.
var invisible = map[rune]bool{
	0x00AD: true, // soft hyphen
	0x200B: true, // zero width space: zero width means zero ink
	0x2060: true, // word joiner
	0xFEFF: true, // byte order mark used as a zero width no-break space
	0x200C: true, // zero width non-joiner
	0x200D: true, // zero width joiner
}

// Substitution records a rune that WinAnsiEncoding cannot represent, together
// with the marker printed in its place and how often it occurred.
//
// It exists because a document offered as evidence must never quietly lose a
// character. Callers are expected to surface these, not ignore them.
type Substitution struct {
	Rune   rune
	Marker string
	Count  int
}

// String renders a substitution for an operator-facing message.
func (s Substitution) String() string {
	return fmt.Sprintf("%s (%q) x%d", s.Marker, s.Rune, s.Count)
}

// marker is what gets printed in place of a rune the standard fonts have no
// glyph for. The bracketed code point is unmistakably not prose, so a reader
// can see that something was there and what it was.
func marker(r rune) string { return fmt.Sprintf("[U+%04X]", r) }

// encode converts s to WinAnsi bytes, replacing anything unrepresentable with
// a visible marker and counting it in subs. It never drops input.
func encode(s string, subs map[rune]int) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 0x20 && r < 0x7F:
			out = append(out, byte(r))
		default:
			if invisible[r] {
				continue
			}
			if b, ok := spaceFolds[r]; ok {
				out = append(out, b)
				continue
			}
			if b, ok := winAnsi[r]; ok {
				out = append(out, b)
				continue
			}
			m := marker(r)
			if subs != nil {
				subs[r]++
			}
			out = append(out, m...)
		}
	}
	return out
}

// substitutions turns the collected counts into a stable, sorted report.
func substitutions(subs map[rune]int) []Substitution {
	if len(subs) == 0 {
		return nil
	}
	out := make([]Substitution, 0, len(subs))
	for r, n := range subs {
		out = append(out, Substitution{Rune: r, Marker: marker(r), Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rune < out[j].Rune })
	return out
}

// FormatSubstitutions renders subs as one operator-facing line, or the empty
// string when nothing was substituted.
func FormatSubstitutions(subs []Substitution) string {
	if len(subs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(subs))
	for _, s := range subs {
		parts = append(parts, s.String())
	}
	return strings.Join(parts, ", ")
}
