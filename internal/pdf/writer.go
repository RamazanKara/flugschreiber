package pdf

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
	"unicode/utf16"
)

// version is the PDF version claimed in the header. Everything this package
// emits is 1.4 syntax; 1.7 is claimed because it is what current viewers
// expect to see and nothing here is newer than 1.4.
const version = "1.7"

// writer accumulates indirect objects and serialises them with a cross
// reference table. Object numbers are handed out before bodies are known,
// because a page has to name its parent and the page tree has to name its
// children.
type writer struct {
	bodies [][]byte
}

// reserve allocates an object number whose body is filled in later.
func (w *writer) reserve() int {
	w.bodies = append(w.bodies, nil)
	return len(w.bodies)
}

// set fills in a reserved object.
func (w *writer) set(num int, body []byte) { w.bodies[num-1] = body }

// add appends an object and returns its number.
func (w *writer) add(body []byte) int {
	n := w.reserve()
	w.set(n, body)
	return n
}

// addf is add with formatting, for the many small dictionaries.
func (w *writer) addf(format string, args ...any) int {
	return w.add([]byte(fmt.Sprintf(format, args...)))
}

// addStream appends a stream object. dict must not contain /Length; it is
// added here so it can never disagree with the data.
//
// Streams are written uncompressed on purpose. These documents are tens of
// kilobytes, and a file whose text can be read with a pager is worth more to
// this project than a smaller one: an auditor can confirm what the tool wrote
// without trusting the tool.
func (w *writer) addStream(dict string, data []byte) int {
	var b bytes.Buffer
	b.WriteString("<< ")
	if dict != "" {
		b.WriteString(dict)
		b.WriteByte(' ')
	}
	fmt.Fprintf(&b, "/Length %d >>\nstream\n", len(data))
	b.Write(data)
	b.WriteString("\nendstream")
	return w.add(b.Bytes())
}

// fingerprint hashes every object body. It is used for the file identifier so
// that rendering the same input twice produces the same bytes, which is what
// lets an operator show that a PDF they hold is the one the tool produced.
func (w *writer) fingerprint() []byte {
	var b bytes.Buffer
	for _, body := range w.bodies {
		b.Write(body)
	}
	return b.Bytes()
}

// serialise writes the complete file. It fails rather than emitting a
// structurally broken document if an object was reserved and never filled in.
func (w *writer) serialise(root, info int, id []byte) ([]byte, error) {
	for i, body := range w.bodies {
		if body == nil {
			return nil, fmt.Errorf("pdf: object %d was reserved but never written, refusing to emit a broken cross reference table", i+1)
		}
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, "%%PDF-%s\n", version)
	// A comment with high bytes tells file transfer tools and viewers to
	// treat the file as binary rather than text.
	out.Write([]byte{'%', 0xE2, 0xE3, 0xCF, 0xD3, '\n'})

	offsets := make([]int, len(w.bodies))
	for i, body := range w.bodies {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", i+1)
		out.Write(body)
		out.WriteString("\nendobj\n")
	}

	startxref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", len(w.bodies)+1)
	// Every entry is exactly 20 bytes including the two byte end of line,
	// which readers that seek into the table depend on.
	out.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}

	h := hex.EncodeToString(id)
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /ID [<%s> <%s>] >>\n",
		len(w.bodies)+1, root, info, h, h)
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", startxref)
	return out.Bytes(), nil
}

// literal renders b as a PDF literal string. Everything outside printable
// ASCII becomes an octal escape, which keeps the file itself ASCII and so
// greppable, and removes any question about how a reader treats a raw newline
// inside a string.
func literal(b []byte) string {
	var out bytes.Buffer
	out.WriteByte('(')
	for _, c := range b {
		switch {
		case c == '(' || c == ')' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c < 0x20 || c > 0x7E:
			fmt.Fprintf(&out, "\\%03o", c)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte(')')
	return out.String()
}

// textString renders s for a metadata or outline entry. Plain ASCII stays a
// literal so the metadata is readable in a text editor; anything else goes out
// as UTF-16BE with a byte order mark, the only encoding PDF guarantees for the
// full range of Unicode.
func textString(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			ascii = false
			break
		}
	}
	if ascii {
		return literal([]byte(s))
	}
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+2*len(units))
	buf = append(buf, 0xFE, 0xFF)
	for _, u := range units {
		buf = append(buf, byte(u>>8), byte(u))
	}
	return "<" + hex.EncodeToString(buf) + ">"
}

// pdfDate formats t as a PDF date string.
func pdfDate(t time.Time) string {
	_, off := t.Zone()
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	return fmt.Sprintf("D:%s%s%02d'%02d'", t.Format("20060102150405"), sign, off/3600, (off%3600)/60)
}

// num formats a coordinate. Two decimals is finer than any viewer renders and
// keeps the content stream stable across platforms, since it never depends on
// how a float prints by default.
func num(v float64) string {
	if v == 0 {
		// Avoid emitting negative zero, which some tools echo back oddly.
		v = 0
	}
	s := strconv.FormatFloat(v, 'f', 2, 64)
	// Trim a trailing ".00" and any trailing zero, purely to keep the
	// content stream readable.
	if i := len(s) - 1; s[i] == '0' {
		s = s[:i]
		if s[len(s)-1] == '0' {
			s = s[:len(s)-1]
		}
		if s[len(s)-1] == '.' {
			s = s[:len(s)-1]
		}
	}
	return s
}
