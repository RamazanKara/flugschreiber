package pdf

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// structure is what a reader recovers from a rendered file by following the
// trailer and the cross reference table, the same route a viewer takes.
type structure struct {
	objects map[int][]byte
	trailer string
	root    int
	info    int
	size    int
}

var (
	refPattern     = regexp.MustCompile(`(\d+) 0 R`)
	lengthPattern  = regexp.MustCompile(`/Length (\d+)`)
	trailerPattern = regexp.MustCompile(`/(Size|Root|Info) (\d+)`)
)

// parsePDF walks a rendered file exactly as a reader would: it finds startxref,
// reads the cross reference table, and follows every offset. It deliberately
// does not scan for "obj" markers, because a validator that repairs its input
// cannot tell you whether the input was correct. Poppler, for one, silently
// rebuilds a broken table, so an external tool opening the file proves nothing
// about the table itself.
func parsePDF(data []byte) (*structure, error) {
	if !bytes.HasPrefix(data, []byte("%PDF-1.7\n")) {
		return nil, fmt.Errorf("missing or wrong header: %q", firstLine(data))
	}
	if !bytes.HasSuffix(data, []byte("\n%%EOF\n")) {
		return nil, fmt.Errorf("file does not end with %%%%EOF")
	}

	marker := bytes.LastIndex(data, []byte("\nstartxref\n"))
	if marker < 0 {
		return nil, fmt.Errorf("no startxref")
	}
	rest := string(data[marker+len("\nstartxref\n"):])
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("startxref has no value")
	}
	start, err := strconv.Atoi(rest[:nl])
	if err != nil {
		return nil, fmt.Errorf("startxref value %q is not a number", rest[:nl])
	}
	if start < 0 || start >= len(data) {
		return nil, fmt.Errorf("startxref %d is outside the file", start)
	}

	table := data[start:]
	if !bytes.HasPrefix(table, []byte("xref\n0 ")) {
		return nil, fmt.Errorf("startxref %d does not point at a cross reference table, found %q", start, firstLine(table))
	}
	nl = bytes.IndexByte(table, '\n')
	head := table[nl+1:]
	nl2 := bytes.IndexByte(head, '\n')
	count, err := strconv.Atoi(strings.TrimSpace(string(head[2:nl2])))
	if err != nil {
		return nil, fmt.Errorf("cross reference subsection header %q is malformed", head[:nl2])
	}

	entries := head[nl2+1:]
	if len(entries) < count*20 {
		return nil, fmt.Errorf("cross reference table claims %d entries but only %d bytes remain", count, len(entries))
	}
	s := &structure{objects: map[int][]byte{}, size: count}
	for i := 0; i < count; i++ {
		e := entries[i*20 : i*20+20]
		if len(e) != 20 {
			return nil, fmt.Errorf("entry %d is %d bytes, every entry must be exactly 20", i, len(e))
		}
		kind := e[17]
		if i == 0 {
			if kind != 'f' || string(e[:16]) != "0000000000 65535" {
				return nil, fmt.Errorf("entry 0 must be the free head, got %q", e)
			}
			continue
		}
		if kind != 'n' {
			return nil, fmt.Errorf("entry %d is marked %q, expected in use", i, kind)
		}
		off, err := strconv.Atoi(string(e[:10]))
		if err != nil {
			return nil, fmt.Errorf("entry %d offset %q is not a number", i, e[:10])
		}
		if off <= 0 || off >= len(data) {
			return nil, fmt.Errorf("entry %d points at offset %d, outside the file", i, off)
		}
		want := fmt.Sprintf("%d 0 obj\n", i)
		if !bytes.HasPrefix(data[off:], []byte(want)) {
			return nil, fmt.Errorf("entry %d points at %q, expected %q", i, firstLine(data[off:]), strings.TrimSpace(want))
		}
		end := bytes.Index(data[off:], []byte("\nendobj\n"))
		if end < 0 {
			return nil, fmt.Errorf("object %d has no endobj", i)
		}
		s.objects[i] = data[off+len(want) : off+end]
	}

	tp := bytes.Index(table, []byte("\ntrailer\n"))
	if tp < 0 {
		return nil, fmt.Errorf("no trailer after the cross reference table")
	}
	s.trailer = firstLine(table[tp+len("\ntrailer\n"):])
	for _, m := range trailerPattern.FindAllStringSubmatch(s.trailer, -1) {
		v, _ := strconv.Atoi(m[2])
		switch m[1] {
		case "Size":
			if v != count {
				return nil, fmt.Errorf("trailer /Size is %d but the table has %d entries", v, count)
			}
		case "Root":
			s.root = v
		case "Info":
			s.info = v
		}
	}
	if s.root == 0 {
		return nil, fmt.Errorf("trailer names no /Root")
	}
	if s.info == 0 {
		return nil, fmt.Errorf("trailer names no /Info")
	}
	if !strings.Contains(s.trailer, "/ID [<") {
		return nil, fmt.Errorf("trailer carries no file identifier: %s", s.trailer)
	}

	for num, body := range s.objects {
		for _, m := range refPattern.FindAllStringSubmatch(string(body), -1) {
			target, _ := strconv.Atoi(m[1])
			if _, ok := s.objects[target]; !ok {
				return nil, fmt.Errorf("object %d refers to object %d, which the table does not list", num, target)
			}
		}
		if err := checkStream(num, body); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// checkStream confirms that a declared /Length matches the bytes actually
// present. A stream that lies about its length is the classic way to produce a
// file that opens in one viewer and not in another.
func checkStream(num int, body []byte) error {
	i := bytes.Index(body, []byte("\nstream\n"))
	if i < 0 {
		return nil
	}
	m := lengthPattern.FindSubmatch(body[:i])
	if m == nil {
		return fmt.Errorf("object %d has a stream but no /Length", num)
	}
	declared, _ := strconv.Atoi(string(m[1]))
	data := body[i+len("\nstream\n"):]
	end := bytes.LastIndex(data, []byte("\nendstream"))
	if end < 0 {
		return fmt.Errorf("object %d has a stream with no endstream", num)
	}
	if end != declared {
		return fmt.Errorf("object %d declares /Length %d but carries %d bytes", num, declared, end)
	}
	return nil
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 120 {
		b = b[:120]
	}
	return string(b)
}

// balanced reports whether every open operator in a content stream is closed.
func balanced(stream, open, shut string) bool {
	depth := 0
	for _, f := range strings.Fields(stream) {
		switch f {
		case open:
			depth++
		case shut:
			depth--
		}
		if depth < 0 {
			return false
		}
	}
	return depth == 0
}
