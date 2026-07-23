package evidence

import (
	"bufio"
	"io"
)

// maxLineBytes bounds a single JSONL record. Stored transcripts can be large,
// so this sits well above bufio's 64 KiB default.
const maxLineBytes = 16 << 20

type lineScanner struct {
	sc   *bufio.Scanner
	line int
}

func newLineScanner(r io.Reader) *lineScanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	return &lineScanner{sc: sc}
}

func (l *lineScanner) Scan() bool {
	if !l.sc.Scan() {
		return false
	}
	l.line++
	return true
}

func (l *lineScanner) Bytes() []byte { return l.sc.Bytes() }
func (l *lineScanner) Line() int     { return l.line }
func (l *lineScanner) Err() error    { return l.sc.Err() }
