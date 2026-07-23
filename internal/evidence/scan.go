package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Entry pairs a decoded event with the chain metadata of its record.
type Entry struct {
	Record Record
	Event  Event
}

// Walk reads every record in dir in chain order and calls fn for each. It does
// not verify hashes; use Verify for that. Reading and verifying are kept apart
// so that a damaged log can still be inspected.
func Walk(dir string, fn func(Entry) error) error {
	segs, err := Segments(dir)
	if err != nil {
		return err
	}
	for _, seg := range segs {
		f, err := os.Open(seg.Path)
		if err != nil {
			return err
		}
		sc := newLineScanner(f)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec Record
			if err := json.Unmarshal(line, &rec); err != nil {
				f.Close()
				return fmt.Errorf("%s:%d: %w", filepath.Base(seg.Path), sc.Line(), err)
			}
			ev, err := rec.DecodeEvent()
			if err != nil {
				f.Close()
				return fmt.Errorf("%s:%d: decode event: %w", filepath.Base(seg.Path), sc.Line(), err)
			}
			if err := fn(Entry{Record: rec, Event: *ev}); err != nil {
				f.Close()
				return err
			}
		}
		scanErr := sc.Err()
		f.Close()
		if scanErr != nil {
			return scanErr
		}
	}
	return nil
}
