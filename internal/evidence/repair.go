package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// TornRecord describes a partial final line in a segment: bytes that a write
// began and a power loss or a full disk cut short.
//
// It is not a record. Nothing counted it, no hash covers it, and no checkpoint
// attests to it, so removing it destroys nothing that was ever evidence. That
// is the whole reason a repair is safe to offer at all, and it is why Repair
// will only ever touch the last line of the last segment.
type TornRecord struct {
	Segment string `json:"segment"`

	// Offset is where the good bytes end and the fragment begins.
	Offset int64 `json:"offset"`

	// Bytes is how many bytes the fragment occupies.
	Bytes int64 `json:"bytes"`

	// Line is the 1-based line number of the fragment.
	Line int `json:"line"`

	// Preview is the fragment itself when it is short enough to show, so an
	// operator can see what they are about to remove rather than trusting a
	// byte count.
	Preview string `json:"preview,omitempty"`

	// Detail is the parse error the fragment produced.
	Detail string `json:"detail"`
}

// maxTornPreview bounds what a repair prints back. A fragment is at most one
// record, but a record can hold stored content, and an operator does not need
// a prompt echoed at them to decide.
const maxTornPreview = 200

// refuseIfAttested stops a repair that would destroy evidence.
//
// The premise of this command is that the fragment was never a complete record.
// A checkpoint attesting to a sequence beyond what survives says otherwise: the
// record completed, it was signed for, and something damaged it afterwards.
// That is disk corruption or tampering, and truncating it would quietly delete
// attested evidence and leave the signature contradicting the log forever.
//
// So the tool refuses and says what it found. Getting this wrong in the other
// direction, refusing an ordinary interrupted write, costs a support question;
// getting it wrong this way destroys the thing the operator is holding.
func refuseIfAttested(dir string, torn *TornRecord) error {
	checks, err := ReadCheckpoints(dir)
	if err != nil {
		return fmt.Errorf("evidence: repair: cannot read the checkpoints to see what is attested: %w", err)
	}
	if len(checks) == 0 {
		return nil
	}

	segs, err := Segments(dir)
	if err != nil {
		return err
	}
	var surviving uint64
	for i := len(segs) - 1; i >= 0 && surviving == 0; i-- {
		head, headErr := segmentHeadBefore(segs[i].Path, torn)
		if headErr != nil {
			return fmt.Errorf("evidence: repair: cannot read %s: %w", filepath.Base(segs[i].Path), headErr)
		}
		if head != nil {
			surviving = head.Seq
		}
	}

	for _, c := range checks {
		if c.Seq > surviving {
			return fmt.Errorf(
				"evidence: refusing to repair %s: the checkpoint of %s attests to seq %d and only seq %d would survive the truncation, "+
					"so the damaged bytes were a completed record that was signed for rather than a write that never finished. "+
					"This is corruption or tampering, not an interrupted append. Preserve this directory and run flugschreiber verify --dir %s",
				torn.Segment, c.Timestamp, c.Seq, surviving, dir)
		}
	}
	return nil
}

// segmentHeadBefore returns the last intact record of a segment, ignoring the
// torn fragment at its end.
func segmentHeadBefore(path string, torn *TornRecord) (*Record, error) {
	if filepath.Base(path) != torn.Segment {
		return segmentHead(path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if torn.Offset > int64(len(raw)) {
		return nil, fmt.Errorf("the fragment starts past the end of the file")
	}
	return lastRecordIn(raw[:torn.Offset])
}

// lastRecordIn returns the final record in a run of complete lines.
func lastRecordIn(raw []byte) (*Record, error) {
	var last *Record
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		rec := r
		last = &rec
	}
	return last, nil
}

// FindTornRecord reports a partial final line in the newest segment, or nil
// when there is nothing to repair.
//
// Only the final line of the final segment can be torn. Damage anywhere else
// was not caused by an interrupted append, and this function deliberately does
// not offer to remove it: that would be a tool for editing evidence rather than
// for finishing a write the machine did not.
func FindTornRecord(dir string) (*TornRecord, error) {
	segs, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return nil, nil
	}
	last := segs[len(segs)-1]

	raw, err := os.ReadFile(last.Path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	// A segment that ends in a newline ends on a record boundary. Whatever is
	// wrong with it, an interrupted append is not it.
	if raw[len(raw)-1] == '\n' {
		return nil, nil
	}

	cut := bytes.LastIndexByte(raw, '\n') + 1
	fragment := raw[cut:]
	if len(bytes.TrimSpace(fragment)) == 0 {
		return nil, nil
	}

	// A final line with no newline may still be a whole record, if the process
	// died between the write and the newline. That parses, and it is evidence.
	var rec Record
	if err := json.Unmarshal(fragment, &rec); err == nil {
		return nil, nil
	} else {
		preview := string(fragment)
		if len(preview) > maxTornPreview {
			preview = preview[:maxTornPreview] + "..."
		}
		return &TornRecord{
			Segment: filepath.Base(last.Path),
			Offset:  int64(cut),
			Bytes:   int64(len(fragment)),
			Line:    bytes.Count(raw[:cut], []byte{'\n'}) + 1,
			Preview: preview,
			Detail:  err.Error(),
		}, nil
	}
}

// Repair removes a torn trailing fragment so that the writer can continue.
//
// It refuses while a writer holds the directory, because truncating a file
// underneath an open writer is how one problem becomes two. It returns what it
// removed so the caller can record the repair in the chain: a log that quietly
// loses bytes is exactly what this project exists to make impossible, so a
// repair has to leave its own account behind.
func Repair(dir string) (*TornRecord, error) {
	if err := refuseWhileWriterHolds(dir, "repair the log"); err != nil {
		return nil, err
	}
	torn, err := FindTornRecord(dir)
	if err != nil || torn == nil {
		return nil, err
	}
	if err := refuseIfAttested(dir, torn); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, torn.Segment)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("evidence: repair %s: %w", torn.Segment, err)
	}
	if err := f.Truncate(torn.Offset); err != nil {
		f.Close()
		return nil, fmt.Errorf("evidence: repair %s: %w", torn.Segment, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("evidence: fsync %s after repair: %w", torn.Segment, err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	syncDir(dir)
	return torn, nil
}
