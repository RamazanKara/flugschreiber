package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Problem is one integrity failure, located precisely enough to be actionable.
type Problem struct {
	Segment string `json:"segment"`
	Line    int    `json:"line"`
	Seq     uint64 `json:"seq,omitempty"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
}

func (p Problem) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", p.Segment, p.Line, p.Kind, p.Detail)
}

// Kinds of integrity failure.
const (
	ProblemMalformed    = "malformed_record"
	ProblemHashMismatch = "hash_mismatch"
	ProblemBrokenLink   = "broken_link"
	ProblemSeqGap       = "sequence_gap"
	ProblemEmptyDir     = "no_segments"
)

// VerifyResult summarises a verification pass.
type VerifyResult struct {
	Dir       string    `json:"dir"`
	Segments  []string  `json:"segments"`
	Records   uint64    `json:"records"`
	FirstSeq  uint64    `json:"first_seq,omitempty"`
	LastSeq   uint64    `json:"last_seq,omitempty"`
	FirstTime string    `json:"first_time,omitempty"`
	LastTime  string    `json:"last_time,omitempty"`
	HeadHash  string    `json:"head_hash,omitempty"`
	Problems  []Problem `json:"problems,omitempty"`
	Duration  string    `json:"duration"`
}

// OK reports whether the chain verified without any problem.
func (r *VerifyResult) OK() bool { return len(r.Problems) == 0 }

// Verify walks every segment in dir and checks that each record's hash matches
// its contents, that each record links to its predecessor, and that sequence
// numbers are contiguous across segment boundaries.
//
// It reads only the files on disk and needs no running server, so a third
// party can check a chain with nothing but this binary and the evidence
// directory.
func Verify(dir string) (*VerifyResult, error) {
	start := time.Now()
	res := &VerifyResult{Dir: dir}

	segs, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		res.Problems = append(res.Problems, Problem{
			Segment: filepath.Base(dir),
			Kind:    ProblemEmptyDir,
			Detail:  "no seg-*.jsonl files found in evidence directory",
		})
		res.Duration = time.Since(start).String()
		return res, nil
	}

	prevHash := GenesisHash
	var prevSeq uint64

	for _, seg := range segs {
		name := filepath.Base(seg.Path)
		res.Segments = append(res.Segments, name)

		f, err := os.Open(seg.Path)
		if err != nil {
			return nil, err
		}
		sc := newLineScanner(f)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec Record
			if err := json.Unmarshal(line, &rec); err != nil {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(),
					Kind:   ProblemMalformed,
					Detail: err.Error(),
				})
				// The chain head is unknown from here on, so keep reading for
				// a full damage report but stop trusting the linkage.
				prevHash = ""
				continue
			}

			if want := rec.Hash(); want != rec.RecordHash {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(), Seq: rec.Seq,
					Kind:   ProblemHashMismatch,
					Detail: fmt.Sprintf("record_hash is %s, contents hash to %s", short(rec.RecordHash), short(want)),
				})
			}
			if prevHash != "" && rec.PrevHash != prevHash {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(), Seq: rec.Seq,
					Kind:   ProblemBrokenLink,
					Detail: fmt.Sprintf("prev_hash is %s, predecessor hashes to %s", short(rec.PrevHash), short(prevHash)),
				})
			}
			if prevSeq != 0 && rec.Seq != prevSeq+1 {
				res.Problems = append(res.Problems, Problem{
					Segment: name, Line: sc.Line(), Seq: rec.Seq,
					Kind:   ProblemSeqGap,
					Detail: fmt.Sprintf("expected seq %d, found %d", prevSeq+1, rec.Seq),
				})
			}

			if res.Records == 0 {
				res.FirstSeq = rec.Seq
				res.FirstTime = rec.Timestamp
			}
			res.Records++
			res.LastSeq = rec.Seq
			res.LastTime = rec.Timestamp
			res.HeadHash = rec.RecordHash
			prevHash = rec.RecordHash
			prevSeq = rec.Seq
		}
		scanErr := sc.Err()
		f.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read %s: %w", name, scanErr)
		}
	}

	res.Duration = time.Since(start).String()
	return res, nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
