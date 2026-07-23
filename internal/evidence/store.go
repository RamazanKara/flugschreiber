package evidence

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultSegmentMaxBytes caps a segment at 64 MiB, which keeps a single
// segment comfortably readable by line-oriented tools and bounds the cost of
// re-verifying after an append.
const DefaultSegmentMaxBytes int64 = 64 << 20

// DefaultSyncInterval is how often the writer calls fsync. Every record is
// flushed to the operating system immediately, so this window only covers loss
// from a machine-level crash, not from the process exiting.
const DefaultSyncInterval = time.Second

var segmentPattern = regexp.MustCompile(`^seg-(\d{8})\.jsonl$`)

// Options configures a Store.
type Options struct {
	Dir             string
	SegmentMaxBytes int64
	SyncInterval    time.Duration
	QueueDepth      int

	// Now is injectable so that tests and golden files are deterministic.
	Now func() time.Time
}

// Store is an append-only, hash-chained evidence log split into JSONL
// segments. A single writer goroutine owns the chain state, which is what
// makes the sequence numbers and prev_hash linkage totally ordered without
// callers needing to coordinate.
type Store struct {
	opts Options

	queue chan *Event
	done  chan struct{}
	wg    sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool

	// Owned by the writer goroutine after Open returns.
	file     *os.File
	buf      *bufio.Writer
	segIndex int
	segBytes int64
	seq      uint64
	prevHash string
	dirty    bool

	appended atomic.Uint64
	writeErr atomic.Pointer[error]
}

// Open prepares dir for appending, recovering the chain head from the newest
// existing segment. An existing log is continued, never rewritten.
func Open(opts Options) (*Store, error) {
	if opts.Dir == "" {
		return nil, errors.New("evidence: Dir is required")
	}
	if opts.SegmentMaxBytes <= 0 {
		opts.SegmentMaxBytes = DefaultSegmentMaxBytes
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = DefaultSyncInterval
	}
	if opts.QueueDepth <= 0 {
		opts.QueueDepth = 4096
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("evidence: create data dir: %w", err)
	}

	s := &Store{
		opts:     opts,
		queue:    make(chan *Event, opts.QueueDepth),
		done:     make(chan struct{}),
		prevHash: GenesisHash,
	}

	segs, err := Segments(opts.Dir)
	if err != nil {
		return nil, err
	}
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		head, err := segmentHead(last.Path)
		if err != nil {
			return nil, fmt.Errorf("evidence: recover chain head from %s: %w", filepath.Base(last.Path), err)
		}
		s.segIndex = last.Index
		if head != nil {
			s.seq = head.Seq
			s.prevHash = head.RecordHash
		}
		info, err := os.Stat(last.Path)
		if err != nil {
			return nil, err
		}
		s.segBytes = info.Size()
		f, err := os.OpenFile(last.Path, os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		s.file = f
	} else {
		s.segIndex = 1
		if err := s.openSegment(); err != nil {
			return nil, err
		}
	}
	s.buf = bufio.NewWriterSize(s.file, 64<<10)

	s.wg.Add(1)
	go s.run()
	return s, nil
}

// Append enqueues an event. It blocks if the writer is behind, applying
// backpressure to the proxy rather than dropping evidence, which is the whole
// point of the tool.
func (s *Store) Append(e *Event) error {
	if s.closed.Load() {
		return errors.New("evidence: store is closed")
	}
	if e.SchemaVersion == 0 {
		e.SchemaVersion = SchemaVersion
	}
	if err := s.writeErr.Load(); err != nil {
		return *err
	}
	select {
	case s.queue <- e:
		return nil
	case <-s.done:
		return errors.New("evidence: store is closed")
	}
}

// Appended reports how many records have been durably handed to the OS.
func (s *Store) Appended() uint64 { return s.appended.Load() }

// Err reports the first write error the background writer hit, if any.
func (s *Store) Err() error {
	if err := s.writeErr.Load(); err != nil {
		return *err
	}
	return nil
}

// Close drains the queue, flushes and fsyncs. Records already accepted by
// Append are written before Close returns.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.queue)
		s.wg.Wait()
		close(s.done)
	})
	return s.closeErr
}

func (s *Store) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.opts.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case e, ok := <-s.queue:
			if !ok {
				s.closeErr = s.shutdown()
				return
			}
			if err := s.write(e); err != nil {
				s.writeErr.CompareAndSwap(nil, &err)
			}
		case <-ticker.C:
			if err := s.sync(); err != nil {
				s.writeErr.CompareAndSwap(nil, &err)
			}
		}
	}
}

func (s *Store) write(e *Event) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("evidence: marshal event: %w", err)
	}

	seq := s.seq + 1
	ts := s.opts.Now().UTC().Format(time.RFC3339Nano)
	rec := Record{
		Seq:        seq,
		Timestamp:  ts,
		PrevHash:   s.prevHash,
		RecordHash: ComputeHash(seq, ts, s.prevHash, payload),
		Event:      payload,
	}
	line, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("evidence: marshal record: %w", err)
	}
	line = append(line, '\n')

	if s.segBytes > 0 && s.segBytes+int64(len(line)) > s.opts.SegmentMaxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	if _, err := s.buf.Write(line); err != nil {
		return fmt.Errorf("evidence: write record: %w", err)
	}
	// Flush per record so that a process crash cannot lose an event that the
	// proxy has already reported as captured.
	if err := s.buf.Flush(); err != nil {
		return fmt.Errorf("evidence: flush record: %w", err)
	}

	s.seq = seq
	s.prevHash = rec.RecordHash
	s.segBytes += int64(len(line))
	s.dirty = true
	s.appended.Add(1)
	return nil
}

func (s *Store) rotate() error {
	if err := s.closeSegment(); err != nil {
		return err
	}
	s.segIndex++
	s.segBytes = 0
	if err := s.openSegment(); err != nil {
		return err
	}
	s.buf.Reset(s.file)
	return nil
}

func (s *Store) openSegment() error {
	path := filepath.Join(s.opts.Dir, SegmentName(s.segIndex))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("evidence: open segment: %w", err)
	}
	s.file = f
	return nil
}

func (s *Store) closeSegment() error {
	if s.file == nil {
		return nil
	}
	if err := s.buf.Flush(); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	return s.file.Close()
}

func (s *Store) sync() error {
	if !s.dirty || s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("evidence: fsync: %w", err)
	}
	s.dirty = false
	return nil
}

func (s *Store) shutdown() error {
	if err := s.closeSegment(); err != nil {
		return err
	}
	s.file = nil
	return s.Err()
}

// SegmentName renders the file name for a segment index.
func SegmentName(index int) string {
	return fmt.Sprintf("seg-%08d.jsonl", index)
}

// SegmentInfo locates one segment file.
type SegmentInfo struct {
	Index int
	Path  string
}

// Segments lists the segment files in dir, ordered by index.
func Segments(dir string) ([]SegmentInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SegmentInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		m := segmentPattern.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		out = append(out, SegmentInfo{Index: idx, Path: filepath.Join(dir, entry.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// segmentHead returns the last record of a segment, or nil if it is empty. A
// truncated final line is treated as an error rather than silently skipped:
// the chain head must be known exactly before anything is appended to it.
func segmentHead(path string) (*Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := newLineScanner(f)
	var last *Record
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("line %d: %w", sc.Line(), err)
		}
		rec := r
		last = &rec
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return last, nil
}
