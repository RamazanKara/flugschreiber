package evidence

import (
	"bufio"
	"context"
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

// DefaultCheckpointInterval bounds how much of the log can be rewritten
// unnoticed. Five minutes keeps checkpoints.jsonl small on a busy proxy and
// still narrows the window in which an end-to-end rewrite leaves no
// contradicting signature behind.
const DefaultCheckpointInterval = 5 * time.Minute

// DefaultArchiveShutdownTimeout bounds how long Close waits for outstanding
// uploads. Shutdown that hangs on an unreachable bucket is worse than an
// archive that is one segment behind, because the evidence directory already
// holds every record either way.
const DefaultArchiveShutdownTimeout = 30 * time.Second

var segmentPattern = regexp.MustCompile(`^seg-(\d{8})\.jsonl$`)

// Options configures a Store.
type Options struct {
	Dir             string
	SegmentMaxBytes int64
	SyncInterval    time.Duration
	QueueDepth      int

	// Keys signs checkpoints. When nil, and no Signer is set either, the store
	// writes no checkpoints, which is the hash-chain-only behaviour of M1.
	Keys *KeyPair

	// Signer signs checkpoints instead of Keys when it is set, which is how
	// the private key stops having to live beside the evidence. Verification
	// is unaffected: it needs the public keys on disk and nothing else.
	Signer Signer

	// CheckpointInterval is how often the head is attested while the log is
	// being appended to. Defaults to DefaultCheckpointInterval.
	CheckpointInterval time.Duration

	// Timestamper anchors checkpoints with an RFC 3161 authority. When it is
	// set, checkpoints are anchored on the interval below, which upgrades their
	// time from this host's claim to a third party's. Anchoring never blocks a
	// write and never fails one; internal/custody has the HTTP implementation.
	Timestamper Timestamper

	// TSAInterval bounds how often a checkpoint is anchored. Defaults to
	// DefaultTSAInterval.
	TSAInterval time.Duration

	// TSATimeout bounds one round trip to the authority. Defaults to
	// DefaultTSATimeout.
	TSATimeout time.Duration

	// Archiver copies sealed segments, the checkpoints and the public key to a
	// second location. It is optional, it is never on the append path, and a
	// backend that is down or misconfigured cannot fail a write: the local
	// segment is always the primary copy.
	Archiver Archiver

	// ArchivePrefix is prepended to every object key, which is how several
	// installations share one bucket. It may be empty.
	ArchivePrefix string

	// ArchiveQueueDepth bounds outstanding uploads. Defaults to
	// DefaultArchiveQueueDepth.
	ArchiveQueueDepth int

	// ArchiveShutdownTimeout bounds how long Close waits for uploads to drain.
	// Defaults to DefaultArchiveShutdownTimeout. An unreachable object store
	// delays shutdown by at most this long.
	ArchiveShutdownTimeout time.Duration

	// ForceWriterLock takes the evidence directory even when another writer
	// appears to hold it. It exists for the shared-volume case after a node
	// failure, where the holder is on a host this process cannot ask about.
	// Setting it while a writer really is running breaks the chain permanently.
	ForceWriterLock bool

	// Now is injectable so that tests and golden files are deterministic.
	Now func() time.Time
}

// Store is an append-only, hash-chained evidence log split into JSONL
// segments. A single writer goroutine owns the chain state, which is what
// makes the sequence numbers and prev_hash linkage totally ordered without
// callers needing to coordinate.
type Store struct {
	opts Options

	// signer is Options.Signer, or an adapter over Options.Keys, resolved once
	// at Open so that nothing on the write path has to decide which is in use.
	signer Signer

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

	// checkpointSeq is the head the last checkpoint attested to. An idle log
	// is not checkpointed again, so the timer cannot fill checkpoints.jsonl
	// with identical attestations.
	checkpointSeq uint64

	// checkpointIndex and prevCheckpointHash continue the checkpoint chain
	// across restarts. They are recovered from the file at Open, so a deletion
	// that happened while the process was down shows up as a gap rather than
	// being papered over by starting again from zero.
	checkpointIndex    uint64
	prevCheckpointHash string

	appended    atomic.Uint64
	checkpoints atomic.Uint64
	writeErr    atomic.Pointer[error]

	// Archival runs on its own goroutine so that a slow or broken object store
	// cannot add latency to an append, let alone fail one.
	uploads     chan archiveJob
	archiveWG   sync.WaitGroup
	archiveCtx  context.Context
	archiveStop context.CancelFunc

	archiveUploaded atomic.Uint64
	archiveSkipped  atomic.Uint64
	archiveFailed   atomic.Uint64
	archiveErr      atomic.Pointer[error]

	// Timestamping runs on its own goroutine for the same reason archival
	// does: a timestamping authority is somebody else's service, and it must
	// not be able to add latency to an append, let alone fail one.
	tsaJobs chan timestampJob
	tsaWG   sync.WaitGroup
	tsaCtx  context.Context
	tsaStop context.CancelFunc

	// lastTimestampAt is owned by the writer goroutine.
	lastTimestampAt time.Time

	timestamped atomic.Uint64
	tsaFailed   atomic.Uint64
	tsaErr      atomic.Pointer[error]
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
	if opts.CheckpointInterval <= 0 {
		opts.CheckpointInterval = DefaultCheckpointInterval
	}
	if opts.ArchiveQueueDepth <= 0 {
		opts.ArchiveQueueDepth = DefaultArchiveQueueDepth
	}
	if opts.ArchiveShutdownTimeout <= 0 {
		opts.ArchiveShutdownTimeout = DefaultArchiveShutdownTimeout
	}
	if opts.TSAInterval <= 0 {
		opts.TSAInterval = DefaultTSAInterval
	}
	if opts.TSATimeout <= 0 {
		opts.TSATimeout = DefaultTSATimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("evidence: create data dir: %w", err)
	}

	s := &Store{
		opts:     opts,
		signer:   resolveSigner(opts),
		queue:    make(chan *Event, opts.QueueDepth),
		done:     make(chan struct{}),
		prevHash: GenesisHash,
	}
	// An external signer's public key still has to reach the evidence
	// directory, or the checkpoints it signs are unverifiable by whoever holds
	// the log. Writing it when it is absent, and refusing when it contradicts
	// what is already there, is exactly how the built-in key is handled.
	if opts.Signer != nil {
		if err := reconcilePublicKey(opts.Dir, opts.Signer.Public()); err != nil {
			return nil, err
		}
	}

	segs, err := Segments(opts.Dir)
	if err != nil {
		return nil, err
	}
	seq, prevHash, err := recoverChainHead(opts.Dir, segs)
	if err != nil {
		return nil, err
	}
	s.seq = seq
	s.prevHash = prevHash
	// A restart with no traffic should not append a checkpoint that says
	// nothing the previous one did not.
	s.checkpointSeq = seq

	if err := s.recoverCheckpointChain(); err != nil {
		return nil, err
	}

	if len(segs) > 0 {
		last := segs[len(segs)-1]
		s.segIndex = last.Index
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

	// The lock is claimed before any background worker starts, so that a
	// failure here cannot leave goroutines running behind a Store that Open
	// never returned.
	if err := claimWriterLock(opts.Dir, opts.ForceWriterLock); err != nil {
		return nil, err
	}

	if opts.Archiver != nil {
		s.uploads = make(chan archiveJob, opts.ArchiveQueueDepth)
		s.archiveCtx, s.archiveStop = context.WithCancel(context.Background())
		s.archiveWG.Add(1)
		go s.archiveLoop()
		// The public key is what makes an archived checkpoint checkable, so it
		// goes up before the first segment rather than only at shutdown, which
		// a crash never reaches.
		s.archiveVerificationKeys()
		s.archiveCatchUp(segs)
	}

	if opts.Timestamper != nil {
		s.tsaJobs = make(chan timestampJob, tsaQueueDepth)
		s.tsaCtx, s.tsaStop = context.WithCancel(context.Background())
		s.tsaWG.Add(1)
		go s.timestampLoop()
	}

	s.wg.Add(1)
	go s.run()
	return s, nil
}

// resolveSigner picks the signing path once. An explicit Signer wins over a
// key file: an operator who has moved custody off the host has said which one
// they mean, and silently preferring the local key would be the one mistake
// that makes the move pointless.
func resolveSigner(opts Options) Signer {
	if opts.Signer != nil {
		return opts.Signer
	}
	if opts.Keys != nil {
		return NewKeyPairSigner(opts.Keys)
	}
	return nil
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

// Checkpoints reports how many signed checkpoints this store has written.
func (s *Store) Checkpoints() uint64 { return s.checkpoints.Load() }

// Err reports the first write error the background writer hit, if any.
func (s *Store) Err() error {
	if err := s.writeErr.Load(); err != nil {
		return *err
	}
	return nil
}

// Close drains the queue, flushes and fsyncs. Records already accepted by
// Append are written before Close returns.
//
// The timestamper is drained before the archive, and the anchors are offered to
// the archive once more afterwards. The order matters on the last shutdown an
// installation ever performs: anchors are appended by the timestamping
// goroutine, so the one over a run's final checkpoint lands in timestamps.jsonl
// after the archive has already snapshotted that file. Draining the other way
// round converges on the next start, and a host that is being decommissioned
// has no next start.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.queue)
		s.wg.Wait()
		close(s.done)
		s.stopTimestamps()
		s.archiveTimestamps()
		s.stopArchive()
		removeWriterLock(s.opts.Dir)
	})
	return s.closeErr
}

// drainCancelGrace is how long shutdown waits after cancelling work that is
// still in flight. An implementation that honours its context returns almost
// immediately; one that does not is abandoned rather than allowed to block the
// process.
const drainCancelGrace = 2 * time.Second

// stopArchive drains the upload queue, but only for as long as it is worth
// waiting. Nothing in the evidence directory depends on the archive, so an
// object store that has stopped answering delays shutdown by the timeout and
// then loses its outstanding uploads rather than holding the process open.
func (s *Store) stopArchive() {
	if s.uploads == nil {
		return
	}
	// The writer goroutine has finished, so nothing can queue another job.
	close(s.uploads)

	if drainWithin(&s.archiveWG, s.archiveStop, s.opts.ArchiveShutdownTimeout) {
		return
	}
	s.recordArchiveErr(fmt.Errorf(
		"evidence: archive to %s did not finish within %s of shutdown; the evidence directory %s holds the complete log",
		s.opts.Archiver.Name(), s.opts.ArchiveShutdownTimeout, s.opts.Dir))
}

// drainWithin waits for a background worker to finish what it is doing,
// cancels it when timeout expires, and gives the cancellation a moment to be
// noticed. It reports whether the work drained in time.
//
// Cancelling aborts a transfer in flight for any implementation that honours
// its context, and the caller then counts what could not be shipped. But these
// are interfaces satisfied by code this package does not own, and an
// implementation that ignores cancellation must not be able to hold the
// process open: waiting here without a bound would hand a third party a veto
// over shutdown, which is what the timeout exists to prevent.
func drainWithin(wg *sync.WaitGroup, stop context.CancelFunc, timeout time.Duration) bool {
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
		stop()
		return true
	case <-timer.C:
	}

	stop()
	grace := time.NewTimer(drainCancelGrace)
	defer grace.Stop()
	select {
	case <-drained:
	case <-grace.C:
	}
	return false
}

func (s *Store) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.opts.SyncInterval)
	defer ticker.Stop()
	checkpoints := time.NewTicker(s.opts.CheckpointInterval)
	defer checkpoints.Stop()

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
		case <-checkpoints.C:
			if err := s.checkpoint(); err != nil {
				s.writeErr.CompareAndSwap(nil, &err)
			}
		}
	}
}

// checkpoint attests the current head. The records it covers are fsynced
// first, so a checkpoint never attests to bytes that a power cut could still
// take away.
func (s *Store) checkpoint() error {
	if s.signer == nil || s.seq == 0 || s.seq == s.checkpointSeq {
		return nil
	}
	if err := s.sync(); err != nil {
		return err
	}
	return s.appendCheckpoint(SegmentName(s.segIndex))
}

func (s *Store) appendCheckpoint(segment string) error {
	if s.signer == nil || s.seq == 0 || s.seq == s.checkpointSeq {
		return nil
	}
	c := Checkpoint{
		Version:    CheckpointVersion,
		Segment:    segment,
		Seq:        s.seq,
		RecordHash: s.prevHash,
		// Sequence numbers are contiguous from 1, so the head sequence is also
		// the number of records ever written to this chain. It counts records
		// the log has held, not files still on disk, which is what makes a
		// checkpoint comparable across a later prune.
		Records:   s.seq,
		Timestamp: s.opts.Now().UTC().Format(time.RFC3339Nano),

		Index:              s.checkpointIndex,
		PrevCheckpointHash: s.prevCheckpointHash,
	}
	if err := SignCheckpointWith(s.signer, &c); err != nil {
		return err
	}
	// The linkage signature is added after the checkpoint's own, because it
	// covers that signature: a successor commits to who attested to its
	// predecessor and not only to what was attested.
	if err := SignCheckpointChain(s.signer, &c); err != nil {
		return err
	}
	if err := AppendCheckpoint(s.opts.Dir, c); err != nil {
		return err
	}
	s.checkpointSeq = s.seq
	s.checkpointIndex++
	s.prevCheckpointHash = CheckpointHash(c)
	s.checkpoints.Add(1)
	s.maybeTimestamp(c)
	return nil
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
	// Checkpoint the segment that was just sealed. A completed segment never
	// changes again, so this is the moment its contents become worth attesting
	// to.
	//
	// A checkpoint that cannot be signed is recorded as a store error and the
	// rotation continues, exactly as at shutdown. Returning here instead would
	// abandon the rotation with the old segment closed and no new one open, so
	// an external signer that stops answering would cost every record from that
	// moment on, which is the one thing a signing failure must never do.
	if err := s.appendCheckpoint(SegmentName(s.segIndex)); err != nil {
		s.writeErr.CompareAndSwap(nil, &err)
	}
	// The segment is sealed and will never change again, which is the only
	// state an object store can hold. Queueing it here never blocks: the upload
	// itself happens on the archive goroutine.
	s.archiveSealedSegment(s.segIndex)
	s.archiveCheckpoints()
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
	if err := s.appendCheckpoint(SegmentName(s.segIndex)); err != nil {
		s.writeErr.CompareAndSwap(nil, &err)
	}
	// Shutdown does not rotate, so the segment still open goes up as a snapshot
	// under its own key. Everything needed to check it goes with it.
	if s.segBytes > 0 {
		s.archiveOpenSegment()
	}
	s.archiveCheckpoints()
	s.archiveVerificationKeys()
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

// recoverChainHead works out which record the next append must link to.
//
// It walks backwards to the newest segment that actually holds a record,
// because rotation creates the next segment file before anything is written
// into it: a crash in that window leaves an empty newest segment, and reading
// the head from that file alone would report no head at all. Continuing from
// genesis at that point would start a second chain inside an existing log,
// which Verify reports as tampering even though nothing was tampered with.
//
// When no segment holds a record the log either has never been written to, or
// everything written so far has been pruned. pruned.json settles which: it says
// where the surviving chain legitimately begins, so the next record links to
// the anchor rather than to the genesis hash.
func recoverChainHead(dir string, segs []SegmentInfo) (uint64, string, error) {
	for i := len(segs) - 1; i >= 0; i-- {
		head, err := segmentHead(segs[i].Path)
		if err != nil {
			// A torn final line is the ordinary result of a power loss or a
			// full disk inside the fsync window, and it stops the writer dead.
			// Naming the command that finishes the interrupted write is the
			// difference between a restart and an operator editing evidence by
			// hand, which is the one thing this design tells them never to do.
			if torn, ferr := FindTornRecord(dir); ferr == nil && torn != nil {
				return 0, "", fmt.Errorf(
					"evidence: %s ends in a partial record of %d byte(s) at offset %d, left by a write that did not finish: %w. "+
						"Run flugschreiber repair --dir %s to remove the fragment and record the repair in the chain",
					torn.Segment, torn.Bytes, torn.Offset, err, dir)
			}
			return 0, "", fmt.Errorf("evidence: recover chain head from %s: %w", filepath.Base(segs[i].Path), err)
		}
		if head != nil {
			return head.Seq, head.RecordHash, nil
		}
	}

	anchor, err := ReadPruneAnchor(dir)
	if err != nil {
		return 0, "", fmt.Errorf("evidence: recover chain head: %w", err)
	}
	if anchor == nil {
		return 0, GenesisHash, nil
	}
	if anchor.LastPrunedSeq == 0 || !isChainHash(anchor.LastPrunedHash) {
		return 0, "", fmt.Errorf(
			"evidence: %s records deletion through seq %d with hash %q, which does not say where the surviving chain begins; refusing to append and start a second chain, repair or remove the anchor",
			PruneAnchorFile, anchor.LastPrunedSeq, anchor.LastPrunedHash)
	}
	return anchor.LastPrunedSeq, anchor.LastPrunedHash, nil
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
