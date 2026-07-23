package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultArchiveQueueDepth bounds how many uploads may be outstanding. It is
// small on purpose: a store that is rotating segments faster than the archive
// can absorb them has an archive problem, and the useful response is to say so
// rather than to grow a queue until the process runs out of memory.
const DefaultArchiveQueueDepth = 64

// Archiver stores one immutable object per key.
//
// The method set is exactly the one internal/archive implements, so its
// backends satisfy this interface with no adapter, and the dependency points
// the right way: the evidence core knows nothing about object stores,
// credentials or HTTP, and cannot be made to depend on them.
//
// Put must be safe to call again with the same key and the same bytes, which
// is what a restart produces. Every key this package hands to an Archiver names
// content that is final at the moment it is written, so nothing here ever asks
// a backend to change an object it already holds. That is what makes an
// object-lock (WORM) bucket a usable target.
type Archiver interface {
	// Put writes size bytes read from body under key.
	Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error

	// Exists reports whether key is already present. An error means unknown
	// rather than absent.
	Exists(ctx context.Context, key string) (bool, error)

	// Name is the backend kind, low cardinality, suitable as a metric label.
	Name() string
}

// ArchiveStats reports what the background archiver has done since the store
// was opened. It is the input for flugschreiber_archive_uploads_total, where
// Backend is the {backend} label and the three counters are the {result} one.
type ArchiveStats struct {
	Backend  string `json:"backend"`
	Uploaded uint64 `json:"uploaded"`
	Skipped  uint64 `json:"skipped"`
	Failed   uint64 `json:"failed"`
}

// archiveJob is one file to copy, named by the key it will live under.
type archiveJob struct {
	key  string
	path string
}

// ArchiveStats reports the archiver's progress. It is safe to call at any time
// and returns zeroes when no Archiver is configured.
func (s *Store) ArchiveStats() ArchiveStats {
	st := ArchiveStats{
		Uploaded: s.archiveUploaded.Load(),
		Skipped:  s.archiveSkipped.Load(),
		Failed:   s.archiveFailed.Load(),
	}
	if s.opts.Archiver != nil {
		st.Backend = s.opts.Archiver.Name()
	}
	return st
}

// ArchiveErr reports the most recent archival failure, or nil if there has not
// been one.
//
// It is deliberately separate from Err. A failing archive is not a failing
// store: the local segment is the primary copy and stays complete whatever the
// object store does, so an upload failure is reported and counted but never
// turned into a write error that would stop the proxy recording.
func (s *Store) ArchiveErr() error {
	if err := s.archiveErr.Load(); err != nil {
		return *err
	}
	return nil
}

// archiveKey renders the key for one file below the configured prefix.
func (s *Store) archiveKey(name string) string {
	prefix := strings.Trim(s.opts.ArchivePrefix, "/")
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

// archiveSealedSegment queues the segment that rotation has just sealed. A
// sealed segment never changes again, which is the only reason it can be
// uploaded at all: object stores cannot append.
func (s *Store) archiveSealedSegment(index int) {
	name := SegmentName(index)
	s.enqueueUpload(s.archiveKey(name), filepath.Join(s.opts.Dir, name))
}

// archiveOpenSegment queues a snapshot of the segment that is still being
// written, which is what shutdown has to work with because it does not rotate.
//
// The snapshot gets its own key, carrying the head sequence it covers, so that
// it never collides with the final upload of the same segment once a later run
// seals it. Overwriting one object with a longer version of itself is exactly
// what a locked bucket refuses, and it would also silently replace evidence
// that is already archived.
func (s *Store) archiveOpenSegment() {
	name := SegmentName(s.segIndex)
	key := fmt.Sprintf("open/%s.seq-%012d.jsonl", strings.TrimSuffix(name, ".jsonl"), s.seq)
	s.enqueueUpload(s.archiveKey(key), filepath.Join(s.opts.Dir, name))
}

// archiveCheckpoints queues the checkpoint file as it stands, keyed by the head
// it attests to. Checkpoints are what let a reader of the archive check the
// segments in it, so they travel with them rather than only at shutdown, which
// a crash never reaches.
func (s *Store) archiveCheckpoints() {
	if s.opts.Keys == nil || s.checkpointSeq == 0 {
		return
	}
	key := fmt.Sprintf("checkpoints/checkpoints.seq-%012d.jsonl", s.checkpointSeq)
	s.enqueueUpload(s.archiveKey(key), filepath.Join(s.opts.Dir, CheckpointsFile))
}

// archiveCatchUp queues every sealed segment and the current checkpoint file,
// so an upload that failed in an earlier run, or a run that died before its
// shutdown drain, converges on the next start instead of leaving a permanent
// hole in the archive. Exists makes the common case cheap: a segment already
// in the bucket costs one HEAD and is counted as skipped.
//
// The enqueue is the writer-safe non-blocking one, so a backlog larger than
// the queue converges over several restarts rather than blocking Open; what
// could not be queued is counted and reported through ArchiveErr.
func (s *Store) archiveCatchUp(segs []SegmentInfo) {
	if len(segs) == 0 {
		return
	}
	// The newest segment is still being appended to; shutdown snapshots it
	// under its own key. Everything before it is sealed and final.
	for _, seg := range segs[:len(segs)-1] {
		name := filepath.Base(seg.Path)
		s.enqueueUpload(s.archiveKey(name), seg.Path)
	}
	s.archiveCheckpoints()
}

// archivePublicKey queues the public half of the signing key. Without it the
// archived checkpoints are unverifiable by whoever holds the bucket, which is
// usually not the person holding the evidence directory.
func (s *Store) archivePublicKey() {
	path := filepath.Join(s.opts.Dir, PublicKeyFile)
	if _, err := os.Stat(path); err != nil {
		return
	}
	s.enqueueUpload(s.archiveKey(PublicKeyFile), path)
}

// enqueueUpload hands one file to the background archiver and never waits. The
// writer goroutine owns the chain, so anything it blocks on becomes latency on
// every append and, through backpressure, on every proxied request. A full
// queue therefore drops the job and counts it instead of stalling.
func (s *Store) enqueueUpload(key, path string) {
	if s.uploads == nil {
		return
	}
	select {
	case s.uploads <- archiveJob{key: key, path: path}:
	default:
		s.archiveFailed.Add(1)
		s.recordArchiveErr(fmt.Errorf(
			"evidence: archive queue is full, %s was not uploaded; the local copy in %s is unaffected and remains the primary one",
			key, s.opts.Dir))
	}
}

func (s *Store) archiveLoop() {
	defer s.archiveWG.Done()

	// Every key names content that is final, so a key already uploaded in this
	// run cannot need uploading again.
	sent := map[string]bool{}
	for job := range s.uploads {
		if sent[job.key] {
			continue
		}
		switch err := s.upload(job); {
		case err == nil:
			sent[job.key] = true
			s.archiveUploaded.Add(1)
		case errors.Is(err, errArchiveAlreadyPresent):
			sent[job.key] = true
			s.archiveSkipped.Add(1)
		default:
			s.archiveFailed.Add(1)
			s.recordArchiveErr(err)
		}
	}
}

// errArchiveAlreadyPresent marks the object as one a previous run uploaded.
var errArchiveAlreadyPresent = errors.New("evidence: object is already archived")

func (s *Store) upload(job archiveJob) error {
	if err := s.archiveCtx.Err(); err != nil {
		return fmt.Errorf("evidence: archive %s: %w", job.key, err)
	}
	// A restart re-offers objects an earlier run already shipped. Asking first
	// keeps that cheap and keeps a locked bucket from rejecting the write. An
	// error here means unknown rather than absent, so the upload goes ahead.
	if present, err := s.opts.Archiver.Exists(s.archiveCtx, job.key); err == nil && present {
		return errArchiveAlreadyPresent
	}

	f, err := os.Open(job.path)
	if err != nil {
		return fmt.Errorf("evidence: archive %s: %w", job.key, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("evidence: archive %s: %w", job.key, err)
	}
	// checkpoints.jsonl can grow while an earlier snapshot of it is on its way
	// up. Sending only the bytes that were there when the size was measured
	// keeps the object exactly what its key says it is, and keeps a file that
	// grows mid-upload from failing on a length mismatch.
	body := io.LimitReader(f, info.Size())
	if err := s.opts.Archiver.Put(s.archiveCtx, job.key, body, info.Size(), archiveContentType(job.path)); err != nil {
		return fmt.Errorf("evidence: archive %s to %s: %w", job.key, s.opts.Archiver.Name(), err)
	}
	return nil
}

func (s *Store) recordArchiveErr(err error) {
	s.archiveErr.Store(&err)
}

// archiveContentType names the content type for an evidence file. The three
// cases are duplicated from internal/archive rather than imported, because
// importing it here would put an object store client behind every append.
func archiveContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl":
		return "application/x-ndjson"
	case ".json":
		return "application/json"
	case ".pem":
		return "application/x-pem-file"
	default:
		return "application/octet-stream"
	}
}
