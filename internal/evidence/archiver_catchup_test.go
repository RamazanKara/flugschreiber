package evidence

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// memArchiver records every Put and can pretend some keys already exist.
type memArchiver struct {
	mu       sync.Mutex
	stored   map[string]bool
	existing map[string]bool
}

func newMemArchiver(existing ...string) *memArchiver {
	m := &memArchiver{stored: map[string]bool{}, existing: map[string]bool{}}
	for _, k := range existing {
		m.existing[k] = true
	}
	return m
}

func (m *memArchiver) Name() string { return "mem" }

func (m *memArchiver) Exists(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.existing[key] || m.stored[key], nil
}

func (m *memArchiver) Put(_ context.Context, key string, r io.Reader, _ int64, _ string) error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored[key] = true
	return nil
}

func (m *memArchiver) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.stored))
	for k := range m.stored {
		out = append(out, k)
	}
	return out
}

// sealedLog writes enough records across small segments that several are
// sealed, then closes without an archiver, which is what a run whose uploads
// all failed looks like from the next run's point of view.
func sealedLog(t *testing.T, dir string) int {
	t.Helper()
	s, err := Open(Options{Dir: dir, SegmentMaxBytes: 400})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if err := s.Append(&Event{EventType: EventInference, RequestID: "r", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(segs)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A segment whose upload was missed must reach the archive on the next start,
// or archival has permanent silent holes and the object-lock story is theatre.
func TestOpenCatchesUpSealedSegments(t *testing.T) {
	dir := t.TempDir()
	total := sealedLog(t, dir)
	if total < 3 {
		t.Fatalf("fixture produced %d segments, need at least 3", total)
	}
	sealed := total - 1

	arch := newMemArchiver()
	s, err := Open(Options{Dir: dir, SegmentMaxBytes: 400, Archiver: arch})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	waitFor(t, "catch-up uploads", func() bool {
		n := 0
		for _, k := range arch.keys() {
			if strings.HasPrefix(k, "seg-") {
				n++
			}
		}
		return n >= sealed
	})

	for _, k := range arch.keys() {
		if strings.HasPrefix(k, "seg-") && strings.Contains(k, SegmentName(total)) {
			t.Errorf("the open segment %s was uploaded under its sealed key", k)
		}
	}
}

// Segments the archive already holds are skipped, not overwritten. A locked
// bucket would refuse the overwrite; every other backend must not need to.
func TestCatchUpSkipsSegmentsTheArchiveAlreadyHolds(t *testing.T) {
	dir := t.TempDir()
	total := sealedLog(t, dir)

	arch := newMemArchiver(SegmentName(1))
	s, err := Open(Options{Dir: dir, SegmentMaxBytes: 400, Archiver: arch})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	waitFor(t, "skip accounting", func() bool {
		return s.ArchiveStats().Skipped >= 1
	})
	if arch.stored[SegmentName(1)] {
		t.Errorf("%s was re-uploaded although the archive already held it", SegmentName(1))
	}
	waitFor(t, "remaining sealed segments", func() bool {
		return len(arch.keys()) >= total-2
	})
}

// A backlog larger than the queue must not deadlock Open; it converges over
// restarts and says what it could not queue.
func TestCatchUpBacklogBeyondTheQueueDoesNotBlockOpen(t *testing.T) {
	dir := t.TempDir()
	sealedLog(t, dir)

	done := make(chan struct{})
	go func() {
		s, err := Open(Options{Dir: dir, SegmentMaxBytes: 400, Archiver: newMemArchiver(), ArchiveQueueDepth: 1})
		if err == nil {
			s.Close()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Open blocked on an archive backlog larger than the queue")
	}
}
