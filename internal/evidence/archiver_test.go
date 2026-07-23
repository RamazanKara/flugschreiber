package evidence

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeArchiver records what a store hands it. It stands in for internal/archive
// so that the evidence package can be tested, and the evidence package can
// ship, without any knowledge of object stores.
type fakeArchiver struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int

	// failWith is returned by every Put, which is how a broken bucket behaves.
	failWith error

	// block holds every Put until it is closed, which is how a bucket that has
	// stopped answering behaves.
	block chan struct{}
}

func newFakeArchiver() *fakeArchiver {
	return &fakeArchiver{objects: map[string][]byte{}}
}

func (f *fakeArchiver) Name() string { return "fake" }

func (f *fakeArchiver) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.failWith != nil {
		return f.failWith
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if size >= 0 && int64(len(raw)) != size {
		return errors.New("archive: declared size does not match the body")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = raw
	f.puts++
	return nil
}

func (f *fakeArchiver) Exists(ctx context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[key]
	return ok, nil
}

func (f *fakeArchiver) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	return out
}

func (f *fakeArchiver) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, ok := f.objects[key]
	return raw, ok
}

func hasKeyWithPrefix(keys []string, prefix string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func archivingStore(t *testing.T, dir string, a Archiver, prefix string, maxBytes int64) *Store {
	t.Helper()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        maxBytes,
		Keys:                   kp,
		Archiver:               a,
		ArchivePrefix:          prefix,
		ArchiveShutdownTimeout: 5 * time.Second,
		Now:                    fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Rotation seals a segment, and a sealed segment is the only thing an object
// store can hold, because it will never be appended to again.
func TestRotationArchivesTheSealedSegment(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()
	s := archivingStore(t, dir, fake, "site-a/", 400)
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(segs))
	}
	// Every segment but the one still open must be in the archive byte for
	// byte.
	for _, seg := range segs[:len(segs)-1] {
		key := "site-a/" + SegmentName(seg.Index)
		got, ok := fake.get(key)
		if !ok {
			t.Fatalf("sealed segment %s was not archived; archive holds %v", key, fake.keys())
		}
		want := readFileBytes(t, seg.Path)
		if string(got) != string(want) {
			t.Errorf("%s in the archive differs from the segment on disk", key)
		}
	}

	keys := fake.keys()
	if _, ok := fake.get("site-a/" + PublicKeyFile); !ok {
		t.Errorf("the public key was not archived, so nothing in %v can be checked", keys)
	}
	if !hasKeyWithPrefix(keys, "site-a/checkpoints/") {
		t.Errorf("no checkpoints were archived: %v", keys)
	}
	if !hasKeyWithPrefix(keys, "site-a/open/") {
		t.Errorf("the segment still open at shutdown was not archived: %v", keys)
	}

	stats := s.ArchiveStats()
	if stats.Backend != "fake" || stats.Uploaded == 0 || stats.Failed != 0 {
		t.Errorf("ArchiveStats = %+v, want a fake backend with uploads and no failures", stats)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Errorf("ArchiveErr = %v, want nil", err)
	}
}

// The store's job is to record. An archive that rejects everything must cost
// nothing but a counter and a readable error: not an append, not a record, not
// the chain.
func TestFailingArchiverDoesNotBreakAppendsOrTheChain(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()
	fake.failWith = errors.New("bucket is on fire")
	s := archivingStore(t, dir, fake, "", 400)

	appendN(t, s, 12)
	if err := s.Err(); err != nil {
		t.Fatalf("a failing archive turned into a write error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s.Appended() != 12 {
		t.Errorf("Appended = %d, want 12", s.Appended())
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a failing archive damaged the log: %v", res.Problems)
	}
	if res.Records != 12 {
		t.Errorf("Records = %d, want 12", res.Records)
	}

	stats := s.ArchiveStats()
	if stats.Failed == 0 {
		t.Error("failures were not counted, so nothing would ever alert")
	}
	if stats.Uploaded != 0 {
		t.Errorf("Uploaded = %d although every Put failed", stats.Uploaded)
	}
	err = s.ArchiveErr()
	if err == nil {
		t.Fatal("ArchiveErr is nil after every upload failed")
	}
	if !strings.Contains(err.Error(), "bucket is on fire") {
		t.Errorf("ArchiveErr does not name the cause: %v", err)
	}
}

// A backend that has stopped answering must not stall the writer, and must not
// hold shutdown open beyond the timeout. The evidence directory is complete
// either way.
func TestStalledArchiverDoesNotStallAppendsOrShutdown(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()
	fake.block = make(chan struct{})

	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        400,
		Keys:                   kp,
		Archiver:               fake,
		ArchiveShutdownTimeout: 50 * time.Millisecond,
		Now:                    fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}

	appended := make(chan error, 1)
	go func() {
		for i := 0; i < 40; i++ {
			if err := s.Append(&Event{EventType: EventInference, RequestID: "r", Status: 200}); err != nil {
				appended <- err
				return
			}
		}
		appended <- nil
	}()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("appends blocked on a stalled archive")
	}

	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked on a stalled archive")
	}
	close(fake.block)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() || res.Records != 40 {
		t.Fatalf("a stalled archive cost records: %d records, problems %v", res.Records, res.Problems)
	}
	if s.ArchiveErr() == nil {
		t.Error("uploads were abandoned at shutdown without saying so")
	}
}

// A restart re-offers objects an earlier run already shipped. They are skipped
// rather than written again, which is what keeps a locked bucket usable.
func TestAlreadyArchivedObjectsAreNotUploadedTwice(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()

	first := archivingStore(t, dir, fake, "", 400)
	appendN(t, first, 12)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	putsAfterFirstRun := fake.puts
	sealed := len(fake.keys())

	second := archivingStore(t, dir, fake, "", 400)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.puts != putsAfterFirstRun {
		t.Errorf("a restart re-uploaded %d object(s) that were already archived", fake.puts-putsAfterFirstRun)
	}
	if second.ArchiveStats().Skipped == 0 {
		t.Error("nothing was reported as already archived")
	}
	if len(fake.keys()) != sealed {
		t.Errorf("the archive gained keys on a run that wrote no record: %v", fake.keys())
	}
}

// Without an Archiver nothing changes: no goroutine, no counters, no keys.
func TestStoreWithoutAnArchiverReportsNothing(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 400)
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := (s.ArchiveStats()); stats != (ArchiveStats{}) {
		t.Errorf("ArchiveStats = %+v, want the zero value", stats)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Errorf("ArchiveErr = %v, want nil", err)
	}
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
