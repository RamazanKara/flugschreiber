package evidence

import (
	"context"
	"io"
	"testing"
	"time"
)

// stubbornArchiver ignores context cancellation, which is what a third-party
// backend with a blocking client library looks like from here.
type stubbornArchiver struct {
	release chan struct{}
}

func (a *stubbornArchiver) Name() string { return "stubborn" }

func (a *stubbornArchiver) Exists(context.Context, string) (bool, error) { return false, nil }

func (a *stubbornArchiver) Put(_ context.Context, _ string, _ io.Reader, _ int64, _ string) error {
	<-a.release
	return nil
}

// Close must return even when the archiver refuses to stop. Nothing in the
// evidence directory depends on the archive, so a wedged backend has to be
// abandoned rather than allowed to hold the process open.
func TestCloseReturnsEvenWhenTheArchiverIgnoresCancellation(t *testing.T) {
	archiver := &stubbornArchiver{release: make(chan struct{})}
	defer close(archiver.release)

	dir := t.TempDir()
	store, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        300,
		Archiver:               archiver,
		ArchiveShutdownTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Enough records to force a rotation, which is what queues an upload.
	for i := 0; i < 12; i++ {
		if err := store.Append(&Event{EventType: EventInference, RequestID: "r", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan error, 1)
	go func() { done <- store.Close() }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Close did not return: a wedged archiver can hold the process open forever")
	}

	// The log itself must be complete and verifiable regardless.
	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("chain broken after an archiver stall: %v", res.Problems)
	}
	if res.Records != 12 {
		t.Errorf("Records = %d, want 12", res.Records)
	}
}
