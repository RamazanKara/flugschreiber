package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two writers on one directory interleave records and break the chain in a way
// that reads as tampering, permanently and with no repair. The chart forbids it
// for Kubernetes; nothing forbade it anywhere else.
func TestASecondWriterIsRefusedWhileTheFirstHoldsTheDirectory(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	appendN(t, first, 3)

	second, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err == nil {
		second.Close()
		t.Fatal("a second writer opened a directory the first one holds")
	}
	if !strings.Contains(err.Error(), "still running") {
		t.Errorf("the refusal does not say the holder is alive: %v", err)
	}
	if !strings.Contains(err.Error(), "break the chain permanently") {
		t.Errorf("the refusal does not say what is at stake: %v", err)
	}
}

// A crash leaves the lock behind. Refusing to start then would turn one problem
// into an outage, which is the trade the previous design was protecting.
func TestAStaleLockFromADeadProcessDoesNotBlockStartup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 2)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A lock naming a process that is gone. PID 1 is always alive, so use a
	// high one this host will not have.
	host, _ := os.Hostname()
	stale := []byte(`{"pid":4194303,"host":"` + host + `","started_at":"2026-01-01T00:00:00Z"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, WriterLockFile), stale, 0o644); err != nil {
		t.Fatal(err)
	}

	again, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatalf("a stale lock from a dead process blocked startup, turning a crash into an outage: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

// A lock from another host cannot be probed, so it is refused rather than
// guessed, and the override is what an operator uses after a node failure.
func TestALockFromAnotherHostIsRefusedUnlessForced(t *testing.T) {
	dir := t.TempDir()
	lock := []byte(`{"pid":1234,"host":"some-other-node","started_at":"2026-01-01T00:00:00Z"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, WriterLockFile), lock, 0o644); err != nil {
		t.Fatal(err)
	}

	if s, err := Open(Options{Dir: dir, Now: fixedClock()}); err == nil {
		s.Close()
		t.Fatal("a lock held by another host was taken without a word")
	} else if !strings.Contains(err.Error(), "force-writer-lock") {
		t.Errorf("the refusal does not name the way out: %v", err)
	}

	forced, err := Open(Options{Dir: dir, ForceWriterLock: true, Now: fixedClock()})
	if err != nil {
		t.Fatalf("--force-writer-lock did not take the directory: %v", err)
	}
	if err := forced.Close(); err != nil {
		t.Fatal(err)
	}
}
