package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tearTail chops bytes off the end of the newest segment, which is what a power
// loss inside the fsync window leaves behind.
func tearTail(t *testing.T, dir string, n int) {
	t.Helper()
	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("no segments to tear")
	}
	path := segs[len(segs)-1].Path
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= n {
		t.Fatalf("the segment is %d bytes, cannot tear %d", len(raw), n)
	}
	if err := os.WriteFile(path, raw[:len(raw)-n], 0o644); err != nil {
		t.Fatal(err)
	}
}

// A torn tail stops the writer dead, and a proxy that cannot start records
// nothing at all. That turns one lost record into total coverage loss, which is
// the trade this repair exists to refuse.
func TestATornTailStopsTheWriterAndRepairLetsItStartAgain(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 5)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	tearTail(t, dir, 40)

	if _, err := Open(Options{Dir: dir, Now: fixedClock()}); err == nil {
		t.Fatal("the writer opened a log with a torn tail, so the chain head was a guess")
	} else if !strings.Contains(err.Error(), "repair") {
		t.Errorf("the refusal does not name the way out: %v", err)
	}

	torn, err := Repair(dir)
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if torn == nil {
		t.Fatal("Repair found nothing to remove")
	}
	if torn.Bytes == 0 || torn.Offset == 0 {
		t.Errorf("the repair does not say what it removed: %+v", torn)
	}

	again, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatalf("the writer still refuses after a repair: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("a repaired log does not verify: %v", res.Problems)
	}
}

// The premise of the repair is that the fragment was never a complete record.
// A checkpoint attesting past it says otherwise, and truncating then would
// destroy signed evidence and leave the signature contradicting the log.
func TestRepairRefusesToRemoveSomethingACheckpointAttestsTo(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 5)
	// Close writes a checkpoint over seq 5, so the damage below is to a record
	// that completed and was signed for.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	tearTail(t, dir, 40)

	_, err = Repair(dir)
	if err == nil {
		t.Fatal("the repair destroyed a record a checkpoint attests to")
	}
	if !strings.Contains(err.Error(), "signed for") {
		t.Errorf("the refusal does not explain what it found: %v", err)
	}
	// And it really did leave the bytes alone.
	if torn, ferr := FindTornRecord(dir); ferr != nil || torn == nil {
		t.Error("the fragment was removed despite the refusal")
	}
}

// Only the final line is ever touched. Damage in the middle is not an
// interrupted append, and a tool that edited it would be a tool for rewriting
// evidence.
func TestRepairIgnoresDamageThatIsNotAtTheEnd(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 5)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(segs[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[1] = lines[1][:len(lines[1])/2] // corrupt a middle line
	if err := os.WriteFile(segs[0].Path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	torn, err := FindTornRecord(dir)
	if err != nil {
		t.Fatal(err)
	}
	if torn != nil {
		t.Errorf("mid-file damage was offered as a repairable fragment: %+v", torn)
	}
}

// A repair must not run underneath a writer.
func TestRepairRefusesWhileAWriterHoldsTheDirectory(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	appendN(t, s, 3)

	if _, err := Repair(dir); err == nil {
		t.Fatal("a repair ran while the server held the directory")
	} else if !strings.Contains(err.Error(), "stop the server") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
	_ = filepath.Base(dir)
}
