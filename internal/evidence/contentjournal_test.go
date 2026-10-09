package evidence

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Checking the append-only layout catches a return to rewriting the keystore
// without depending on disk timings or thousands of fsyncs.
func TestMintingAKeyAppendsToTheJournal(t *testing.T) {
	dir := t.TempDir()
	k, err := OpenContentKeystore(ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}

	snapshot := readFileBytes(t, k.Path())
	var previous []byte
	for i := range 12 {
		if _, _, err := k.KeyFor("", fmt.Sprintf("req-%d", i)); err != nil {
			t.Fatal(err)
		}
		journal := readFileBytes(t, contentJournalPath(k.Path()))
		if !bytes.HasPrefix(journal, previous) || bytes.Count(journal[len(previous):], []byte{'\n'}) != 1 {
			t.Fatal("minting a key did not append exactly one journal entry")
		}
		if !bytes.Equal(readFileBytes(t, k.Path()), snapshot) {
			t.Fatal("minting a key rewrote the keystore before compaction")
		}
		previous = journal
	}
}

// A key that is not on disk when the machine dies cannot decrypt the record
// already written under it, so the append has to be durable before the record
// that uses it is written.
func TestAJournalledKeySurvivesReopening(t *testing.T) {
	dir := t.TempDir()
	path := ContentKeystorePath(dir)

	k, err := OpenContentKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	key, id, err := k.KeyFor("sess-journal", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ContentJournalFile)); err != nil {
		t.Fatalf("the key was not journalled: %v", err)
	}

	reopened, err := OpenContentKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Key(id)
	if err != nil {
		t.Fatalf("a journalled key did not survive a reopen, so its records are unreadable: %v", err)
	}
	if string(got) != string(key) {
		t.Fatal("the key came back different")
	}
	// And the session index came back with it, or a busy session would mint a
	// second key for records it should share one with.
	if _, again, err := reopened.KeyFor("sess-journal", "req-2"); err != nil {
		t.Fatal(err)
	} else if again != id {
		t.Errorf("the session got a new key %s after a reopen, want %s", again, id)
	}
}

// Erasure has to reach the journal too, or a key the operator told a data
// subject was destroyed would come back on the next start.
func TestErasureReachesAJournalledKey(t *testing.T) {
	dir := t.TempDir()
	path := ContentKeystorePath(dir)

	k, err := OpenContentKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, id, err := k.KeyFor("sess-erase", "req-1")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := wrappedKeyOnDisk(t, path, id)

	if _, err := k.Erase(ContentErasureRequest{SessionID: "sess-erase", Requester: "dpo@example.org"}); err != nil {
		t.Fatal(err)
	}

	// Not in either file, as bytes.
	for _, f := range []string{path, filepath.Join(dir, ContentJournalFile)} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue // the journal is removed by compaction, which is fine
		}
		if strings.Contains(string(raw), wrapped) {
			t.Errorf("the wrapped key is still in %s after an erasure", filepath.Base(f))
		}
	}

	reopened, err := OpenContentKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Key(id); err == nil {
		t.Fatal("an erased key came back after a reopen")
	}
	if state := reopened.State(id); state != ContentKeyErased {
		t.Errorf("State = %q, want %q", state, ContentKeyErased)
	}
}

// Compaction must not lose a key, and it has to happen or the journal grows
// without limit and Open gets slower forever.
func TestCompactionFoldsEveryKeyIn(t *testing.T) {
	dir := t.TempDir()
	path := ContentKeystorePath(dir)

	k, err := OpenContentKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, contentJournalCompactAt+10)
	for i := range contentJournalCompactAt + 10 {
		_, id, err := k.KeyFor("", fmt.Sprintf("req-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	reopened, err := OpenContentKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := reopened.Key(id); err != nil {
			t.Fatalf("key %s did not survive compaction: %v", id, err)
		}
	}
}
