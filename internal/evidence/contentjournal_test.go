package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Minting a key used to rewrite the whole keystore, so the cost of writing one
// grew with every key already there, on the request path, under the lock. The
// shape of the curve is the defect, not any single number, so this measures the
// shape and allows generously for a slow or loaded disk.
func TestMintingAKeyDoesNotGetSlowerAsTheKeystoreGrows(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	dir := t.TempDir()
	k, err := OpenContentKeystore(ContentKeystorePath(dir))
	if err != nil {
		t.Fatal(err)
	}

	mint := func(n, offset int) time.Duration {
		start := time.Now()
		for i := range n {
			if _, _, err := k.KeyFor("", fmt.Sprintf("req-%d", offset+i)); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / time.Duration(n)
	}

	const batch = 400
	first := mint(batch, 0)
	mint(batch*3, batch) // grow the store
	later := mint(batch, batch*4)

	// Quadratic total cost showed up here as later being several times first.
	// A flat curve wanders a little either way, so the bar is deliberately
	// loose: it catches a return to growth, not ordinary noise.
	if later > first*3 {
		t.Errorf("minting a key costs %v with a large keystore against %v with a small one, so the cost is growing with the store again", later, first)
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
