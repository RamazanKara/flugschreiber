package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ContentJournalFile holds content keys that have not been folded into the
// keystore yet.
//
// Minting a key used to rewrite the whole keystore, and because a key is minted
// per request whenever the caller sends no session header, the cost of writing
// one grew with every key already there: measured at 3 ms each at five hundred
// keys and 14 ms each at seven and a half thousand, on the request path, under
// the lock. A large store then needed more memory to open than the chart grants
// the container, so the proxy died on start and died again on every restart.
//
// The journal makes minting a key an append of one line. The keystore itself is
// still rewritten, but only by the rare operations: erasure, compaction, and
// the first write after a compaction.
const ContentJournalFile = "content-keys.jsonl"

// contentJournalCompactAt is how many journalled keys are allowed to accumulate
// before the next write folds them in. It bounds both the work Open has to do
// and how much a single rewrite costs, and the exact value matters little: the
// point is that neither grows without limit.
const contentJournalCompactAt = 512

// contentJournalEntry is one appended key. It carries the same fields the
// keystore holds, so folding it in is a copy rather than a conversion.
type contentJournalEntry struct {
	Version int             `json:"version"`
	Key     contentKeyEntry `json:"key"`
}

// contentJournalPath is the journal beside a keystore.
func contentJournalPath(keystore string) string {
	return filepath.Join(filepath.Dir(keystore), ContentJournalFile)
}

// appendJournal adds one key to the journal and fsyncs it.
//
// The fsync is not optional. A key that is not on disk when the machine dies is
// a key that cannot decrypt the record already written under it, which turns a
// crash into content that nobody, including the operator, can ever read again.
func (k *ContentKeystore) appendJournal(e contentKeyEntry) error {
	line, err := json.Marshal(contentJournalEntry{Version: contentKeystoreVersion, Key: e})
	if err != nil {
		return fmt.Errorf("evidence: marshal content key: %w", err)
	}
	line = append(line, '\n')

	path := contentJournalPath(k.path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("evidence: open %s: %w", ContentJournalFile, err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("evidence: write %s: %w", ContentJournalFile, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("evidence: fsync %s: %w", ContentJournalFile, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	k.journalled++
	return nil
}

// readJournal returns the keys appended since the last compaction.
//
// A line that does not parse is an error rather than a skipped line, on the
// same reasoning as the checkpoint reader: a key that quietly disappears takes
// the readability of its records with it, and silence is the worst way to
// discover that.
func readJournal(keystore string) ([]contentKeyEntry, error) {
	path := contentJournalPath(keystore)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []contentKeyEntry
	sc := newLineScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e contentJournalEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("evidence: %s:%d: %w", ContentJournalFile, sc.Line(), err)
		}
		if e.Version != contentKeystoreVersion {
			return nil, fmt.Errorf(
				"evidence: %s:%d: version %d, this build writes version %d",
				ContentJournalFile, sc.Line(), e.Version, contentKeystoreVersion)
		}
		if e.Key.KeyID == "" {
			return nil, fmt.Errorf("evidence: %s:%d: a key with no id", ContentJournalFile, sc.Line())
		}
		out = append(out, e.Key)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", ContentJournalFile, err)
	}
	return out, nil
}

// compactLocked folds the journal into the keystore and removes it.
//
// The order is what makes this safe across a crash: the keystore is written
// first and fsynced, so it already holds every journalled key before the
// journal is unlinked. A crash between the two leaves keys in both places,
// which the loader handles because folding a key that is already there is a
// no-op. The reverse order would lose keys.
func (k *ContentKeystore) compactLocked() error {
	if err := k.saveLocked(); err != nil {
		return err
	}
	if err := os.Remove(contentJournalPath(k.path)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("evidence: remove %s after folding it in: %w", ContentJournalFile, err)
	}
	syncDir(filepath.Dir(k.path))
	k.journalled = 0
	return nil
}
