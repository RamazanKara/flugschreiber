package evidence

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Two processes started at the same moment both call LoadOrCreateKeyPair. Every
// caller has to end up with the same key: one that reads a partially written
// file would either fail to start or, worse, sign checkpoints nobody can
// verify. Run with -race, which is where the interleaving shows up.
func TestConcurrentKeyCreationConvergesOnOneKey(t *testing.T) {
	const starters = 12
	// Repeated because the window between creating the file and filling it is
	// short, and a single round can miss it.
	for round := 0; round < 40; round++ {
		dir := t.TempDir()
		ids := make([]string, starters)
		errs := make([]error, starters)

		var ready sync.WaitGroup
		var done sync.WaitGroup
		start := make(chan struct{})
		ready.Add(starters)
		done.Add(starters)
		for i := 0; i < starters; i++ {
			go func(i int) {
				defer done.Done()
				ready.Done()
				<-start
				kp, err := LoadOrCreateKeyPair(dir)
				if err != nil {
					errs[i] = err
					return
				}
				ids[i] = kp.ID
			}(i)
		}
		ready.Wait()
		close(start)
		done.Wait()

		for i := range ids {
			if errs[i] != nil {
				t.Fatalf("round %d: starter %d failed instead of getting the key: %v", round, i, errs[i])
			}
			if ids[i] != ids[0] {
				t.Fatalf("round %d: starter %d holds key %s, starter 0 holds %s", round, i, ids[i], ids[0])
			}
		}

		pub, err := LoadPublicKeyPEM(filepath.Join(dir, PublicKeyFile))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if KeyID(pub) != ids[0] {
			t.Fatalf("round %d: %s holds key %s but the starters hold %s", round, PublicKeyFile, KeyID(pub), ids[0])
		}
	}
}

// The signing key file must never be observable in a state that is not a
// complete PEM block, so nothing that reads it can see zero bytes.
func TestSigningKeyIsNeverPublishedEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SigningKeyFile)

	stop := make(chan struct{})
	var watcher sync.WaitGroup
	var sawEmpty bool
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if info, err := os.Stat(path); err == nil && info.Size() == 0 {
				sawEmpty = true
				return
			}
		}
	}()

	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatal(err)
	}
	close(stop)
	watcher.Wait()

	if sawEmpty {
		t.Fatalf("%s existed with zero bytes; a concurrent starter could have read it", SigningKeyFile)
	}
}
