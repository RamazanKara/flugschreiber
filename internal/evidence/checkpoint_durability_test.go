package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// The first checkpoint creates checkpoints.jsonl, and fsyncing a file does not
// make the directory entry naming it durable. Without the directory sync a
// machine crash can leave a log whose checkpoints were written and then lost,
// which is the one file that proves the head was attested to at a given time.
func TestAppendCheckpointSyncsTheDirectory(t *testing.T) {
	dir := t.TempDir()

	var synced []string
	syncDirObserver = func(d string) { synced = append(synced, d) }
	t.Cleanup(func() { syncDirObserver = nil })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := Checkpoint{
		Version:    CheckpointVersion,
		Segment:    SegmentName(1),
		Seq:        1,
		RecordHash: GenesisHash,
		Records:    1,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := SignCheckpoint(priv, KeyID(pub), &c); err != nil {
		t.Fatal(err)
	}
	if err := AppendCheckpoint(dir, c); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	for _, d := range synced {
		if d == dir {
			return
		}
	}
	t.Fatalf("%s was written without flushing the directory entry that names it", CheckpointsFile)
}
