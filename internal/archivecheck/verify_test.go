package archivecheck

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/RamazanKara/flugschreiber/internal/archive"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestCompareArchived(t *testing.T) {
	for _, tc := range []struct {
		name     string
		local    string
		archived string
		want     byteRelation
		offset   int64
	}{
		{"empty", "", "", bytesIdentical, 0},
		{"identical", "abc", "abc", bytesIdentical, 3},
		{"empty archive", "abc", "", bytesPrefix, 0},
		{"prefix", "abc", "ab", bytesPrefix, 2},
		{"longer archive", "ab", "abc", bytesLonger, 2},
		{"empty local", "", "abc", bytesLonger, 0},
		{"different", "abc", "aBc", bytesDiffer, 1},
		{"chunk boundary", strings.Repeat("a", 64<<10) + "b", strings.Repeat("a", 64<<10) + "c", bytesDiffer, 64 << 10},
		{"whole chunk", strings.Repeat("a", 64<<10), strings.Repeat("a", 64<<10), bytesIdentical, 64 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel, n, err := compareArchived(strings.NewReader(tc.local), iotest.HalfReader(strings.NewReader(tc.archived)))
			if err != nil || rel != tc.want || n != tc.offset {
				t.Fatalf("compareArchived = %q, %d, %v; want %q, %d, nil", rel, n, err, tc.want, tc.offset)
			}
		})
	}
	readErr := errors.New("read interrupted")
	for _, tc := range []struct {
		name     string
		local    io.Reader
		archived io.Reader
	}{
		{"archive read", strings.NewReader("abc"), iotest.ErrReader(readErr)},
		{"local read", iotest.ErrReader(readErr), strings.NewReader("abc")},
		{"local tail", iotest.ErrReader(readErr), strings.NewReader("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := compareArchived(tc.local, tc.archived)
			if !errors.Is(err, readErr) {
				t.Fatalf("compareArchived = %v, want read error", err)
			}
		})
	}
}

func TestVerifySnapshotsReachTheirNamedHead(t *testing.T) {
	for _, kind := range []string{KindCheckpoints, KindOpenSegment} {
		for _, mutation := range []string{"empty", "partial record", "missing newline", "earlier head", "named head", "later head"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				dir, root := t.TempDir(), t.TempDir()
				segment := evidence.SegmentName(1)
				if err := os.WriteFile(filepath.Join(dir, segment), []byte("{\"seq\":1}\n{\"seq\":2}\n{\"seq\":3}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				for seq := uint64(1); seq <= 3; seq++ {
					if err := evidence.AppendCheckpoint(dir, evidence.Checkpoint{Seq: seq, Segment: segment}); err != nil {
						t.Fatal(err)
					}
				}
				key, localPath := openSegmentSnapshotKey(segment, 2), filepath.Join(dir, segment)
				if kind == KindCheckpoints {
					key, localPath = checkpointSnapshotKey(2), filepath.Join(dir, evidence.CheckpointsFile)
				}
				local, err := os.ReadFile(localPath)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.SplitAfter(string(local), "\n")
				var body string
				want := StatusMismatch
				switch mutation {
				case "partial record":
					body = lines[0] + lines[1][:len(lines[1])/2]
				case "missing newline":
					body = lines[0] + strings.TrimSuffix(lines[1], "\n")
				case "earlier head":
					body = lines[0]
				case "named head":
					body, want = lines[0]+lines[1], StatusPresent
				case "later head":
					body, want = string(local), StatusPresent
				}
				backend, err := archive.NewDir(root)
				if err != nil {
					t.Fatal(err)
				}
				if err := backend.Put(t.Context(), key, strings.NewReader(body), int64(len(body)), "application/x-ndjson"); err != nil {
					t.Fatal(err)
				}
				for _, deep := range []bool{false, true} {
					res, err := Verify(t.Context(), backend, dir, "", deep)
					if err != nil {
						t.Fatal(err)
					}
					expected := StatusPresent
					if deep {
						expected = want
					}
					if len(res.Objects) != 1 || res.Objects[0].Status != expected || res.OK() != (expected == StatusPresent) {
						t.Fatalf("deep=%v: %+v; want one %s object", deep, res, expected)
					}
					if expected == StatusMismatch && res.OpenSnapshots+res.CheckpointSnapshots != 0 {
						t.Fatal("a damaged snapshot was counted as present")
					}
				}
			})
		}
	}
}

func TestVerifyReportsArchiveFailures(t *testing.T) {
	dir, root := t.TempDir(), t.TempDir()
	backend, err := archive.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := evidence.Open(evidence.Options{Dir: dir, Keys: keys, Archiver: backend, ArchivePrefix: "site-a", SegmentMaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := store.Append(&evidence.Event{EventType: evidence.EventInference, RequestID: "request", Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, deep := range []bool{false, true} {
		res, err := Verify(t.Context(), backend, dir, "site-a", deep)
		if err != nil || !res.OK() || res.OpenSnapshots != 1 || res.CheckpointSnapshots == 0 {
			t.Fatalf("complete archive, deep=%v: %+v, %v", deep, res, err)
		}
	}
	key := archive.JoinKey("site-a", evidence.SegmentName(1))
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(key)), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(t.Context(), backend, dir, "site-a", true)
	if err != nil || res.Mismatched != 1 || res.OK() {
		t.Fatalf("damaged archive: %+v, %v", res, err)
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(key))); err != nil {
		t.Fatal(err)
	}
	res, err = Verify(t.Context(), backend, dir, "site-a", true)
	if err != nil || res.Missing != 1 || res.OK() {
		t.Fatalf("missing segment: %+v, %v", res, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	res, err = Verify(ctx, backend, dir, "site-a", true)
	if err != nil || res.Unknown == 0 || res.OK() {
		t.Fatalf("cancelled check: %+v, %v", res, err)
	}
}
