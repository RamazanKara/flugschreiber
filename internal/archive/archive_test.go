package archive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	_ Archiver = (*Dir)(nil)
	_ Getter   = (*Dir)(nil)
)

// recorder is a stand-in Archiver for testing the helpers that drive one.
type recorder struct {
	keys        []string
	bodies      map[string][]byte
	sizes       map[string]int64
	contentType map[string]string
	err         error
}

func newRecorder() *recorder {
	return &recorder{
		bodies:      map[string][]byte{},
		sizes:       map[string]int64{},
		contentType: map[string]string{},
	}
}

func (r *recorder) Put(_ context.Context, key string, body io.Reader, size int64, contentType string) error {
	if r.err != nil {
		return r.err
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	r.keys = append(r.keys, key)
	r.bodies[key] = b
	r.sizes[key] = size
	r.contentType[key] = contentType
	return nil
}

func (r *recorder) Exists(_ context.Context, key string) (bool, error) {
	_, ok := r.bodies[key]
	return ok, nil
}

func (r *recorder) Name() string { return "recorder" }

func newTestDir(t *testing.T) *Dir {
	t.Helper()
	d, err := NewDir(filepath.Join(t.TempDir(), "archive"))
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	return d
}

func TestDirPutStoresTheExactBytes(t *testing.T) {
	d := newTestDir(t)
	body := []byte(`{"seq":1,"record_hash":"abc"}` + "\n")

	if err := d.Put(context.Background(), "2026/seg-00000001.jsonl", bytes.NewReader(body), int64(len(body)), ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(d.Target(), "2026", "seg-00000001.jsonl"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("stored %q, want %q", got, body)
	}
}

// A key is derived from a segment name, but a bug in the calling code must not
// be able to write outside the archive root.
func TestDirRejectsKeysThatCouldEscapeTheRoot(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "parent traversal", key: "../escaped.jsonl"},
		{name: "traversal in the middle", key: "a/../../escaped.jsonl"},
		{name: "absolute path", key: "/etc/passwd"},
		{name: "current directory element", key: "./seg.jsonl"},
		{name: "windows separator", key: `..\escaped.jsonl`},
		{name: "empty element", key: "a//b.jsonl"},
		{name: "empty key", key: ""},
		{name: "control character", key: "seg\x00.jsonl"},
	}

	d := newTestDir(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := d.Put(context.Background(), tt.key, strings.NewReader("x"), 1, ContentTypeText)
			if err == nil {
				t.Fatalf("Put(%q) was accepted", tt.key)
			}
			if _, err := d.Exists(context.Background(), tt.key); err == nil {
				t.Errorf("Exists(%q) was accepted", tt.key)
			}
		})
	}
}

// A crash or a read failure part way through an upload must leave nothing that
// a later run could mistake for a complete segment.
func TestDirPutLeavesNothingBehindWhenTheBodyFails(t *testing.T) {
	d := newTestDir(t)
	body := io.MultiReader(strings.NewReader("half a segment"), errReader{errors.New("disk went away")})

	if err := d.Put(context.Background(), "seg-00000001.jsonl", body, 64, ContentTypeJSONL); err == nil {
		t.Fatal("expected the failed read to surface")
	}

	entries, err := os.ReadDir(d.Target())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("archive holds %v after a failed upload, want nothing", names)
	}
}

func TestDirPutRejectsABodyThatIsNotTheDeclaredSize(t *testing.T) {
	d := newTestDir(t)
	err := d.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("three"), 99, ContentTypeJSONL)
	if err == nil {
		t.Fatal("a short body must not be archived as if it were complete")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error should name the declared size, got %v", err)
	}
	if ok, _ := d.Exists(context.Background(), "seg-00000001.jsonl"); ok {
		t.Error("the short object was published anyway")
	}
}

func TestDirExistsDistinguishesPresentFromAbsent(t *testing.T) {
	d := newTestDir(t)
	ctx := context.Background()

	if ok, err := d.Exists(ctx, "seg-00000001.jsonl"); err != nil || ok {
		t.Fatalf("Exists on an empty archive = %v, %v; want false, nil", ok, err)
	}
	if err := d.Put(ctx, "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok, err := d.Exists(ctx, "seg-00000001.jsonl"); err != nil || !ok {
		t.Fatalf("Exists after Put = %v, %v; want true, nil", ok, err)
	}
}

// Get is what a deep archive verification reads bytes back through, so a
// round trip has to return exactly what Put stored.
func TestDirGetReturnsTheBytesThatWerePut(t *testing.T) {
	d := newTestDir(t)
	ctx := context.Background()
	body := []byte(`{"seq":1,"record_hash":"abc"}` + "\n")

	if err := d.Put(ctx, "2026/seg-00000001.jsonl", bytes.NewReader(body), int64(len(body)), ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, err := d.Get(ctx, "2026/seg-00000001.jsonl")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("Get returned %q, want %q", got, body)
	}
}

// A missing key is a gap in the archive, which a deep check must be able to
// name as such rather than mistake for an unreadable backend.
func TestDirGetOnAMissingKeyReportsNotFound(t *testing.T) {
	d := newTestDir(t)
	rc, err := d.Get(context.Background(), "seg-00000001.jsonl")
	if rc != nil {
		rc.Close()
		t.Fatal("Get returned a reader for a key that is not in the archive")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on a missing key = %v, want it to wrap ErrNotFound", err)
	}
}

// Get validates the key the same way Put and Exists do, so a bug in the calling
// code cannot read outside the archive root.
func TestDirGetRejectsAKeyThatCouldEscapeTheRoot(t *testing.T) {
	d := newTestDir(t)
	rc, err := d.Get(context.Background(), "../../etc/passwd")
	if rc != nil {
		rc.Close()
		t.Fatal("Get returned a reader for a traversing key")
	}
	if err == nil {
		t.Fatal("Get accepted a key that escapes the archive root")
	}
	// A rejected key is not a not-found: the caller passed something invalid,
	// which is a different failure from an object that is simply absent.
	if errors.Is(err, ErrNotFound) {
		t.Errorf("an invalid key was reported as not-found: %v", err)
	}
}

// Re-uploading a sealed segment happens after a restart, and must converge
// rather than fail or leave two copies.
func TestDirPutOfTheSameSegmentTwiceIsIdempotent(t *testing.T) {
	d := newTestDir(t)
	ctx := context.Background()
	body := "seg-00000001 contents"

	for i := 0; i < 2; i++ {
		if err := d.Put(ctx, "seg-00000001.jsonl", strings.NewReader(body), int64(len(body)), ContentTypeJSONL); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(d.Target())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("archive holds %d files after two uploads of one segment, want 1", len(entries))
	}
	got, err := os.ReadFile(filepath.Join(d.Target(), "seg-00000001.jsonl"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != body {
		t.Errorf("stored %q, want %q", got, body)
	}
}

func TestDirPutStopsOnContextCancellation(t *testing.T) {
	d := newTestDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := d.Put(ctx, "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Put on a cancelled context = %v, want context.Canceled", err)
	}
}

func TestPutFileSendsTheWholeFileAndItsSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seg-00000002.jsonl")
	body := strings.Repeat(`{"seq":1}`+"\n", 500)
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rec := newRecorder()
	if err := PutFile(context.Background(), rec, "evidence/seg-00000002.jsonl", path, ContentTypeJSONL); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	key := "evidence/seg-00000002.jsonl"
	if string(rec.bodies[key]) != body {
		t.Error("PutFile did not upload the whole file")
	}
	if rec.sizes[key] != int64(len(body)) {
		t.Errorf("size = %d, want %d", rec.sizes[key], len(body))
	}
	if rec.contentType[key] != ContentTypeJSONL {
		t.Errorf("content type = %q, want %q", rec.contentType[key], ContentTypeJSONL)
	}
}

func TestPutFileReportsAMissingFile(t *testing.T) {
	err := PutFile(context.Background(), newRecorder(), "k", filepath.Join(t.TempDir(), "absent"), ContentTypeJSONL)
	if err == nil {
		t.Fatal("archiving a file that is not there must fail")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error should wrap os.ErrNotExist, got %v", err)
	}
}

func TestCleanKeyAcceptsTheKeysThisProjectProduces(t *testing.T) {
	tests := []string{
		"seg-00000001.jsonl",
		"checkpoints.jsonl",
		"public-key.pem",
		"pruned.json",
		"flugschreiber/prod/2026/seg-00000123.jsonl",
	}
	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			got, err := CleanKey(key)
			if err != nil {
				t.Fatalf("CleanKey(%q): %v", key, err)
			}
			if got != key {
				t.Errorf("CleanKey(%q) = %q, want it unchanged", key, got)
			}
		})
	}
}

// A key that one backend accepts and the other rejects would make an archive
// that works on a volume fail against a bucket, or the reverse, so the limits
// are enforced in one place and checked at their edges.
func TestCleanKeyRejectsKeysNeitherBackendCanStore(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "at the length limit", key: strings.Repeat("a", MaxKeyBytes)},
		{name: "one byte over the length limit", key: strings.Repeat("a", MaxKeyBytes+1), wantErr: true},
		{name: "the limit counts bytes, not runes", key: strings.Repeat("ü", MaxKeyBytes/2+1), wantErr: true},
		{name: "invalid utf-8", key: "seg-\xff\xfe.jsonl", wantErr: true},
		{name: "delete character", key: "seg-\x7f.jsonl", wantErr: true},
		{name: "newline", key: "seg\n.jsonl", wantErr: true},
		{name: "trailing slash is an empty element", key: "evidence/", wantErr: true},
		{name: "a space is allowed, both backends take one", key: "prod 2026/seg-00000001.jsonl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CleanKey(tt.key)
			if tt.wantErr != (err != nil) {
				t.Fatalf("CleanKey error = %v, want an error: %v", err, tt.wantErr)
			}
			if err == nil && got != tt.key {
				t.Errorf("CleanKey(%q) = %q, want it unchanged", tt.key, got)
			}
		})
	}
}

func TestJoinKeyToleratesPrefixSlashes(t *testing.T) {
	tests := []struct {
		prefix, key, want string
	}{
		{prefix: "", key: "seg.jsonl", want: "seg.jsonl"},
		{prefix: "evidence", key: "seg.jsonl", want: "evidence/seg.jsonl"},
		{prefix: "evidence/", key: "seg.jsonl", want: "evidence/seg.jsonl"},
		{prefix: "/evidence/", key: "seg.jsonl", want: "evidence/seg.jsonl"},
		{prefix: "a/b", key: "seg.jsonl", want: "a/b/seg.jsonl"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			if got := JoinKey(tt.prefix, tt.key); got != tt.want {
				t.Errorf("JoinKey(%q, %q) = %q, want %q", tt.prefix, tt.key, got, tt.want)
			}
		})
	}
}

func TestContentTypeForKnownEvidenceFiles(t *testing.T) {
	tests := []struct {
		name, want string
	}{
		{name: "seg-00000001.jsonl", want: ContentTypeJSONL},
		{name: "checkpoints.jsonl", want: ContentTypeJSONL},
		{name: "pruned.json", want: ContentTypeJSON},
		{name: "public-key.pem", want: ContentTypePEM},
		// A reason somebody typed, not a byte stream.
		{name: "LEGAL_HOLD", want: ContentTypeText},
		{name: "flugschreiber/prod/LEGAL_HOLD", want: ContentTypeText},
		{name: "client-salt", want: "application/octet-stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContentTypeFor(tt.name); got != tt.want {
				t.Errorf("ContentTypeFor(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// Put removes its own partial file on every path it controls, but SIGKILL and
// a power loss are not among them. Without a sweep those accumulate in the
// archive forever, so the archive slowly fills with files nobody can identify.
func TestCleanTempRemovesPartialUploadsAKilledProcessLeftBehind(t *testing.T) {
	d := newTestDir(t)
	ctx := context.Background()

	if err := d.Put(ctx, "2026/seg-00000001.jsonl", strings.NewReader("evidence"), 8, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// What a process killed mid-Put leaves: the temporary file is on disk and
	// the rename never happened.
	stale := []string{
		filepath.Join(d.Target(), tempPrefix+"123456"),
		filepath.Join(d.Target(), "2026", tempPrefix+"789012"),
	}
	old := time.Now().Add(-2 * DefaultTempMaxAge)
	for _, p := range stale {
		if err := os.WriteFile(p, []byte("half a segment"), 0o640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
	}

	removed, err := d.CleanTemp(DefaultTempMaxAge)
	if err != nil {
		t.Fatalf("CleanTemp: %v", err)
	}
	if removed != len(stale) {
		t.Errorf("CleanTemp removed %d files, want %d", removed, len(stale))
	}
	for _, p := range stale {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the sweep", p)
		}
	}
	// The published object is not a partial upload and must be untouched.
	if ok, err := d.Exists(ctx, "2026/seg-00000001.jsonl"); err != nil || !ok {
		t.Errorf("CleanTemp removed a published object: %v, %v", ok, err)
	}
}

// A sweep that ran while an upload was in flight would delete the file that
// upload is writing, turning routine housekeeping into a failed archive.
func TestCleanTempLeavesAnUploadThatIsStillRunning(t *testing.T) {
	d := newTestDir(t)
	fresh := filepath.Join(d.Target(), tempPrefix+"inflight")
	if err := os.WriteFile(fresh, []byte("still being written"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	removed, err := d.CleanTemp(time.Hour)
	if err != nil {
		t.Fatalf("CleanTemp: %v", err)
	}
	if removed != 0 {
		t.Errorf("CleanTemp removed %d files, want it to leave a fresh one alone", removed)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a partial upload written a moment ago was swept: %v", err)
	}
}

func TestCleanTempOnAnArchiveWithNothingToSweep(t *testing.T) {
	d := newTestDir(t)
	if err := d.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	removed, err := d.CleanTemp(0)
	if err != nil {
		t.Fatalf("CleanTemp: %v", err)
	}
	if removed != 0 {
		t.Errorf("CleanTemp removed %d files from a clean archive", removed)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
