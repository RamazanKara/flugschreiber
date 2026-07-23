package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/archive"
)

// fakeArchiver records what a store hands it. It stands in for internal/archive
// so that the evidence package can be tested, and the evidence package can
// ship, without any knowledge of object stores.
type fakeArchiver struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int

	// failWith is returned by every Put, which is how a broken bucket behaves.
	failWith error

	// block holds every Put until it is closed, which is how a bucket that has
	// stopped answering behaves.
	block chan struct{}
}

func newFakeArchiver() *fakeArchiver {
	return &fakeArchiver{objects: map[string][]byte{}}
}

func (f *fakeArchiver) Name() string { return "fake" }

func (f *fakeArchiver) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.failWith != nil {
		return f.failWith
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if size >= 0 && int64(len(raw)) != size {
		return errors.New("archive: declared size does not match the body")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = raw
	f.puts++
	return nil
}

func (f *fakeArchiver) Exists(ctx context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[key]
	return ok, nil
}

func (f *fakeArchiver) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	return out
}

func (f *fakeArchiver) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, ok := f.objects[key]
	return raw, ok
}

func hasKeyWithPrefix(keys []string, prefix string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func archivingStore(t *testing.T, dir string, a Archiver, prefix string, maxBytes int64) *Store {
	t.Helper()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        maxBytes,
		Keys:                   kp,
		Archiver:               a,
		ArchivePrefix:          prefix,
		ArchiveShutdownTimeout: 5 * time.Second,
		Now:                    fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Rotation seals a segment, and a sealed segment is the only thing an object
// store can hold, because it will never be appended to again.
func TestRotationArchivesTheSealedSegment(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()
	s := archivingStore(t, dir, fake, "site-a/", 400)
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	segs, err := Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(segs))
	}
	// Every segment but the one still open must be in the archive byte for
	// byte.
	for _, seg := range segs[:len(segs)-1] {
		key := "site-a/" + SegmentName(seg.Index)
		got, ok := fake.get(key)
		if !ok {
			t.Fatalf("sealed segment %s was not archived; archive holds %v", key, fake.keys())
		}
		want := readFileBytes(t, seg.Path)
		if string(got) != string(want) {
			t.Errorf("%s in the archive differs from the segment on disk", key)
		}
	}

	keys := fake.keys()
	if _, ok := fake.get("site-a/" + PublicKeyFile); !ok {
		t.Errorf("the public key was not archived, so nothing in %v can be checked", keys)
	}
	if !hasKeyWithPrefix(keys, "site-a/checkpoints/") {
		t.Errorf("no checkpoints were archived: %v", keys)
	}
	if !hasKeyWithPrefix(keys, "site-a/open/") {
		t.Errorf("the segment still open at shutdown was not archived: %v", keys)
	}

	stats := s.ArchiveStats()
	if stats.Backend != "fake" || stats.Uploaded == 0 || stats.Failed != 0 {
		t.Errorf("ArchiveStats = %+v, want a fake backend with uploads and no failures", stats)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Errorf("ArchiveErr = %v, want nil", err)
	}
}

// The store's job is to record. An archive that rejects everything must cost
// nothing but a counter and a readable error: not an append, not a record, not
// the chain.
func TestFailingArchiverDoesNotBreakAppendsOrTheChain(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()
	fake.failWith = errors.New("bucket is on fire")
	s := archivingStore(t, dir, fake, "", 400)

	appendN(t, s, 12)
	if err := s.Err(); err != nil {
		t.Fatalf("a failing archive turned into a write error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s.Appended() != 12 {
		t.Errorf("Appended = %d, want 12", s.Appended())
	}

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a failing archive damaged the log: %v", res.Problems)
	}
	if res.Records != 12 {
		t.Errorf("Records = %d, want 12", res.Records)
	}

	stats := s.ArchiveStats()
	if stats.Failed == 0 {
		t.Error("failures were not counted, so nothing would ever alert")
	}
	if stats.Uploaded != 0 {
		t.Errorf("Uploaded = %d although every Put failed", stats.Uploaded)
	}
	err = s.ArchiveErr()
	if err == nil {
		t.Fatal("ArchiveErr is nil after every upload failed")
	}
	if !strings.Contains(err.Error(), "bucket is on fire") {
		t.Errorf("ArchiveErr does not name the cause: %v", err)
	}
}

// A backend that has stopped answering must not stall the writer, and must not
// hold shutdown open beyond the timeout. The evidence directory is complete
// either way.
func TestStalledArchiverDoesNotStallAppendsOrShutdown(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()
	fake.block = make(chan struct{})

	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        400,
		Keys:                   kp,
		Archiver:               fake,
		ArchiveShutdownTimeout: 50 * time.Millisecond,
		Now:                    fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}

	appended := make(chan error, 1)
	go func() {
		for i := 0; i < 40; i++ {
			if err := s.Append(&Event{EventType: EventInference, RequestID: "r", Status: 200}); err != nil {
				appended <- err
				return
			}
		}
		appended <- nil
	}()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("appends blocked on a stalled archive")
	}

	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked on a stalled archive")
	}
	close(fake.block)

	res, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() || res.Records != 40 {
		t.Fatalf("a stalled archive cost records: %d records, problems %v", res.Records, res.Problems)
	}
	if s.ArchiveErr() == nil {
		t.Error("uploads were abandoned at shutdown without saying so")
	}
}

// A restart re-offers objects an earlier run already shipped. They are skipped
// rather than written again, which is what keeps a locked bucket usable.
func TestAlreadyArchivedObjectsAreNotUploadedTwice(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeArchiver()

	first := archivingStore(t, dir, fake, "", 400)
	appendN(t, first, 12)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	putsAfterFirstRun := fake.puts
	sealed := len(fake.keys())

	second := archivingStore(t, dir, fake, "", 400)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.puts != putsAfterFirstRun {
		t.Errorf("a restart re-uploaded %d object(s) that were already archived", fake.puts-putsAfterFirstRun)
	}
	if second.ArchiveStats().Skipped == 0 {
		t.Error("nothing was reported as already archived")
	}
	if len(fake.keys()) != sealed {
		t.Errorf("the archive gained keys on a run that wrote no record: %v", fake.keys())
	}
}

// Without an Archiver nothing changes: no goroutine, no counters, no keys.
func TestStoreWithoutAnArchiverReportsNothing(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, 400)
	appendN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := (s.ArchiveStats()); stats != (ArchiveStats{}) {
		t.Errorf("ArchiveStats = %+v, want the zero value", stats)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Errorf("ArchiveErr = %v, want nil", err)
	}
}

// rotatedDir is an evidence directory that has been written under one key,
// rotated to another, and anchored. It returns the id of the retired key.
func rotatedDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Keys: kp, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 6)
	// Closing writes the checkpoint that the rotation is about to strand: it is
	// signed by the key that is on its way out.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	cps, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) == 0 {
		t.Fatal("the first run wrote no checkpoint, so there is nothing for a retired key to have signed")
	}
	appendAnchor(t, dir, cps[0])

	rot, err := RotateKey(dir)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	return dir, rot.OldKeyID
}

// assembleFromArchive rebuilds an evidence directory from the archive alone,
// which is what somebody holding the bucket and nothing else has to work with.
// The snapshots are collapsed back to the file name they were taken from, and
// the last key in order wins: every one of them carries a zero-padded number
// that grows with the file, so that is the fullest snapshot the archive holds.
func assembleFromArchive(t *testing.T, root string) string {
	t.Helper()
	out := t.TempDir()

	copyTo := func(src, name string) {
		dst := filepath.Join(out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, readFileBytes(t, src), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	err := filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		base := path.Base(key)
		switch dir := path.Dir(key); dir {
		case "open":
			// open/seg-00000001.seq-000000000009.jsonl came from seg-00000001.jsonl.
			copyTo(p, strings.SplitN(base, ".seq-", 2)[0]+".jsonl")
		case "checkpoints":
			copyTo(p, CheckpointsFile)
		case "timestamps":
			copyTo(p, TimestampsFile)
		default:
			copyTo(p, key)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The archive is read by whoever holds the bucket, and after a rotation it
// holds checkpoints signed by a key that public-key.pem no longer names. If the
// retired public key and the anchors do not travel with them, that copy of the
// evidence cannot be verified by anyone, which makes the whole offsite copy
// theatre.
func TestArchiveCarriesRetiredKeysAndAnchorsAfterARotation(t *testing.T) {
	dir, retiredID := rotatedDir(t)

	root := t.TempDir()
	backend, err := archive.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	s := archivingStore(t, dir, backend, "", 0)
	appendN(t, s, 3)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Fatalf("ArchiveErr = %v, want nil", err)
	}

	retiredKey := RetiredKeysDir + "/retired-" + retiredID + ".pem"
	archived, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(retiredKey)))
	if err != nil {
		t.Fatalf("the archive does not hold %s, so the checkpoints it signed cannot be checked from the archive: %v",
			retiredKey, err)
	}
	if string(archived) != string(readFileBytes(t, filepath.Join(dir, filepath.FromSlash(retiredKey)))) {
		t.Error("the retired key in the archive differs from the one on disk")
	}

	// The decisive property: the archive on its own verifies, including the half
	// of the checkpoints that predate the rotation.
	assembled := assembleFromArchive(t, root)
	res, err := Verify(assembled)
	if err != nil {
		t.Fatalf("Verify on the archive: %v", err)
	}
	if !res.OK() {
		t.Fatalf("the archive alone does not verify: %v", res.Problems)
	}
	if res.Records != 10 {
		t.Errorf("the archive holds %d records, want 10", res.Records)
	}
	if len(res.RetiredKeys) != 1 || res.RetiredKeys[0] != retiredID {
		t.Errorf("retired keys in the archive = %v, want [%s]", res.RetiredKeys, retiredID)
	}
	if res.CheckpointsVerified != res.Checkpoints {
		t.Errorf("%d of %d archived checkpoints verified against the keys in the archive",
			res.CheckpointsVerified, res.Checkpoints)
	}
	if res.Timestamps != 1 {
		t.Errorf("the archive holds %d anchors, want 1; the RFC 3161 tokens never left the host", res.Timestamps)
	}
}

// An archive that cannot list keys/ says so. Silence there is the failure this
// test exists to keep out: an operator would read an archive with no retired
// keys as an archive that never needed any.
func TestUnreadableRetiredKeysAreReportedNotSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Go synthesises Unix permission bits there, so chmod would not make the
		// directory unreadable and the test would prove nothing.
		t.Skip("directory permissions are not enforced through os.Chmod on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root, which can read a directory with no permissions")
	}
	dir, _ := rotatedDir(t)
	keys := filepath.Join(dir, RetiredKeysDir)
	if err := os.Chmod(keys, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keys, 0o750) })

	s := archivingStore(t, dir, newFakeArchiver(), "", 0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	err := s.ArchiveErr()
	if err == nil {
		t.Fatal("keys/ could not be read and the archiver said nothing")
	}
	if !strings.Contains(err.Error(), RetiredKeysDir) {
		t.Errorf("ArchiveErr does not name what could not be read: %v", err)
	}
	if s.ArchiveStats().Failed == 0 {
		t.Error("nothing was counted as failed, so nothing would ever alert")
	}
}

// Anchors are appended by the timestamping goroutine, and Close drains the
// archive before it drains that goroutine, so the anchor over the last
// checkpoint of a run is written after the snapshot of timestamps.jsonl has
// gone up. Whatever names the object it went up under has to change when the
// file gains that anchor, or the next start offers a key the archive already
// holds, Exists answers yes, and the anchor never leaves the host: an
// installation shut down for the last time would leave its final anchors out
// of the offsite copy for good.
func TestAnAnchorWrittenAfterTheSnapshotStillReachesTheArchive(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	backend, err := archive.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}

	s := archivingStore(t, dir, backend, "", 400)
	appendN(t, s, 4)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cps, err := ReadCheckpoints(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) < 2 {
		t.Fatalf("the fixture wrote %d checkpoints, it needs at least two", len(cps))
	}

	// An anchor over an earlier checkpoint, and the restart that ships it. From
	// here the archive holds a timestamps object taken at this head.
	appendAnchor(t, dir, cps[0])
	s = archivingStore(t, dir, backend, "", 400)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The anchor over the last checkpoint, landing after that object went up.
	appendAnchor(t, dir, cps[len(cps)-1])

	// A restart that writes no record, which is what an idle installation does
	// and what a decommissioned one does exactly once.
	s = archivingStore(t, dir, backend, "", 400)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Fatalf("ArchiveErr = %v, want nil", err)
	}

	onDisk, err := ReadTimestamps(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(assembleFromArchive(t, root))
	if err != nil {
		t.Fatalf("Verify on the archive: %v", err)
	}
	if res.Timestamps != len(onDisk) {
		t.Errorf("the archive holds %d of the %d anchors on disk; the rest never left the host",
			res.Timestamps, len(onDisk))
	}
}

// A key file that is there and cannot be examined is the case that must not be
// quiet: an archive missing a retired key reads exactly like an archive that
// never needed one, and the difference only shows up when somebody tries to
// verify the offsite copy and cannot.
func TestAKeyFileThatCannotBeExaminedIsReportedNotSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks are not available to an unprivileged process on Windows")
	}
	dir, retiredID := rotatedDir(t)

	// A symlink loop: the name is in keys/ and stat cannot resolve it, which is
	// what a directory copied badly or a filesystem in trouble produces.
	retired := filepath.Join(dir, filepath.FromSlash(RetiredKeysDir), "retired-"+retiredID+".pem")
	loop := retired + ".loop"
	if err := os.Remove(retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loop, retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(retired, loop); err != nil {
		t.Fatal(err)
	}

	s := archivingStore(t, dir, newFakeArchiver(), "", 0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	err := s.ArchiveErr()
	if err == nil {
		t.Fatal("a retired key could not be read and the archiver said nothing")
	}
	if !strings.Contains(err.Error(), retiredID) {
		t.Errorf("ArchiveErr does not name the key that did not reach the archive: %v", err)
	}
	if s.ArchiveStats().Failed == 0 {
		t.Error("nothing was counted as failed, so nothing would ever alert")
	}
}

// externalSigner stands in for custody that has moved off the host: it signs
// exactly as the built-in key does, but the store is never given a KeyPair.
type externalSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func (s *externalSigner) Sign(preimage []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, preimage), nil
}
func (s *externalSigner) Public() ed25519.PublicKey { return s.pub }
func (s *externalSigner) KeyID() string             { return KeyID(s.pub) }

// Moving the private key off the host must not cost the archive its
// checkpoints. Segments in a bucket with nothing attesting to them are
// segments whoever holds that bucket cannot attribute to anybody.
func TestCheckpointsReachTheArchiveWhenSigningIsExternal(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	backend, err := archive.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        400,
		Signer:                 &externalSigner{pub: pub, priv: priv},
		Archiver:               backend,
		ArchiveShutdownTimeout: 5 * time.Second,
		Now:                    fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 4)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(assembleFromArchive(t, root))
	if err != nil {
		t.Fatalf("Verify on the archive: %v", err)
	}
	if res.Checkpoints == 0 {
		t.Fatal("the archive holds no checkpoints, so nothing in it can be attributed to the signer")
	}
	if !res.Attested || res.CheckpointsVerified != res.Checkpoints {
		t.Errorf("%d of %d archived checkpoints verified against the archived key",
			res.CheckpointsVerified, res.Checkpoints)
	}
}

// appendAnchor files an anchor against a checkpoint. The token is not a real
// RFC 3161 one, so verification reports it as a note rather than a problem;
// what the archive tests are about is whether the line reaches the bucket.
func appendAnchor(t *testing.T, dir string, c Checkpoint) {
	t.Helper()
	err := AppendTimestamp(dir, Timestamp{
		Seq:         c.Seq,
		RecordHash:  c.RecordHash,
		TokenBase64: base64.StdEncoding.EncodeToString([]byte("not a real timestamp token")),
		TSAURL:      "https://tsa.example/tsr",
		RequestedAt: "2026-03-01T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The anchor over a run's last checkpoint is written by the timestamping
// goroutine while the store is shutting down, which is after the point the
// shutdown flush snapshots timestamps.jsonl for the archive. A restart ships it;
// a host being decommissioned has no restart. So shutdown drains the
// timestamper before the archive and offers the anchors once more in between.
//
// The authority here answers slowly on purpose. That is the mechanism, not
// incidental: the defect only exists for an anchor that lands after the
// snapshot, and an instant answer lands before it and would make this test pass
// against the bug. The delay is two orders of magnitude longer than draining a
// handful of small files to a local directory, and both shutdown timeouts are
// set far above it.
func TestTheFinalAnchorOfARunReachesTheArchiveWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	backend, err := archive.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}

	const answerDelay = 300 * time.Millisecond
	stub := newTSAStub(t)
	stub.answer = func(t *testing.T, imprint []byte) ([]byte, error) {
		time.Sleep(answerDelay)
		return timestampResponseOver(t, imprint), nil
	}

	s, err := Open(Options{
		Dir:                    dir,
		SegmentMaxBytes:        400,
		Keys:                   kp,
		Archiver:               backend,
		ArchiveShutdownTimeout: 30 * time.Second,
		Timestamper:            stub,
		TSAInterval:            time.Nanosecond,
		TSATimeout:             30 * time.Second,
		Now:                    fixedClock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 12)

	// One shutdown, no second start. That is the whole point of the test.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.ArchiveErr(); err != nil {
		t.Fatalf("ArchiveErr = %v, want nil", err)
	}

	onDisk, err := ReadTimestamps(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) == 0 {
		t.Fatal("nothing was anchored, so the archive has nothing to be missing")
	}

	res, err := Verify(assembleFromArchive(t, root))
	if err != nil {
		t.Fatalf("Verify on the archive: %v", err)
	}
	if res.Timestamps != len(onDisk) {
		t.Errorf("the archive holds %d of the %d anchors on disk; the rest would have stayed on a host that never starts again",
			res.Timestamps, len(onDisk))
	}
}
