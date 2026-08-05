package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/archive"
	"github.com/RamazanKara/flugschreiber/internal/archivecheck"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// archivedLog records a log that rotates several times with a dir archive
// attached, so the keys under test are the ones the evidence store itself
// wrote rather than the ones this package believes it writes.
func archivedLog(t *testing.T, prefix string) (dir, root string) {
	t.Helper()
	dir, root = t.TempDir(), t.TempDir()
	recordWithArchive(t, dir, root, prefix, 40)

	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 3 {
		t.Fatalf("expected the log to rotate, got %d segment(s)", len(segs))
	}
	return dir, root
}

// recordWithArchive runs one server lifetime against dir with the archive
// attached: open, append, clean shutdown. Whatever the store uploads on that
// path is what these tests check against.
func recordWithArchive(t *testing.T, dir, root, prefix string, n int) {
	t.Helper()
	backend, err := archive.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := evidence.Open(evidence.Options{
		Dir:             dir,
		Keys:            kp,
		SegmentMaxBytes: 2048,
		Archiver:        backend,
		ArchivePrefix:   prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := store.Append(&evidence.Event{
			EventType: evidence.EventInference,
			RequestID: strings.Repeat("r", 24),
			Status:    200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// flipAByte alters one byte of a file without changing its length, which is
// the alteration only a run that reads the object back can see.
func flipAByte(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty, so there is nothing to alter", path)
	}
	body[len(body)/2] ^= 0x20
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
}

// archivedObjects lists the keys the dir backend holds, which is what the
// store actually wrote rather than what this package expects it to write.
func archivedObjects(t *testing.T, root string) []string {
	t.Helper()
	var keys []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		keys = append(keys, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// openSnapshotKey finds the snapshot of a segment that was still being written,
// as the store filed it.
func openSnapshotKey(t *testing.T, root string) string {
	t.Helper()
	for _, key := range archivedObjects(t, root) {
		if strings.HasPrefix(key, "open/") {
			return key
		}
	}
	t.Fatalf("the store archived no snapshot of the open segment: %v", archivedObjects(t, root))
	return ""
}

// sealedSegments is every segment that is final, which is every one but the
// segment a store would append to next.
func sealedSegments(t *testing.T, dir string) []string {
	t.Helper()
	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range segs[:len(segs)-1] {
		names = append(names, filepath.Base(s.Path))
	}
	return names
}

func archiveVerifyJSON(t *testing.T, args ...string) (int, archivecheck.VerifyResult) {
	t.Helper()
	code, out := runCLI(t, append([]string{"archive-verify"}, append(args, "--json")...)...)
	var res archivecheck.VerifyResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("archive-verify --json is not JSON: %v\n%s", err, out)
	}
	return code, res
}

func TestArchiveVerifyAcceptsACompleteArchive(t *testing.T) {
	dir, root := archivedLog(t, "")

	for _, mode := range [][]string{nil, {"--deep"}} {
		args := append([]string{"--dir", dir, "--archive-backend", "dir", "--archive-dir", root}, mode...)
		code, res := archiveVerifyJSON(t, args...)
		if code != 0 {
			t.Fatalf("archive-verify %v exited %d: %+v", mode, code, res.Objects)
		}
		if res.Missing != 0 || res.Mismatched != 0 || res.Unknown != 0 {
			t.Fatalf("archive-verify %v reported gaps in a complete archive: %+v", mode, res)
		}

		archived := map[string]string{}
		for _, o := range res.Objects {
			archived[o.Key] = o.Status
		}
		for _, name := range sealedSegments(t, dir) {
			if archived[name] != archivecheck.StatusPresent {
				t.Errorf("sealed segment %s was not checked: %+v", name, res.Objects)
			}
		}
		if archived[evidence.PublicKeyFile] != archivecheck.StatusPresent {
			t.Errorf("the public key was not checked: %+v", res.Objects)
		}
		if res.CheckpointSnapshots == 0 {
			t.Errorf("no checkpoint snapshot was found, so nothing in the archive attests to it: %+v", res)
		}
	}
}

// The roadmap's acceptance condition: an object removed from the archive makes
// the command fail and names the key, rather than reporting a healthy archive.
func TestArchiveVerifyNamesAnObjectTheArchiveHasLost(t *testing.T) {
	dir, root := archivedLog(t, "")
	lost := sealedSegments(t, dir)[0]
	if err := os.Remove(filepath.Join(root, lost)); err != nil {
		t.Fatal(err)
	}

	code, out := runCLI(t, "archive-verify", "--dir", dir, "--archive-backend", "dir", "--archive-dir", root)
	if code == 0 {
		t.Fatalf("a missing segment did not fail the command\n%s", out)
	}
	if !strings.Contains(out, lost) {
		t.Errorf("the output does not name the missing key %q:\n%s", lost, out)
	}
}

// Presence and content are different claims, and the command must not make the
// second one when it only checked the first.
func TestOnlyADeepRunCatchesAnAlteredObject(t *testing.T) {
	dir, root := archivedLog(t, "")
	// One byte, same length: the object is still there and still the right
	// size, so nothing but reading it back can tell.
	flipAByte(t, filepath.Join(root, sealedSegments(t, dir)[1]))

	if code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root); code != 0 {
		t.Fatalf("the presence check claimed to detect an altered object: %+v", res.Objects)
	}

	code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code == 0 {
		t.Fatal("--deep did not detect an altered object")
	}
	if res.Mismatched != 1 {
		t.Fatalf("mismatched = %d, want 1: %+v", res.Mismatched, res.Objects)
	}
	if res.BytesCompared == 0 {
		t.Error("a deep run reported comparing no bytes")
	}
}

// A run has to say what it did not do, and a presence-only run has strictly
// more of that to say than a deep one.
func TestArchiveVerifyReportsWhatItCouldNotCheck(t *testing.T) {
	dir, root := archivedLog(t, "")

	_, shallow := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root)
	_, deep := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")

	if len(deep.NotChecked) == 0 {
		t.Fatal("a clean deep run claimed to have checked everything")
	}
	if len(shallow.NotChecked) <= len(deep.NotChecked) {
		t.Errorf("a presence-only run listed %d limits and a deep one %d; the weaker check must say more",
			len(shallow.NotChecked), len(deep.NotChecked))
	}

	// The segment still being written is covered only by the snapshot a clean
	// shutdown left. Without that object there is nothing to check it against,
	// and the run has to say so rather than counting it as verified.
	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Base(segs[len(segs)-1].Path)
	if strings.Contains(strings.Join(deep.NotChecked, "\n"), active) {
		t.Errorf("%s has a snapshot in the archive and was still reported as unchecked: %v", active, deep.NotChecked)
	}

	if err := os.Remove(filepath.Join(root, openSnapshotKey(t, root))); err != nil {
		t.Fatal(err)
	}
	_, without := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if !strings.Contains(strings.Join(without.NotChecked, "\n"), active) {
		t.Errorf("with no snapshot of %s in the archive, the run did not report it as unchecked: %v",
			active, without.NotChecked)
	}
}

// The segment still being written holds the newest evidence there is. A clean
// shutdown archives a snapshot of it under a key naming the segment and the
// head it reached, and checkpoints.jsonl names both, so it is checkable.
func TestArchiveVerifyChecksTheSnapshotOfTheOpenSegment(t *testing.T) {
	dir, root := archivedLog(t, "")
	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	active := segs[len(segs)-1].Path

	code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code != 0 {
		t.Fatalf("archive-verify exited %d on a complete archive: %+v", code, res.Objects)
	}
	if res.OpenSnapshots != 1 {
		t.Fatalf("open_snapshots = %d, want 1: %+v", res.OpenSnapshots, res.Objects)
	}
	var checked bool
	for _, o := range res.Objects {
		if o.Kind != archivecheck.KindOpenSegment {
			continue
		}
		checked = true
		if o.Local != active {
			t.Errorf("the snapshot %s was compared against %s, want %s", o.Key, o.Local, active)
		}
		if o.Bytes == 0 {
			t.Errorf("the snapshot %s was reported as compared over no bytes", o.Key)
		}
	}
	if !checked {
		t.Fatal("no snapshot of the open segment was checked")
	}

	// Altering the snapshot must be caught, and only by a run that reads it
	// back: the presence check cannot see inside an object.
	flipAByte(t, filepath.Join(root, openSnapshotKey(t, root)))
	if code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root); code != 0 {
		t.Fatalf("the presence check claimed to detect an altered snapshot: %+v", res.Objects)
	}
	code, res = archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code == 0 {
		t.Fatal("an altered snapshot of the open segment was not detected")
	}
	if res.Mismatched != 1 {
		t.Fatalf("mismatched = %d, want 1: %+v", res.Mismatched, res.Objects)
	}
}

// A key rotation leaves the archive holding checkpoints signed under a key that
// is no longer in public-key.pem. The store uploads the retired public half for
// exactly that reason, so the archive stays checkable by whoever holds it, and
// this command has to be able to tell whether it arrived.
func TestArchiveVerifyChecksTheKeysARotationRetired(t *testing.T) {
	dir, root := archivedLog(t, "")
	if code, out := runCLI(t, "keys", "rotate", "--dir", dir); code != 0 {
		t.Fatalf("keys rotate exited %d\n%s", code, out)
	}
	retired, err := evidence.RetiredKeyFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 {
		t.Fatalf("the rotation retired %v, want exactly one key", retired)
	}

	// Nothing has run since the rotation, so the archive cannot hold the key
	// yet. That is a normal state and must not be reported as a gap, but it
	// must be reported.
	code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code != 0 {
		t.Fatalf("a rotation the archive has not caught up with failed the run: %+v", res.Objects)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), retired[0]) {
		t.Errorf("the run does not say that %s is not in the archive: %v", retired[0], res.Notes)
	}

	// A run after the rotation uploads it, and then it is checkable.
	recordWithArchive(t, dir, root, "", 5)
	code, res = archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code != 0 {
		t.Fatalf("archive-verify exited %d after the retired key reached the archive: %+v", code, res.Objects)
	}
	var checked bool
	for _, o := range res.Objects {
		if o.Kind == archivecheck.KindRetiredKey && o.Key == retired[0] {
			checked = true
			if o.Status != archivecheck.StatusPresent {
				t.Errorf("the archived retired key is reported as %q: %s", o.Status, o.Detail)
			}
		}
	}
	if !checked {
		t.Fatalf("the retired key %s was not checked: %+v", retired[0], res.Objects)
	}

	// A retired key is written once and never changes, so a copy in the archive
	// that differs from the local one is a finding rather than drift.
	flipAByte(t, filepath.Join(root, filepath.FromSlash(retired[0])))
	if code, out := runCLI(t, "archive-verify", "--dir", dir,
		"--archive-backend", "dir", "--archive-dir", root, "--deep"); code == 0 {
		t.Fatalf("an altered retired key in the archive did not fail the command\n%s", out)
	}
}

func TestArchiveVerifyLooksUnderTheConfiguredPrefix(t *testing.T) {
	dir, root := archivedLog(t, "site-a")

	if code, _ := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root); code == 0 {
		t.Error("archive-verify found the evidence without being told the prefix it was archived under")
	}
	code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root,
		"--archive-prefix", "site-a")
	if code != 0 {
		t.Fatalf("archive-verify exited %d under the right prefix: %+v", code, res.Objects)
	}
	for _, o := range res.Objects {
		if !strings.HasPrefix(o.Key, "site-a/") {
			t.Errorf("key %q was not looked for under the prefix", o.Key)
		}
	}
}

// D27: both the evidence store and the backend can prepend a key prefix, and a
// command that set both would look under site-a/site-a for evidence that is
// under site-a. The dir backend has no prefix of its own, so only the s3 path
// can make this mistake, and only a real request shows which key was asked for.
func TestArchiveVerifyAppliesTheKeyPrefixExactlyOnce(t *testing.T) {
	dir, _ := archivedLog(t, "site-a")

	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The backend checks the bucket itself before it reports an object
		// absent, so that a missing bucket is never read as a missing object.
		if r.URL.Path == "/evidence" {
			return
		}
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		// Every object absent, which is a definitive answer and keeps the
		// backend from retrying.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := filepath.Join(t.TempDir(), "config.json")
	body := fmt.Sprintf(`{"archive": {"backend": "s3", "bucket": "evidence", "region": "eu-central-1",
		"endpoint": %q, "addressing": "path", "prefix": "site-a",
		"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret"}}`, srv.URL)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// The archive is empty, so the run fails; what it asked for is the point.
	runCLI(t, "archive-verify", "--dir", dir, "--config", cfg)

	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 {
		t.Fatal("the s3 backend was never asked for anything")
	}
	for _, path := range asked {
		if !strings.HasPrefix(path, "/evidence/site-a/") {
			t.Errorf("asked for %q, which is not under the bucket and prefix the evidence was archived with", path)
		}
		if strings.Count(path, "site-a") != 1 {
			t.Errorf("asked for %q: the prefix was applied more than once", path)
		}
	}
}

func TestArchiveVerifyRefusesWithoutAnArchiveToCheck(t *testing.T) {
	dir, _ := archivedLog(t, "")

	if code, _ := runCLI(t, "archive-verify", "--dir", dir); code == 0 {
		t.Error("archive-verify succeeded with no archive configured")
	}

	absent := filepath.Join(t.TempDir(), "not-here")
	if code, _ := runCLI(t, "archive-verify", "--dir", dir, "--archive-backend", "dir", "--archive-dir", absent); code == 0 {
		t.Error("archive-verify succeeded against an archive that does not exist")
	}
	// Creating the directory would turn "there is no archive" into "the
	// archive is empty", which reads as data loss.
	if _, err := os.Stat(absent); err == nil {
		t.Errorf("archive-verify created %s", absent)
	}
}

// The store uploads the public key once and skips it thereafter, so after a
// rotation the archive legitimately holds a key this directory has retired.
// Reporting that as a mismatch would send an operator hunting for tampering
// that did not happen.
func TestArchiveVerifyAccountsForARotatedPublicKey(t *testing.T) {
	dir, root := archivedLog(t, "")
	before, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := runCLI(t, "keys", "rotate", "--dir", dir); code != 0 {
		t.Fatalf("keys rotate exited %d\n%s", code, out)
	}

	code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code != 0 {
		t.Fatalf("archive-verify failed after a key rotation: %+v", res.Objects)
	}
	var found bool
	for _, o := range res.Objects {
		if o.Kind != archivecheck.KindPublicKey {
			continue
		}
		found = true
		if o.Status != archivecheck.StatusPresent {
			t.Fatalf("the archived public key is reported as %q: %s", o.Status, o.Detail)
		}
		if !strings.Contains(o.Detail, before.ID) {
			t.Errorf("the report does not say which key the archive holds (%s): %q", before.ID, o.Detail)
		}
	}
	if !found {
		t.Fatal("the public key was not checked at all")
	}
}

// A pruned segment exists only in the archive, so its absence there is the
// difference between evidence that was retained and evidence that is gone.
func TestArchiveVerifyChecksSegmentsRetentionHasDeletedLocally(t *testing.T) {
	dir, root := archivedLog(t, "")
	pruned := sealedSegments(t, dir)[0]

	kp, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	anchor := evidence.PruneAnchor{
		Version:        evidence.PruneAnchorVersion,
		PrunedAt:       "2026-01-01T00:00:00Z",
		LastPrunedSeq:  1,
		LastPrunedHash: strings.Repeat("a", 64),
		Segments:       []string{pruned},
		Records:        1,
		Reason:         "test",
	}
	if err := evidence.SignPruneAnchor(kp.Private, kp.ID, &anchor); err != nil {
		t.Fatal(err)
	}
	if err := evidence.WritePruneAnchor(dir, anchor); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, pruned)); err != nil {
		t.Fatal(err)
	}

	code, res := archiveVerifyJSON(t, "--dir", dir, "--archive-backend", "dir", "--archive-dir", root, "--deep")
	if code != 0 {
		t.Fatalf("archive-verify exited %d although the archive still holds the pruned segment: %+v", code, res.Objects)
	}
	var checked bool
	for _, o := range res.Objects {
		if o.Kind == archivecheck.KindPrunedSegment && o.Key == pruned {
			checked = true
			if o.Status != archivecheck.StatusPresent {
				t.Errorf("the pruned segment is reported as %q", o.Status)
			}
		}
	}
	if !checked {
		t.Fatalf("the segment named in %s was not checked: %+v", evidence.PruneAnchorFile, res.Objects)
	}

	if err := os.Remove(filepath.Join(root, pruned)); err != nil {
		t.Fatal(err)
	}
	if code, out := runCLI(t, "archive-verify", "--dir", dir,
		"--archive-backend", "dir", "--archive-dir", root); code == 0 {
		t.Fatalf("losing the only remaining copy of a pruned segment did not fail the command\n%s", out)
	}
}
