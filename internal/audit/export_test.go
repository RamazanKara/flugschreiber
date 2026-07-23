package audit

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func exportFixture(t *testing.T) string {
	t.Helper()
	dir := fixture(t)

	// Files a real evidence directory carries alongside the segments. The
	// secrets are written deliberately so the export tests can prove they stay
	// behind.
	write := func(name, body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("client-salt", saltSentinel, 0o600)

	// A real key and a real checkpoint over the real chain head. A fabricated
	// checkpoint would now be caught by verification, which is the point of it,
	// so the fixture has to be genuine for the export tests to exercise the
	// path an operator actually hits.
	keys, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	cp := evidence.Checkpoint{
		Version:    evidence.CheckpointVersion,
		Segment:    head.Segments[len(head.Segments)-1],
		Seq:        head.LastSeq,
		RecordHash: head.HeadHash,
		Records:    head.Records,
		Timestamp:  time.Date(2026, 6, 1, 9, 5, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	if err := evidence.SignCheckpoint(keys.Private, keys.ID, &cp); err != nil {
		t.Fatal(err)
	}
	if err := evidence.AppendCheckpoint(dir, cp); err != nil {
		t.Fatal(err)
	}

	// Overwrite the real private key with a sentinel so the export tests can
	// prove by content, not just by filename, that it stays behind.
	write(evidence.SigningKeyFile, keySentinel, 0o600)
	return dir
}

func readBundle(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("bundle is not valid gzip: %v", err)
	}
	defer gz.Close()

	out := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("bundle is not a valid tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(body)
	}
	return out
}

func exportTo(t *testing.T, dir string) (string, map[string]string, BundleManifest) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	res, err := Export(ExportOptions{
		Dir: dir, Out: out,
		Now: func() time.Time { return time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return out, readBundle(t, out), res.Manifest
}

func TestExportBundlesSegmentsAndPublicMaterial(t *testing.T) {
	_, files, manifest := exportTo(t, exportFixture(t))

	for _, want := range []string{
		"flugschreiber-evidence/seg-00000001.jsonl",
		"flugschreiber-evidence/checkpoints.jsonl",
		"flugschreiber-evidence/public-key.pem",
		"flugschreiber-evidence/MANIFEST.json",
		"flugschreiber-evidence/VERIFY.md",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle is missing %s", want)
		}
	}
	if manifest.Records != 4 {
		t.Errorf("Records = %d, want 4", manifest.Records)
	}
	if !manifest.ChainVerified {
		t.Error("ChainVerified = false for an intact fixture")
	}
	if manifest.Checkpoints != 1 {
		t.Errorf("Checkpoints = %d, want 1", manifest.Checkpoints)
	}
}

// The signing key and the client salt are what would let a recipient forge
// evidence or reverse a caller identity. They must never be in a bundle, and
// this test is the thing standing between a refactor and a leaked key.
func TestExportNeverIncludesSecrets(t *testing.T) {
	path, files, _ := exportTo(t, exportFixture(t))

	for name := range files {
		base := filepath.Base(name)
		if secretFiles[base] {
			t.Fatalf("bundle contains the secret file %s", base)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The archive is compressed, so also check the decompressed contents for
	// the sentinel values rather than trusting the filenames alone.
	var all strings.Builder
	for _, body := range files {
		all.WriteString(body)
	}
	for _, sentinel := range []string{"DO-NOT-EXPORT", saltSentinel} {
		if strings.Contains(all.String(), sentinel) {
			t.Errorf("secret material %q appears inside the bundle", sentinel)
		}
	}
	if len(raw) == 0 {
		t.Error("bundle is empty")
	}
}

func TestExportManifestDigestsMatchTheBundledFiles(t *testing.T) {
	_, files, manifest := exportTo(t, exportFixture(t))

	if len(manifest.Files) == 0 {
		t.Fatal("manifest lists no files")
	}
	for _, f := range manifest.Files {
		body, ok := files["flugschreiber-evidence/"+f.Name]
		if !ok {
			t.Errorf("manifest lists %s but the bundle does not contain it", f.Name)
			continue
		}
		if int64(len(body)) != f.Bytes {
			t.Errorf("%s: manifest says %d bytes, bundle has %d", f.Name, f.Bytes, len(body))
		}
		if got := sha256Hex(body); got != f.SHA256 {
			t.Errorf("%s: manifest digest %s, actual %s", f.Name, f.SHA256, got)
		}
	}
}

func TestExportManifestIsValidJSON(t *testing.T) {
	_, files, _ := exportTo(t, exportFixture(t))

	var m BundleManifest
	if err := json.Unmarshal([]byte(files["flugschreiber-evidence/MANIFEST.json"]), &m); err != nil {
		t.Fatalf("MANIFEST.json does not parse: %v", err)
	}
	if m.Version != 1 || m.Tool != "flugschreiber" {
		t.Errorf("manifest = %+v", m)
	}
	if m.HeadHash == "" {
		t.Error("manifest has no chain head hash")
	}
}

// A recipient reading VERIFY.md must be told what the bundle does not prove,
// not just what it does.
func TestVerifyInstructionsStateTheLimits(t *testing.T) {
	_, files, _ := exportTo(t, exportFixture(t))
	doc := files["flugschreiber-evidence/VERIFY.md"]

	for _, want := range []string{
		"flugschreiber verify --dir",
		"does not prove that the log is complete",
		"never passed\nthrough the proxy",
		"not a statement",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("VERIFY.md does not mention %q:\n%s", want, doc)
		}
	}
}

func TestExportOnBrokenChainStillSucceedsAndSaysSo(t *testing.T) {
	dir := exportFixture(t)

	seg := filepath.Join(dir, "seg-00000001.jsonl")
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"llama-3.1-8b"`, `"tampered-model"`, 1)
	if edited == string(raw) {
		t.Fatal("fixture does not contain the string this test edits")
	}
	if err := os.WriteFile(seg, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	_, files, manifest := exportTo(t, dir)

	if manifest.ChainVerified {
		t.Error("ChainVerified = true for a tampered log")
	}
	if len(manifest.Problems) == 0 {
		t.Error("manifest records no problems for a tampered log")
	}
	if !strings.Contains(files["flugschreiber-evidence/VERIFY.md"], "**FAILED**") {
		t.Error("VERIFY.md does not tell the recipient verification failed at export")
	}
}

func TestExportRefusesAnEmptyDirectory(t *testing.T) {
	_, err := Export(ExportOptions{Dir: t.TempDir(), Out: filepath.Join(t.TempDir(), "b.tar.gz")})
	if err == nil {
		t.Fatal("exporting an empty directory should be an error")
	}
	if !strings.Contains(err.Error(), "no evidence") {
		t.Errorf("error = %v", err)
	}
}

func TestExportIsDeterministicForTheSameInput(t *testing.T) {
	dir := exportFixture(t)
	_, first, _ := exportTo(t, dir)
	_, second, _ := exportTo(t, dir)

	if len(first) != len(second) {
		t.Fatalf("bundles have different file counts: %d vs %d", len(first), len(second))
	}
	for name, body := range first {
		if second[name] != body {
			t.Errorf("%s differs between two exports of the same directory", name)
		}
	}
}

// rotatedFixture is an evidence directory whose signing key has been rotated
// once, with an anchored checkpoint from before the rotation.
//
// It is the state an installation reaches the first time an operator follows
// the key rotation instructions, and the state in which a bundle that carries
// only public-key.pem is worthless: half the checkpoints in it were signed by a
// key that file no longer holds. It returns the id of the retired key.
func rotatedFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := fixture(t)

	if err := os.WriteFile(filepath.Join(dir, "client-salt"), []byte(saltSentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := evidence.LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	cp := evidence.Checkpoint{
		Version:    evidence.CheckpointVersion,
		Segment:    head.Segments[len(head.Segments)-1],
		Seq:        head.LastSeq,
		RecordHash: head.HeadHash,
		Records:    head.Records,
		Timestamp:  time.Date(2026, 6, 1, 9, 5, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	if err := evidence.SignCheckpoint(keys.Private, keys.ID, &cp); err != nil {
		t.Fatal(err)
	}
	if err := evidence.AppendCheckpoint(dir, cp); err != nil {
		t.Fatal(err)
	}

	// An anchor over that checkpoint. The token is not a real RFC 3161 one, so
	// verification reports it as a note rather than a problem; what this fixture
	// is about is whether the anchor reaches the bundle at all.
	err = evidence.AppendTimestamp(dir, evidence.Timestamp{
		Seq:         cp.Seq,
		RecordHash:  cp.RecordHash,
		TokenBase64: base64.StdEncoding.EncodeToString([]byte("not a real timestamp token")),
		TSAURL:      "https://tsa.example/tsr",
		RequestedAt: time.Date(2026, 6, 1, 9, 6, 0, 0, time.UTC).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}

	rot, err := evidence.RotateKey(dir)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// The new private key is replaced by a sentinel only now, because rotating
	// needs the real one. From here the tests can prove by content that it stays
	// behind.
	if err := os.WriteFile(filepath.Join(dir, evidence.SigningKeyFile), []byte(keySentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, rot.OldKeyID
}

const (
	keySentinel  = "-----BEGIN PRIVATE KEY-----\nDO-NOT-EXPORT\n-----END PRIVATE KEY-----\n"
	saltSentinel = "0123456789abcdef0123456789abcdef"
)

// extractBundle writes a bundle out the way a recipient would, keeping the
// directory structure, so that what is verified is the bundle rather than a
// flattened rearrangement of it.
func extractBundle(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		rel := strings.TrimPrefix(name, "flugschreiber-evidence/")
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func bundleNames(files map[string]string) []string {
	out := make([]string, 0, len(files))
	for name := range files {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// The bundle is the only thing the recipient gets. After a rotation that means
// it has to carry the retired public key: without it, every checkpoint signed
// before the rotation is signed by a key nobody outside this host holds, which
// is exactly the failure the export exists to prevent.
func TestExportedBundleVerifiesStandaloneAfterAKeyRotation(t *testing.T) {
	dir, retiredID := rotatedFixture(t)
	_, files, manifest := exportTo(t, dir)

	retired := "flugschreiber-evidence/keys/retired-" + retiredID + ".pem"
	if _, ok := files[retired]; !ok {
		t.Fatalf("the bundle does not carry the retired key %s, so the checkpoints it signed cannot be checked; the bundle holds %v",
			retiredID, bundleNames(files))
	}

	extracted := extractBundle(t, files)
	res, err := evidence.Verify(extracted)
	if err != nil {
		t.Fatalf("Verify on the extracted bundle: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a recipient cannot verify the bundle: %v", res.Problems)
	}
	if !res.Attested {
		t.Error("no checkpoint in the extracted bundle verified against a key the bundle carries")
	}
	if res.CheckpointsVerified != res.Checkpoints {
		t.Errorf("%d of %d checkpoints verified from the bundle alone", res.CheckpointsVerified, res.Checkpoints)
	}
	if len(res.RetiredKeys) != 1 || res.RetiredKeys[0] != retiredID {
		t.Errorf("retired keys in the extracted bundle = %v, want [%s]", res.RetiredKeys, retiredID)
	}
	if len(manifest.RetiredKeys) != 1 || manifest.RetiredKeys[0] != retiredID {
		t.Errorf("MANIFEST.json retired keys = %v, want [%s]", manifest.RetiredKeys, retiredID)
	}

	// The secrets stay behind whatever else the bundle grew.
	for name, body := range files {
		if secretFiles[path.Base(name)] {
			t.Fatalf("bundle contains the secret file %s", name)
		}
		for _, sentinel := range []string{"DO-NOT-EXPORT", saltSentinel} {
			if strings.Contains(body, sentinel) {
				t.Fatalf("secret material %q appears in %s", sentinel, name)
			}
		}
	}
}

// An RFC 3161 anchor is the only part of the evidence whose time does not rest
// on the operator's word. Leaving it behind on export silently downgrades every
// timestamped checkpoint back to that word.
func TestExportCarriesTheTimestampAnchors(t *testing.T) {
	dir, _ := rotatedFixture(t)
	_, files, manifest := exportTo(t, dir)

	body, ok := files["flugschreiber-evidence/timestamps.jsonl"]
	if !ok {
		t.Fatalf("the bundle does not carry timestamps.jsonl; it holds %v", bundleNames(files))
	}
	local, err := os.ReadFile(filepath.Join(dir, evidence.TimestampsFile))
	if err != nil {
		t.Fatal(err)
	}
	if body != string(local) {
		t.Error("the anchors in the bundle differ from the ones on disk")
	}
	if manifest.Timestamps != 1 {
		t.Errorf("MANIFEST.json reports %d anchors, want 1", manifest.Timestamps)
	}

	res, err := evidence.Verify(extractBundle(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if res.Timestamps != 1 {
		t.Errorf("the extracted bundle holds %d anchors, want 1", res.Timestamps)
	}
	if !strings.Contains(files["flugschreiber-evidence/VERIFY.md"], "timestamps.jsonl") {
		t.Error("VERIFY.md does not tell the recipient what timestamps.jsonl is")
	}
}

// keys/ is written by rotation and holds public keys. A private key that
// reached it by hand or by a careless copy must stop the export rather than
// travel in it, and the file name cannot be trusted to tell the two apart.
func TestExportRefusesPrivateKeyMaterialFiledUnderKeys(t *testing.T) {
	dir := exportFixture(t)
	keysDir := filepath.Join(dir, evidence.RetiredKeysDir)
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "retired-0123456789abcdef.pem"), []byte(keySentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	_, err := Export(ExportOptions{Dir: dir, Out: out})
	if err == nil {
		t.Fatal("export bundled a private key that was filed as a retired key")
	}
	if !strings.Contains(err.Error(), "must never leave the host") {
		t.Errorf("error = %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a bundle was written even though the export refused")
	}
}

// An operator re-exports over yesterday's bundle, and the export fails part
// way. Writing straight to the destination would have truncated the good
// bundle before the first byte of its replacement was read, leaving a fragment
// under a name that says it is evidence. A truncated .tar.gz reads as a whole
// one until somebody opens it.
func TestAFailedExportLeavesTheBundleAlreadyThereIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Creating a symlink needs a privilege the test runner does not have
		// there, and the failure has to happen inside the tar loop rather than
		// before it for this to be testing anything.
		t.Skip("symlinks are not available to an unprivileged process on Windows")
	}
	dir := exportFixture(t)
	// LEGAL_HOLD is collected but never opened by Verify, so a dangling symlink
	// under that name gets past verification and fails once the bundle is
	// already being written.
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, evidence.LegalHoldFile)); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	out := filepath.Join(outDir, "bundle.tar.gz")
	previous := "yesterday's bundle, handed to the auditor already"
	if err := os.WriteFile(out, []byte(previous), 0o640); err != nil {
		t.Fatal(err)
	}

	if _, err := Export(ExportOptions{Dir: dir, Out: out}); err == nil {
		t.Fatal("Export reported success with a file it could not read")
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the bundle that was already there is gone: %v", err)
	}
	if string(got) != previous {
		t.Errorf("the bundle that was already there was overwritten with %d bytes of a failed export", len(got))
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "bundle.tar.gz" {
			t.Errorf("the failed export left %s behind", e.Name())
		}
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// The content keystore opens every sealed prompt in the log. It sits on exactly
// the same footing as the signing key and the client salt: a recipient who has
// it can read content the operator has not decided to hand over, and once a
// bundle has left the building that decision cannot be taken back.
func TestExportNeverIncludesTheContentKeystore(t *testing.T) {
	const keystoreSentinel = "MASTER-CONTENT-KEY-DO-NOT-EXPORT"
	dir := exportFixture(t)

	// Written by hand rather than through OpenContentKeystore, because the
	// claim under test is about the filename and the bytes, not about the
	// keystore's own format.
	path := evidence.ContentKeystorePath(dir)
	if err := os.WriteFile(path, []byte(keystoreSentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	_, files, _ := exportTo(t, dir)
	for name, body := range files {
		if filepath.Base(name) == filepath.Base(path) {
			t.Fatalf("the bundle carries the content keystore as %s", name)
		}
		if strings.Contains(body, keystoreSentinel) {
			t.Fatalf("the master content key leaked into %s", name)
		}
	}
}
