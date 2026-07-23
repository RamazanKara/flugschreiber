package audit

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	write("client-salt", "0123456789abcdef0123456789abcdef", 0o600)

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
	write(evidence.SigningKeyFile, "-----BEGIN PRIVATE KEY-----\nDO-NOT-EXPORT\n-----END PRIVATE KEY-----\n", 0o600)
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
	for _, sentinel := range []string{"DO-NOT-EXPORT", "0123456789abcdef0123456789abcdef"} {
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

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
