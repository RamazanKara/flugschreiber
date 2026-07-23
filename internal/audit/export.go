package audit

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/evidence"
)

// secretFiles never leave the host, whatever else is in the directory.
//
// This is an allowlist problem dressed as a denylist, so it is enforced twice:
// only known-good filename shapes are collected, and then anything matching
// this set is refused with an error rather than skipped. A silent skip would
// turn a future bug into a leaked signing key.
var secretFiles = map[string]bool{
	"signing-key.pem": true,
	"client-salt":     true,
}

// BundleManifest describes an evidence export so a recipient can tell whether
// what they received is what was sent.
type BundleManifest struct {
	Version    int          `json:"version"`
	Tool       string       `json:"tool"`
	ExportedAt string       `json:"exported_at"`
	SourceDir  string       `json:"source_directory"`
	Files      []BundleFile `json:"files"`
	TotalBytes int64        `json:"total_bytes"`

	Records       uint64             `json:"records"`
	FirstSeq      uint64             `json:"first_seq"`
	LastSeq       uint64             `json:"last_seq"`
	FirstRecord   string             `json:"first_record,omitempty"`
	LastRecord    string             `json:"last_record,omitempty"`
	HeadHash      string             `json:"head_hash,omitempty"`
	ChainVerified bool               `json:"chain_verified_at_export"`
	Problems      []evidence.Problem `json:"problems,omitempty"`
	Checkpoints   int                `json:"checkpoints"`
	Pruned        bool               `json:"pruned"`
}

// BundleFile is one file in the bundle with the digest of its contents.
type BundleFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// ExportOptions configures a bundle.
type ExportOptions struct {
	Dir  string
	Out  string
	Now  func() time.Time
	Note string
}

// ExportResult reports what was written.
type ExportResult struct {
	Path     string
	Manifest BundleManifest
}

// Export writes a self-contained evidence bundle as a gzipped tar archive.
//
// The bundle holds everything a third party needs to check the evidence and
// nothing that would let them impersonate the system that produced it: the
// segments, the checkpoints, the public key, a manifest, and instructions.
func Export(opts ExportOptions) (*ExportResult, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("export: source directory is required")
	}
	if opts.Out == "" {
		return nil, fmt.Errorf("export: output path is required")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	files, err := collect(opts.Dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("export: no evidence found in %s", opts.Dir)
	}

	verified, err := evidence.Verify(opts.Dir)
	if err != nil {
		return nil, err
	}

	manifest := BundleManifest{
		Version:       1,
		Tool:          "flugschreiber",
		ExportedAt:    now().UTC().Format(time.RFC3339Nano),
		SourceDir:     opts.Dir,
		Records:       verified.Records,
		FirstSeq:      verified.FirstSeq,
		LastSeq:       verified.LastSeq,
		FirstRecord:   verified.FirstTime,
		LastRecord:    verified.LastTime,
		HeadHash:      verified.HeadHash,
		ChainVerified: verified.OK(),
		Problems:      verified.Problems,
	}

	if err := os.MkdirAll(filepath.Dir(opts.Out), 0o750); err != nil {
		return nil, err
	}
	out, err := os.OpenFile(opts.Out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	const root = "flugschreiber-evidence"

	for _, name := range files {
		path := filepath.Join(opts.Dir, name)
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		digest, err := fileDigest(path)
		if err != nil {
			return nil, err
		}
		if err := writeFileEntry(tw, filepath.Join(root, name), path, info); err != nil {
			return nil, err
		}
		manifest.Files = append(manifest.Files, BundleFile{
			Name: name, Bytes: info.Size(), SHA256: digest,
		})
		manifest.TotalBytes += info.Size()
		if name == "checkpoints.jsonl" {
			manifest.Checkpoints = countLines(path)
		}
		if name == "pruned.json" {
			manifest.Pruned = true
		}
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestJSON = append(manifestJSON, '\n')
	if err := writeBytesEntry(tw, filepath.Join(root, "MANIFEST.json"), manifestJSON, now()); err != nil {
		return nil, err
	}

	instructions := []byte(verifyInstructions(manifest, opts.Note))
	if err := writeBytesEntry(tw, filepath.Join(root, "VERIFY.md"), instructions, now()); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if err := out.Sync(); err != nil {
		return nil, err
	}

	return &ExportResult{Path: opts.Out, Manifest: manifest}, nil
}

// collect lists the files that belong in a bundle, in a stable order, and
// refuses outright if a secret would be included.
func collect(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var segments, extras []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if secretFiles[name] {
			continue
		}
		switch {
		case strings.HasPrefix(name, "seg-") && strings.HasSuffix(name, ".jsonl"):
			segments = append(segments, name)
		case name == "checkpoints.jsonl", name == "public-key.pem",
			name == "pruned.json", name == "LEGAL_HOLD":
			extras = append(extras, name)
		}
	}

	sortStrings(segments)
	sortStrings(extras)
	out := append(segments, extras...)

	for _, name := range out {
		if secretFiles[name] {
			return nil, fmt.Errorf("export: refusing to bundle %s, which must never leave the host", name)
		}
	}
	return out, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func writeFileEntry(tw *tar.Writer, name, path string, info os.FileInfo) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    info.Size(),
		ModTime: info.ModTime().UTC(),
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func writeBytesEntry(tw *tar.Writer, name string, body []byte, now time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: now.UTC(),
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// verifyInstructions is written into the bundle so that a recipient who has
// never heard of this tool can still check what they were given.
func verifyInstructions(m BundleManifest, note string) string {
	var b strings.Builder

	b.WriteString("# Verifying this evidence bundle\n\n")
	b.WriteString("This archive contains an append-only, hash-chained log of interactions with\n")
	b.WriteString("an AI system, exported by Flugschreiber, an open-source audit proxy.\n\n")

	if note != "" {
		b.WriteString("Note from the exporter: " + note + "\n\n")
	}

	b.WriteString("## What is here\n\n")
	b.WriteString("| File | Purpose |\n| --- | --- |\n")
	b.WriteString("| `seg-*.jsonl` | The evidence records, one JSON object per line |\n")
	if m.Checkpoints > 0 {
		b.WriteString("| `checkpoints.jsonl` | Ed25519-signed attestations of the chain head over time |\n")
		b.WriteString("| `public-key.pem` | The public key those signatures verify against |\n")
	}
	if m.Pruned {
		b.WriteString("| `pruned.json` | Records which segments were deleted under a retention policy, and where the surviving chain begins |\n")
	}
	b.WriteString("| `MANIFEST.json` | Every file with its SHA-256, and the state of the chain when it was exported |\n\n")

	b.WriteString("## Checking it\n\n")
	b.WriteString("Download the Flugschreiber binary and run:\n\n")
	b.WriteString("```\nflugschreiber verify --dir ./flugschreiber-evidence\n```\n\n")
	b.WriteString("It reads only these files. It needs no server, no network and no access to\n")
	b.WriteString("the system that produced the log. Exit status 0 means the chain is intact.\n\n")

	b.WriteString("Checking file digests independently:\n\n")
	b.WriteString("```\nsha256sum flugschreiber-evidence/seg-*.jsonl\n```\n\n")
	b.WriteString("and compare against `MANIFEST.json`.\n\n")

	if m.Checkpoints > 0 {
		b.WriteString("The public key is a standard PKIX Ed25519 key, readable with:\n\n")
		b.WriteString("```\nopenssl pkey -pubin -in flugschreiber-evidence/public-key.pem -text -noout\n```\n\n")
	}

	b.WriteString("## State at export\n\n")
	fmt.Fprintf(&b, "- Exported: %s\n", m.ExportedAt)
	fmt.Fprintf(&b, "- Records: %d (sequence %d to %d)\n", m.Records, m.FirstSeq, m.LastSeq)
	if m.FirstRecord != "" {
		fmt.Fprintf(&b, "- Window: %s to %s\n", m.FirstRecord, m.LastRecord)
	}
	fmt.Fprintf(&b, "- Chain head: `%s`\n", m.HeadHash)
	if m.ChainVerified {
		b.WriteString("- Verification at export: intact\n")
	} else {
		fmt.Fprintf(&b, "- Verification at export: **FAILED**, %d problem(s) recorded in MANIFEST.json\n", len(m.Problems))
	}
	if m.Pruned {
		b.WriteString("- This log has been pruned under a retention policy. It is unaltered since\n")
		b.WriteString("  that pruning, and it is not complete from the beginning. `pruned.json`\n")
		b.WriteString("  records what was removed.\n")
	}
	b.WriteString("\n")

	b.WriteString("## What this does and does not prove\n\n")
	b.WriteString("It proves that no record in this log has been altered, inserted or removed\n")
	b.WriteString("since it was written, because every record carries the hash of the one\n")
	b.WriteString("before it.\n\n")
	if m.Checkpoints > 0 {
		b.WriteString("The signed checkpoints additionally show that the chain head had a given\n")
		b.WriteString("value at a given time, attested by a key held by the operator. An attacker\n")
		b.WriteString("who rewrote the log but did not hold that key cannot produce checkpoints\n")
		b.WriteString("that match it.\n\n")
	} else {
		b.WriteString("This bundle contains no signed checkpoints, so the chain shows internal\n")
		b.WriteString("consistency only. It does not establish who wrote the log: anyone with\n")
		b.WriteString("write access to the whole directory could have recomputed it.\n\n")
	}
	b.WriteString("It does not prove that the log is complete. Traffic that never passed\n")
	b.WriteString("through the proxy was never recorded, and no property of this file can tell\n")
	b.WriteString("you whether that happened. Ask the operator what made the proxy\n")
	b.WriteString("unavoidable.\n\n")
	b.WriteString("It does not prove the upstream told the truth. The model name and token\n")
	b.WriteString("counts are as the model server reported them.\n\n")
	b.WriteString("This bundle is evidence and documentation input. It is not a statement\n")
	b.WriteString("about anyone's compliance with anything.\n")

	return b.String()
}
