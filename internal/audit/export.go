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
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
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

	// The content keystore opens every sealed prompt in the log. Handing over
	// the evidence and handing over the content are separate decisions, and an
	// export is only ever the first one. Its journal holds the same material
	// for keys that have not been folded in yet, so it is a secret on exactly
	// the same footing.
	evidence.ContentKeystoreFile: true,
	evidence.ContentJournalFile:  true,
}

// BundleManifest describes an evidence export so a recipient can tell whether
// what they received is what was sent.
type BundleManifest struct {
	Version int    `json:"version"`
	Tool    string `json:"tool"`

	// ToolVersion is the release that wrote the bundle. A recipient checking
	// this in 2031 needs to know which specification to read, and a manifest
	// that names only the tool leaves them guessing.
	ToolVersion string       `json:"tool_version"`
	ExportedAt  string       `json:"exported_at"`
	SourceDir   string       `json:"source_directory"`
	Files       []BundleFile `json:"files"`
	TotalBytes  int64        `json:"total_bytes"`

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

	// Timestamps counts the RFC 3161 anchors carried, RetiredKeys names the
	// keys rotation has replaced whose public halves travel with them. Both are
	// stated in the manifest so that a recipient can tell a bundle that carries
	// no anchors and no retired keys from one that lost them in transit.
	Timestamps  int      `json:"timestamps,omitempty"`
	RetiredKeys []string `json:"retired_keys,omitempty"`

	// SealedRecords counts records whose content is encrypted. The keys are not
	// in the bundle and never will be, so a recipient who is not told would
	// read the unreadable content as content that was never captured.
	SealedRecords int `json:"sealed_records,omitempty"`
}

// countSealed reports how many records carry encrypted content.
//
// A read error yields zero rather than failing the export: the count exists so
// that VERIFY.md can explain unreadable content, and a bundle that ships with
// one fewer sentence is better than an export that refuses to run. Verification
// of the chain itself has already happened and is what has to be exact.
func countSealed(dir string) int {
	var n int
	_ = evidence.Walk(dir, func(e evidence.Entry) error {
		if e.Event.Content != nil && e.Event.Content.Encryption != nil {
			n++
		}
		return nil
	})
	return n
}

// openStream returns a writer when the destination is a stream rather than a
// file to be replaced, and nil when it is an ordinary path.
//
// "-" is the conventional spelling. Anything that already exists and is not a
// regular file is the same case: a pipe, a device, /dev/stdout. Writing a temp
// file beside those and renaming over them would fail, and used to.
func openStream(out string) (io.WriteCloser, error) {
	if out == "-" {
		return nopCloser{os.Stdout}, nil
	}
	// The rule is deliberately mechanical rather than clever, because an
	// operator has to be able to predict which behaviour they get. /dev/stdout
	// is a symlink to /proc/self/fd/1, so a redirect to a file makes Stat
	// report a regular file and the atomic path then tried to create a
	// temporary beside it, in /dev, and failed.
	if out == os.DevNull || strings.HasPrefix(filepath.ToSlash(out), "/dev/") {
		f, err := os.OpenFile(out, os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("export: open %s: %w", out, err)
		}
		return f, nil
	}
	// A pipe, a socket or a device cannot be replaced by a rename, and nothing
	// is at risk of being destroyed by writing to one. Anything else, including
	// a path that does not exist yet or cannot be stat'ed, is an ordinary file
	// to create; a real problem with it surfaces when the bundle is written.
	const streamModes = os.ModeNamedPipe | os.ModeSocket | os.ModeCharDevice
	if info, err := os.Lstat(out); err == nil && info.Mode()&streamModes != 0 {
		f, openErr := os.OpenFile(out, os.O_WRONLY, 0o600)
		if openErr != nil {
			return nil, fmt.Errorf("export: open %s: %w", out, openErr)
		}
		return f, nil
	}
	return nil, nil
}

// nopCloser keeps stdout open after the bundle is written.
type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

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

	// ToolVersion is stamped into the manifest so a recipient knows which
	// specification the bundle was written against. It is passed in rather than
	// read here, because this package has no business knowing about build
	// identity and the architecture is easier to keep that way.
	ToolVersion string
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
// segments, the checkpoints and the anchors over them, every public key that
// may have signed one, a manifest, and instructions.
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
		ToolVersion:   opts.ToolVersion,
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
		RetiredKeys:   verified.RetiredKeys,
	}

	// Streaming to stdout or to a pipe is how a bundle leaves a distroless
	// container: the image has no shell and no tar, so kubectl cp cannot work
	// and kubectl exec with a redirect is the only way out. The rename dance
	// below is skipped in that case, because its whole purpose is to protect a
	// file that is already at the destination and a stream has none.
	if streamed, err := openStream(opts.Out); err != nil {
		return nil, err
	} else if streamed != nil {
		defer streamed.Close()
		if err := writeArchive(streamed, opts, files, &manifest, now); err != nil {
			return nil, err
		}
		return &ExportResult{Path: opts.Out, Manifest: manifest}, nil
	}

	outDir := filepath.Dir(opts.Out)
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, err
	}
	// The bundle is built beside its destination and moved into place only once
	// it is whole. Writing straight to opts.Out would truncate whatever is
	// already there before the first byte of the replacement is read, so an
	// export that fails part way, on an unreadable segment or a full disk,
	// would destroy the bundle the operator already had and leave a fragment
	// under the name they are about to hand over. A truncated .tar.gz reads as
	// a whole one until somebody opens it, which may be somewhere it matters.
	out, err := os.CreateTemp(outDir, ".flugschreiber-bundle-*")
	if err != nil {
		return nil, err
	}
	tmpName := out.Name()
	defer func() {
		_ = out.Close()
		// A no-op once the rename below has moved the file into place.
		_ = os.Remove(tmpName)
	}()

	if err := writeArchive(out, opts, files, &manifest, now); err != nil {
		return nil, err
	}
	if err := out.Sync(); err != nil {
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	// CreateTemp opens at 0600. The bundle carries no secret, and an operator
	// who has to hand it to an auditor should not have to widen it by hand.
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, opts.Out); err != nil {
		return nil, err
	}

	return &ExportResult{Path: opts.Out, Manifest: manifest}, nil
}

// collect lists the files that belong in a bundle, in a stable order, and
// refuses outright if a secret would be included.
//
// The list has to cover everything a recipient needs to check the chain end to
// end with no access to this host, which is more than the current key: after a
// rotation the log holds checkpoints signed under keys that are no longer in
// force, and a bundle carrying those checkpoints without the keys they were
// signed with cannot be verified by the third party it was made for. The
// retired public keys and the RFC 3161 anchors therefore travel with the
// segments.
//
// Names are returned relative to dir and slash separated, because they are also
// paths inside the tar archive.
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
		case name == evidence.CheckpointsFile, name == evidence.TimestampsFile,
			name == evidence.PublicKeyFile, name == evidence.PruneAnchorFile,
			name == evidence.LegalHoldFile:
			extras = append(extras, name)
		}
	}

	// An unreadable keys/ is an error rather than an omission: a bundle that is
	// silently missing a key is one that fails verification in somebody else's
	// hands, weeks later, with no way to tell why.
	retired, err := evidence.RetiredKeyFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}

	sortStrings(segments)
	sortStrings(extras)
	sortStrings(retired)
	out := make([]string, 0, len(segments)+len(extras)+len(retired))
	out = append(out, segments...)
	out = append(out, extras...)
	out = append(out, retired...)

	for _, name := range out {
		if secretFiles[path.Base(name)] {
			return nil, fmt.Errorf("export: refusing to bundle %s, which must never leave the host", name)
		}
		if err := refusePrivateKeyMaterial(dir, name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// refusePrivateKeyMaterial refuses a PEM file that announces a private key.
//
// The names under keys/ are written by rotation and hold public keys only, so
// this fires when somebody has put a private key there by hand, or copied a
// directory in a way that moved one. It is checked by content rather than by
// name because the cost of being wrong once is a signing key in a third party's
// hands, and there is no taking that back.
//
// It matches the PEM header as text rather than decoding the block. A file
// whose body is damaged does not decode, and "this build could not parse it" is
// not a reason to ship a key.
func refusePrivateKeyMaterial(dir, name string) error {
	if path.Ext(name) != ".pem" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN ") && strings.Contains(line, "PRIVATE") {
			return fmt.Errorf(
				"export: refusing to bundle %s, which holds %q; private key material must never leave the host",
				name, line)
		}
	}
	return nil
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
	if n := len(m.RetiredKeys); n > 0 {
		fmt.Fprintf(&b, "| `keys/retired-*.pem` | %d public key(s) a rotation replaced. Checkpoints signed before that rotation verify against these and against nothing else |\n", n)
	}
	if m.Timestamps > 0 {
		b.WriteString("| `timestamps.jsonl` | RFC 3161 tokens from a timestamping authority, one per anchored checkpoint |\n")
	}
	if m.Pruned {
		b.WriteString("| `pruned.json` | Records which segments were deleted under a retention policy, and where the surviving chain begins |\n")
	}
	b.WriteString("| `MANIFEST.json` | Every file with its SHA-256, and the state of the chain when it was exported |\n\n")

	b.WriteString("## Checking it\n\n")
	b.WriteString("You do not need the tool that produced this, and an auditor should not\n")
	b.WriteString("want it: software supplied by the party under audit is not what you\n")
	b.WriteString("validate their evidence with. The construction is specified below and is\n")
	b.WriteString("reimplementable in an afternoon in any language with SHA-256 and Ed25519.\n\n")
	b.WriteString("### The record chain\n\n")
	b.WriteString("Each line of a `seg-*.jsonl` file is one record. For each, in order:\n\n")
	b.WriteString("```\n")
	b.WriteString("preimage = \"flugschreiber-record-v1\\n\"\n")
	b.WriteString("         + \"seq:\"   + decimal(seq)             + \"\\n\"\n")
	b.WriteString("         + \"ts:\"    + timestamp                + \"\\n\"\n")
	b.WriteString("         + \"prev:\"  + prev_hash                + \"\\n\"\n")
	b.WriteString("         + \"event:\" + hex(sha256(event_bytes)) + \"\\n\"\n")
	b.WriteString("\n")
	b.WriteString("record_hash == hex(sha256(preimage))\n")
	b.WriteString("```\n\n")
	b.WriteString("`event_bytes` is the exact byte span the `event` member occupies in the\n")
	b.WriteString("line, taken from the file as it is. Do not parse it and print it again:\n")
	b.WriteString("the writer escapes `<`, `>` and `&` as `\\u003c` and friends, so a reader\n")
	b.WriteString("that re-serialises computes a different digest and will report tampering\n")
	b.WriteString("on ordinary traffic. Go has `json.RawMessage`, Rust's serde has\n")
	b.WriteString("`&RawValue`, and a byte scan for the member with a brace-matching walk is\n")
	b.WriteString("a dozen lines and exact.\n\n")
	b.WriteString("`prev_hash` of the first record is 64 zeros unless `pruned.json` is here,\n")
	b.WriteString("in which case it is the hash that file records. Every later record's\n")
	b.WriteString("`prev_hash` is its predecessor's `record_hash`, and `seq` is contiguous.\n\n")
	b.WriteString("### The checkpoint signatures\n\n")
	b.WriteString("Each line of `checkpoints.jsonl` is signed with Ed25519 over:\n\n")
	b.WriteString("```\n")
	b.WriteString("\"flugschreiber-checkpoint-v1\\n\"\n")
	b.WriteString("+ \"version:\"     + decimal(version)     + \"\\n\"\n")
	b.WriteString("+ \"segment:\"     + segment              + \"\\n\"\n")
	b.WriteString("+ \"seq:\"         + decimal(seq)         + \"\\n\"\n")
	b.WriteString("+ \"record_hash:\" + record_hash          + \"\\n\"\n")
	b.WriteString("+ \"records:\"     + decimal(records)     + \"\\n\"\n")
	b.WriteString("+ \"timestamp:\"   + timestamp            + \"\\n\"\n")
	b.WriteString("+ \"key_id:\"      + key_id               + \"\\n\"\n")
	b.WriteString("```\n\n")
	b.WriteString("The signature is hex in `signature`, the key is the PKIX file named by\n")
	b.WriteString("`key_id`, and `record_hash` must equal the hash of the record at that\n")
	b.WriteString("`seq`. A checkpoint that verifies but names a hash the log does not hold\n")
	b.WriteString("is the signature of a rewrite and matters more than one that fails.\n\n")
	b.WriteString("If you would rather use the tool, it is Apache-2.0 at\n")
	b.WriteString("https://github.com/RamazanKara/flugschreiber and reads only these files:\n\n")
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
	if len(m.RetiredKeys) > 0 {
		b.WriteString("The keys under `keys/` were retired by a rotation and are in the same\n")
		b.WriteString("format. Every checkpoint names the key that signed it in its `key_id`\n")
		b.WriteString("field, and a retired key is filed as `keys/retired-<key_id>.pem`, so a\n")
		b.WriteString("checkpoint written before a rotation is checked against the file carrying\n")
		b.WriteString("its id. This bundle carries the retired key(s):\n\n")
		fmt.Fprintf(&b, "```\n%s\n```\n\n", strings.Join(m.RetiredKeys, "\n"))
	}
	if m.Timestamps > 0 {
		b.WriteString("Each line of `timestamps.jsonl` carries an RFC 3161 token in\n")
		b.WriteString("`token_base64`, covering the `record_hash` of the checkpoint at that\n")
		b.WriteString("sequence number. `verify` checks that the token covers that hash. It does\n")
		b.WriteString("not check who issued the token, because that needs a trust store and a\n")
		b.WriteString("decision about which authorities you accept, both of which are yours to\n")
		b.WriteString("make. Once the token is base64-decoded to a file, openssl settles it:\n\n")
		b.WriteString("```\nopenssl ts -verify -in token.tst -token_in -CAfile your-tsa-ca.pem -digest <record_hash>\n```\n\n")
	}

	b.WriteString("## State at export\n\n")
	fmt.Fprintf(&b, "- Produced by: %s %s\n", m.Tool, m.ToolVersion)
	fmt.Fprintf(&b, "- Exported: %s\n", m.ExportedAt)
	fmt.Fprintf(&b, "- Records: %d (sequence %d to %d)\n", m.Records, m.FirstSeq, m.LastSeq)
	if m.FirstRecord != "" {
		fmt.Fprintf(&b, "- Window: %s to %s\n", m.FirstRecord, m.LastRecord)
	}
	fmt.Fprintf(&b, "- Chain head: `%s`\n", m.HeadHash)
	if len(m.RetiredKeys) > 0 {
		fmt.Fprintf(&b, "- Retired signing keys carried: %d\n", len(m.RetiredKeys))
	}
	if m.Timestamps > 0 {
		fmt.Fprintf(&b, "- Timestamp anchors: %d\n", m.Timestamps)
	}
	if m.SealedRecords > 0 {
		fmt.Fprintf(&b, "- Records with encrypted content: %d\n", m.SealedRecords)
	}
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
		if m.Timestamps > 0 {
			b.WriteString("The timestamp anchors move the time on the checkpoints they cover from\n")
			b.WriteString("the operator's claim to a third party's, as far as you trust the\n")
			b.WriteString("authority that issued them. They say nothing about the records between\n")
			b.WriteString("two anchored checkpoints beyond what the chain already says.\n\n")
		}
	} else {
		b.WriteString("This bundle contains no signed checkpoints, so the chain shows internal\n")
		b.WriteString("consistency only. It does not establish who wrote the log: anyone with\n")
		b.WriteString("write access to the whole directory could have recomputed it.\n\n")
	}
	if m.SealedRecords > 0 {
		fmt.Fprintf(&b, "%d record(s) here carry their prompts and completions encrypted, and the\n", m.SealedRecords)
		b.WriteString("keys that open them are not in this bundle and will not be: handing over\n")
		b.WriteString("the evidence and handing over the content are separate decisions, and this\n")
		b.WriteString("is the first one. Do not read the absent text as content that was never\n")
		b.WriteString("captured. Everything above about the chain holds regardless, because the\n")
		b.WriteString("`sha256` of each request and response is taken over the bytes that crossed\n")
		b.WriteString("the wire, before any encryption. Ask the operator if you need the text.\n\n")
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

// writeArchive streams the bundle into w and fills in the manifest.
func writeArchive(w io.Writer, opts ExportOptions, files []string, manifest *BundleManifest, now func() time.Time) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	const root = "flugschreiber-evidence"

	// A bundle name is a path inside a tar archive and stays slash separated on
	// every platform, so it is built with path.Join while the file it is read
	// from is built with filepath.Join.
	for _, name := range files {
		src := filepath.Join(opts.Dir, filepath.FromSlash(name))
		info, err := os.Stat(src)
		if err != nil {
			return err
		}
		digest, err := fileDigest(src)
		if err != nil {
			return err
		}
		if err := writeFileEntry(tw, path.Join(root, name), src, info); err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, BundleFile{
			Name: name, Bytes: info.Size(), SHA256: digest,
		})
		manifest.TotalBytes += info.Size()
		if name == evidence.CheckpointsFile {
			manifest.Checkpoints = countLines(src)
		}
		if name == evidence.TimestampsFile {
			manifest.Timestamps = countLines(src)
		}
		if name == evidence.PruneAnchorFile {
			manifest.Pruned = true
		}
	}
	manifest.SealedRecords = countSealed(opts.Dir)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestJSON = append(manifestJSON, '\n')
	if err := writeBytesEntry(tw, path.Join(root, "MANIFEST.json"), manifestJSON, now()); err != nil {
		return err
	}

	instructions := []byte(verifyInstructions(*manifest, opts.Note))
	if err := writeBytesEntry(tw, path.Join(root, "VERIFY.md"), instructions, now()); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return nil
}
