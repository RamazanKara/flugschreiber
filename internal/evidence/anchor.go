package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// PruneAnchorVersion is the version of pruned.json and of its signature
// preimage.
const PruneAnchorVersion = 1

// pruneAnchorDomain separates prune anchor signatures from checkpoint
// signatures.
const pruneAnchorDomain = "flugschreiber-prune-anchor-v1"

// PruneAnchor records where a surviving chain legitimately begins after
// retention has deleted segments from the front. Without it a pruned log is
// indistinguishable from a log whose opening records were removed by an
// attacker, so the anchor is what keeps deletion honest rather than merely
// convenient.
type PruneAnchor struct {
	Version        int      `json:"version"`
	PrunedAt       string   `json:"pruned_at"`
	LastPrunedSeq  uint64   `json:"last_pruned_seq"`
	LastPrunedHash string   `json:"last_pruned_hash"`
	Segments       []string `json:"segments"`
	Records        uint64   `json:"records"`
	Reason         string   `json:"reason"`
	KeyID          string   `json:"key_id,omitempty"`
	Signature      string   `json:"signature,omitempty"`
}

// PruneAnchorPreimage renders the exact bytes a prune anchor signature covers.
// Reason is deliberately outside the signature: it is free-form operator prose
// and the fields that a verifier acts on are the sequence number, the hash and
// the segment list.
func PruneAnchorPreimage(a PruneAnchor) []byte {
	var b bytes.Buffer
	b.WriteString(pruneAnchorDomain)
	b.WriteString("\nversion:")
	b.WriteString(strconv.Itoa(a.Version))
	b.WriteString("\npruned_at:")
	b.WriteString(a.PrunedAt)
	b.WriteString("\nlast_pruned_seq:")
	b.WriteString(strconv.FormatUint(a.LastPrunedSeq, 10))
	b.WriteString("\nlast_pruned_hash:")
	b.WriteString(a.LastPrunedHash)
	b.WriteString("\nrecords:")
	b.WriteString(strconv.FormatUint(a.Records, 10))
	b.WriteString("\nsegments:")
	b.WriteString(strings.Join(a.Segments, ","))
	b.WriteString("\nkey_id:")
	b.WriteString(a.KeyID)
	b.WriteString("\n")
	return b.Bytes()
}

// SignPruneAnchor fills in KeyID and Signature.
func SignPruneAnchor(priv ed25519.PrivateKey, keyID string, a *PruneAnchor) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("evidence: sign prune anchor: key is %d bytes, expected %d", len(priv), ed25519.PrivateKeySize)
	}
	if keyID == "" {
		return errors.New("evidence: sign prune anchor: key id is required")
	}
	if a.Version == 0 {
		a.Version = PruneAnchorVersion
	}
	a.KeyID = keyID
	if err := a.checkFieldSeparators(); err != nil {
		return err
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(priv, PruneAnchorPreimage(*a)))
	return nil
}

// VerifyPruneAnchorSignature checks a against pub.
func VerifyPruneAnchorSignature(pub ed25519.PublicKey, a PruneAnchor) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("evidence: verify prune anchor: public key is %d bytes, expected %d", len(pub), ed25519.PublicKeySize)
	}
	if a.Signature == "" {
		return errors.New("evidence: prune anchor carries no signature")
	}
	if err := a.checkFieldSeparators(); err != nil {
		return err
	}
	sig, err := hex.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("evidence: prune anchor has a signature that is not hex: %w", err)
	}
	if !ed25519.Verify(pub, PruneAnchorPreimage(a), sig) {
		return fmt.Errorf("evidence: prune anchor does not verify against key %s", KeyID(pub))
	}
	return nil
}

// checkFieldSeparators rejects an anchor that could render an ambiguous
// preimage. The segment list is comma-joined and every field is newline
// terminated, so a name carrying either delimiter would let one signature cover
// two different segment lists.
func (a PruneAnchor) checkFieldSeparators() error {
	for _, f := range []struct{ name, value string }{
		{"pruned_at", a.PrunedAt},
		{"last_pruned_hash", a.LastPrunedHash},
		{"key_id", a.KeyID},
	} {
		if strings.ContainsAny(f.value, "\n\r") {
			return fmt.Errorf("evidence: prune anchor has a %s containing a line break, which would make its signature cover ambiguous bytes", f.name)
		}
	}
	for _, name := range a.Segments {
		if strings.ContainsAny(name, "\n\r,") {
			return fmt.Errorf("evidence: prune anchor names a segment %q containing a comma or a line break, which the signed segment list cannot represent unambiguously", name)
		}
	}
	return nil
}

// WritePruneAnchor replaces pruned.json atomically. A half-written anchor would
// make every surviving record unverifiable, so the new content is written to a
// temporary file in the same directory, fsynced, and then renamed over the old
// one. A reader sees either the previous anchor or the new one, never a prefix
// of either.
func WritePruneAnchor(dir string, a PruneAnchor) error {
	if a.Version == 0 {
		a.Version = PruneAnchorVersion
	}
	body, err := json.MarshalIndent(&a, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence: marshal prune anchor: %w", err)
	}
	body = append(body, '\n')
	if err := atomicWriteFile(filepath.Join(dir, PruneAnchorFile), body, 0o644); err != nil {
		return fmt.Errorf("evidence: write %s: %w", PruneAnchorFile, err)
	}
	return nil
}

// ReadPruneAnchor returns the anchor in dir, or nil when the log has never been
// pruned. Field-level validation is left to Verify, which can report a bad
// anchor as an integrity problem instead of failing to produce a report at all.
func ReadPruneAnchor(dir string) (*PruneAnchor, error) {
	raw, err := os.ReadFile(filepath.Join(dir, PruneAnchorFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var a PruneAnchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("evidence: parse %s: %w", PruneAnchorFile, err)
	}
	return &a, nil
}

// atomicWriteFile replaces path in one step. The temporary file is created in
// the destination directory so that the rename stays within one filesystem,
// where it is atomic.
func atomicWriteFile(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp makes the file 0600; widen it before the rename so that no
	// window exists where the published file has the wrong mode.
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory entry so that a rename or an unlink survives a
// machine crash. It is best effort: Windows refuses to open a directory for
// sync, and there the rename is still atomic, so a failure here weakens
// durability against power loss but never correctness of what is on disk.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
	if fn := syncDirObserver.Load(); fn != nil {
		(*fn)(dir)
	}
}

// syncDirObserver is nil outside tests. A directory fsync leaves nothing on
// disk to look for afterwards, so watching the call is the only way a test can
// hold this package to its durability claims. It is atomic so a future
// t.Parallel in this package cannot turn the hook into a data race.
var syncDirObserver atomic.Pointer[func(string)]
