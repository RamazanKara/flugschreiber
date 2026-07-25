package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CheckpointVersion is the version of the checkpoint record and of its
// signature preimage. A change to either is a version bump, because a verifier
// reconstructs the preimage from these bytes and cannot guess a new layout.
const CheckpointVersion = 1

// checkpointDomain separates checkpoint signatures from prune anchor
// signatures, so neither can be replayed as the other.
const checkpointDomain = "flugschreiber-checkpoint-v1"

// checkpointChainDomain separates the signature that binds a checkpoint to its
// predecessor from the one that covers the checkpoint's own claims.
const checkpointChainDomain = "flugschreiber-checkpoint-chain-v1"

// GenesisCheckpointHash is the prev_checkpoint_hash of the first checkpoint in
// a directory, mirroring GenesisHash in the record chain.
const GenesisCheckpointHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Checkpoint attests that at one moment the chain head was a given hash. The
// chain alone proves that a log is internally consistent; a checkpoint is what
// makes rewriting the whole log from the beginning detectable, because the
// attacker would also have to produce a signature.
//
// The last three fields chain the checkpoints to each other. Without them a
// signature says only "this head existed", which an attacker defeats by
// deleting the attestations rather than forging them: every remaining
// checkpoint still verifies, and nothing reveals the ones that went. Index and
// PrevCheckpointHash make a deletion visible, and ChainSignature is what stops
// an attacker simply renumbering what is left.
//
// They are carried outside the v1 signature on purpose. Signature still covers
// exactly the bytes CheckpointPreimage rendered before they existed, so a
// verifier built against schema version 1 validates it unchanged and ignores
// the rest. Folding them into that preimage would have made every checkpoint
// this version writes read as a forgery to every verifier already deployed,
// which is the one failure a tamper-evidence tool must never manufacture.
type Checkpoint struct {
	Version    int    `json:"version"`
	Segment    string `json:"segment"`
	Seq        uint64 `json:"seq"`
	RecordHash string `json:"record_hash"`
	Records    uint64 `json:"records"`
	Timestamp  string `json:"timestamp"`
	KeyID      string `json:"key_id"`
	Signature  string `json:"signature"`

	// Index counts checkpoints in this directory from zero. A gap in it is a
	// deletion.
	Index uint64 `json:"index"`

	// PrevCheckpointHash is CheckpointHash of the checkpoint before this one,
	// or GenesisCheckpointHash for the first.
	PrevCheckpointHash string `json:"prev_checkpoint_hash,omitempty"`

	// ChainSignature covers Index and PrevCheckpointHash together with this
	// checkpoint's own identity. Empty on checkpoints written before this
	// version, which verify under the v1 rule alone.
	ChainSignature string `json:"chain_signature,omitempty"`
}

// Chained reports whether this checkpoint carries the linkage fields. A
// directory written by an earlier version has none, and its checkpoints are
// still valid attestations of the heads they name.
func (c Checkpoint) Chained() bool { return c.ChainSignature != "" }

// CheckpointHash identifies one checkpoint for the purpose of linking the next
// one to it. It covers the signed claims and the signature over them, so a
// successor commits to both what its predecessor said and who said it.
//
// It is computed from the preimage rather than from the JSON line, for the same
// reason the record chain hashes the event as bytes: a reader must not have to
// reproduce a particular serialisation to check a link.
func CheckpointHash(c Checkpoint) string {
	var b bytes.Buffer
	b.Write(CheckpointPreimage(c))
	b.WriteString("signature:")
	b.WriteString(c.Signature)
	b.WriteString("\n")
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// CheckpointChainPreimage renders the bytes ChainSignature covers.
func CheckpointChainPreimage(c Checkpoint) []byte {
	var b bytes.Buffer
	b.WriteString(checkpointChainDomain)
	b.WriteString("\ncheckpoint:")
	b.WriteString(CheckpointHash(c))
	b.WriteString("\nindex:")
	b.WriteString(strconv.FormatUint(c.Index, 10))
	b.WriteString("\nprev_checkpoint_hash:")
	b.WriteString(c.PrevCheckpointHash)
	b.WriteString("\n")
	return b.Bytes()
}

// SignCheckpointChain adds the linkage signature, after the checkpoint's own
// signature is already in place. Index and PrevCheckpointHash must be set.
func SignCheckpointChain(s Signer, c *Checkpoint) error {
	if s == nil {
		return errors.New("evidence: sign checkpoint chain: no signer")
	}
	if c.Signature == "" {
		return fmt.Errorf("evidence: sign checkpoint chain at seq %d: the checkpoint is not signed yet", c.Seq)
	}
	if c.PrevCheckpointHash == "" {
		return fmt.Errorf("evidence: sign checkpoint chain at seq %d: no predecessor hash", c.Seq)
	}
	preimage := CheckpointChainPreimage(*c)
	sig, err := s.Sign(preimage)
	if err != nil {
		return fmt.Errorf("evidence: sign checkpoint chain at seq %d: %w", c.Seq, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("evidence: sign checkpoint chain at seq %d: signature is %d bytes, expected %d", c.Seq, len(sig), ed25519.SignatureSize)
	}
	c.ChainSignature = hex.EncodeToString(sig)
	return nil
}

// VerifyCheckpointChainSignature checks the linkage signature against pub.
func VerifyCheckpointChainSignature(pub ed25519.PublicKey, c Checkpoint) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("evidence: verify checkpoint chain: public key is %d bytes, expected %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := hex.DecodeString(c.ChainSignature)
	if err != nil {
		return fmt.Errorf("evidence: checkpoint at seq %d has a chain signature that is not hex: %w", c.Seq, err)
	}
	if !ed25519.Verify(pub, CheckpointChainPreimage(c), sig) {
		return fmt.Errorf(
			"evidence: the chain signature on the checkpoint at seq %d does not verify against key %s, so its position in the sequence is not attested",
			c.Seq, KeyID(pub))
	}
	return nil
}

// CheckpointPreimage renders the exact bytes a checkpoint signature covers.
// The layout is newline-delimited and domain-separated. Callers must reject a
// checkpoint whose fields carry a newline before signing or verifying it (see
// checkFieldSeparators); two different checkpoints could otherwise render the
// same bytes by shifting content across a field boundary.
//
// Signature is excluded from its own preimage.
func CheckpointPreimage(c Checkpoint) []byte {
	var b bytes.Buffer
	b.WriteString(checkpointDomain)
	b.WriteString("\nversion:")
	b.WriteString(strconv.Itoa(c.Version))
	b.WriteString("\nsegment:")
	b.WriteString(c.Segment)
	b.WriteString("\nseq:")
	b.WriteString(strconv.FormatUint(c.Seq, 10))
	b.WriteString("\nrecord_hash:")
	b.WriteString(c.RecordHash)
	b.WriteString("\nrecords:")
	b.WriteString(strconv.FormatUint(c.Records, 10))
	b.WriteString("\ntimestamp:")
	b.WriteString(c.Timestamp)
	b.WriteString("\nkey_id:")
	b.WriteString(c.KeyID)
	b.WriteString("\n")
	return b.Bytes()
}

// SignCheckpoint fills in KeyID and Signature. Version is defaulted here
// rather than at the call site so that the signature always covers the version
// that is written to disk.
func SignCheckpoint(priv ed25519.PrivateKey, keyID string, c *Checkpoint) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("evidence: sign checkpoint: key is %d bytes, expected %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return SignCheckpointWith(&KeyPairSigner{kp: &KeyPair{Private: priv, Public: pub, ID: keyID}}, c)
}

// SignCheckpointWith fills in KeyID and Signature using an arbitrary Signer,
// which is how an external key custodian signs without the private key ever
// being in this process.
//
// The signature it produces is checked against the signer's own public key
// before the checkpoint is returned. A helper that answers with the wrong
// bytes, or signs under a key other than the one it advertises, therefore
// fails here rather than at the next audit.
func SignCheckpointWith(s Signer, c *Checkpoint) error {
	if s == nil {
		return errors.New("evidence: sign checkpoint: no signer")
	}
	keyID := s.KeyID()
	if keyID == "" {
		return errors.New("evidence: sign checkpoint: key id is required, a signature nobody can attribute is not evidence")
	}
	if c.Version == 0 {
		c.Version = CheckpointVersion
	}
	c.KeyID = keyID
	if err := c.checkFieldSeparators(); err != nil {
		return err
	}

	preimage := CheckpointPreimage(*c)
	sig, err := s.Sign(preimage)
	if err != nil {
		return fmt.Errorf("evidence: sign checkpoint at seq %d: %w", c.Seq, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("evidence: sign checkpoint at seq %d: signature is %d bytes, expected %d", c.Seq, len(sig), ed25519.SignatureSize)
	}
	if pub := s.Public(); len(pub) == ed25519.PublicKeySize && !ed25519.Verify(pub, preimage, sig) {
		return fmt.Errorf(
			"evidence: sign checkpoint at seq %d: the signature does not verify against key %s, which the signer says produced it",
			c.Seq, keyID)
	}
	c.Signature = hex.EncodeToString(sig)
	return nil
}

// VerifyCheckpointSignature checks c against pub. It returns an error
// describing what failed rather than a bool, because every caller wants to
// report the reason.
func VerifyCheckpointSignature(pub ed25519.PublicKey, c Checkpoint) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("evidence: verify checkpoint: public key is %d bytes, expected %d", len(pub), ed25519.PublicKeySize)
	}
	if c.Signature == "" {
		return fmt.Errorf("evidence: checkpoint at seq %d carries no signature", c.Seq)
	}
	if err := c.checkFieldSeparators(); err != nil {
		return err
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("evidence: checkpoint at seq %d has a signature that is not hex: %w", c.Seq, err)
	}
	if !ed25519.Verify(pub, CheckpointPreimage(c), sig) {
		return fmt.Errorf("evidence: checkpoint at seq %d does not verify against key %s", c.Seq, KeyID(pub))
	}
	return nil
}

// checkFieldSeparators rejects a checkpoint that could render an ambiguous
// preimage. Nothing this package writes can contain a newline, so a value that
// does was placed there by hand or by an attacker trying to make one signature
// cover two different sets of claims.
func (c Checkpoint) checkFieldSeparators() error {
	for _, f := range []struct{ name, value string }{
		{"segment", c.Segment},
		{"record_hash", c.RecordHash},
		{"timestamp", c.Timestamp},
		{"key_id", c.KeyID},
		{"prev_checkpoint_hash", c.PrevCheckpointHash},
	} {
		if strings.ContainsAny(f.value, "\n\r") {
			return fmt.Errorf("evidence: checkpoint at seq %d has a %s containing a line break, which would make its signature cover ambiguous bytes", c.Seq, f.name)
		}
	}
	return nil
}

// AppendCheckpoint adds one checkpoint to checkpoints.jsonl. The file is only
// ever appended to, and each line is fsynced before the call returns: a
// checkpoint that is not on disk when the machine dies attests to nothing.
func AppendCheckpoint(dir string, c Checkpoint) error {
	line, err := json.Marshal(&c)
	if err != nil {
		return fmt.Errorf("evidence: marshal checkpoint: %w", err)
	}
	line = append(line, '\n')

	path := filepath.Join(dir, CheckpointsFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("evidence: open %s: %w", CheckpointsFile, err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("evidence: write checkpoint: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("evidence: fsync %s: %w", CheckpointsFile, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The first checkpoint also creates the file, and fsyncing a file does not
	// make the directory entry that names it durable. Without this, a machine
	// crash can leave a log whose checkpoints.jsonl was written and lost.
	syncDir(dir)
	return nil
}

// recoverCheckpointChain reads where the checkpoint chain left off, so that a
// restart continues it instead of starting a second one.
//
// A directory whose checkpoints predate the chain fields starts the chain at
// the current end: those checkpoints are still valid attestations, they simply
// carry no linkage, and refusing to run against them would strand every log
// written by an earlier version. What follows is chained, so a deletion after
// the upgrade is detectable even though one before it is not.
func (s *Store) recoverCheckpointChain() error {
	checks, err := ReadCheckpoints(s.opts.Dir)
	if err != nil {
		return err
	}
	if len(checks) == 0 {
		s.checkpointIndex = 0
		s.prevCheckpointHash = GenesisCheckpointHash
		return nil
	}
	last := checks[len(checks)-1]
	s.prevCheckpointHash = CheckpointHash(last)
	if last.Chained() {
		s.checkpointIndex = last.Index + 1
		return nil
	}
	// Unchained history: number the first chained checkpoint after the ones
	// already on disk, so the index still counts every checkpoint in the file
	// and a later reader can tell where chaining began.
	s.checkpointIndex = uint64(len(checks))
	return nil
}

// ReadCheckpoints returns every checkpoint in dir, in the order written. A
// missing file is not an error, because a log written before checkpoints
// existed, or by a build with no signing key, is still a valid log.
//
// A line that does not parse is an error rather than a skipped line. Everywhere
// else this package is a tolerant reader, but silently dropping an
// unrecognisable checkpoint would let an attacker delete an inconvenient
// attestation by corrupting it.
func ReadCheckpoints(dir string) ([]Checkpoint, error) {
	path := filepath.Join(dir, CheckpointsFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Checkpoint
	sc := newLineScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var c Checkpoint
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("evidence: %s:%d: %w", CheckpointsFile, sc.Line(), err)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", CheckpointsFile, err)
	}
	return out, nil
}
