// Package archivecheck answers whether an archive holds what the local
// evidence directory says it should. It sits above both sides and reads
// through them: internal/evidence for what ought to exist, internal/archive
// for what does. Neither of those packages knows this one exists, so the
// verifier's import graph stays free of SigV4 and the byte movers stay free
// of chain knowledge. The archive-verify command in internal/cli is flags and
// printing over this.
package archivecheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/archive"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Reader is the read half of an archive backend. Verification never
// writes, so it takes the two methods it needs and not the Archiver the store
// depends on; both backends satisfy it structurally.
type Reader interface {
	Exists(ctx context.Context, key string) (bool, error)
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Name() string
	Target() string
}

// What one probe found. "unknown" is a distinct outcome from "missing" on
// purpose: a backend that will not answer has told us nothing, and reporting
// silence as absence would invent a gap, while reporting it as presence would
// invent assurance.
const (
	StatusPresent  = "present"
	StatusMissing  = "missing"
	StatusMismatch = "mismatch"
	StatusUnknown  = "unknown"
)

// The parts of an evidence directory that reach an archive at all.
const (
	KindSealedSegment = "sealed_segment"
	KindPrunedSegment = "pruned_segment"
	KindOpenSegment   = "open_segment"
	KindPublicKey     = "public_key"
	KindRetiredKey    = "retired_key"
	KindCheckpoints   = "checkpoints"
)

// maxKeyPEMBytes bounds what is read back for a key comparison. A PEM public
// key is a few hundred bytes; the cap is what keeps a misconfigured bucket
// from streaming a segment into memory in its place.
const maxKeyPEMBytes = 64 << 10

// Object is one key the archive was asked about.
type Object struct {
	Key    string `json:"key"`
	Kind   string `json:"kind"`
	Local  string `json:"local_file,omitempty"`
	Status string `json:"status"`

	// Required marks an object whose absence is a gap in the archive. The
	// snapshots are not: the store writes one per run rather than one per
	// checkpoint, so most of the keys that could exist never do. Nor is a
	// retired public key, which reaches the archive on the next run after the
	// rotation rather than during it.
	Required bool `json:"required"`

	// Bytes is how much was read back and compared, and is zero unless --deep
	// was given.
	Bytes  int64  `json:"bytes_compared,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// VerifyResult is what one run checked, and what it could not.
type VerifyResult struct {
	Dir     string `json:"dir"`
	Backend string `json:"backend"`
	Target  string `json:"target"`
	Prefix  string `json:"prefix,omitempty"`
	Deep    bool   `json:"deep"`

	Objects []Object `json:"objects,omitempty"`

	Probed        int   `json:"probed"`
	Present       int   `json:"present"`
	Missing       int   `json:"missing"`
	Mismatched    int   `json:"mismatched"`
	Unknown       int   `json:"unknown"`
	BytesCompared int64 `json:"bytes_compared,omitempty"`

	// CheckpointHeads counts the attested heads in the local checkpoint file
	// and CheckpointSnapshots how many of them the archive holds a snapshot
	// for. The second is expected to be much smaller than the first.
	CheckpointHeads     int `json:"checkpoint_heads"`
	CheckpointSnapshots int `json:"checkpoint_snapshots"`

	// OpenSnapshots counts the snapshots of a segment that was still being
	// written when a run shut down. One per clean shutdown is the expectation,
	// not one per head.
	OpenSnapshots int `json:"open_snapshots"`

	// NotChecked states, in plain sentences, which parts of a full
	// verification this run could not perform. It is populated on every run,
	// including a clean one, because the value of this command depends on
	// nobody reading it as more than it is.
	NotChecked []string `json:"not_checked"`
	Notes      []string `json:"notes,omitempty"`
}

// OK reports whether every required object was found and matched. An object
// that could not be checked leaves the run not OK: a check that did not happen
// is not a check that passed.
func (r *VerifyResult) OK() bool {
	return r.Missing == 0 && r.Mismatched == 0 && r.Unknown == 0
}

// Verify derives the keys the store would have written from what the
// local directory holds, and asks the archive about each of them.
//
// Deriving rather than listing is not a shortcut: neither backend offers a
// listing, and an archive is checked against the evidence it was made from, so
// the local directory is the authority on what should be there. The cost is
// that an object the local directory does not name cannot be seen from here,
// which the result says out loud.
func Verify(ctx context.Context, ar Reader, dir, prefix string, deep bool) (*VerifyResult, error) {
	res := &VerifyResult{
		Dir:     dir,
		Backend: ar.Name(),
		Target:  ar.Target(),
		Prefix:  prefix,
		Deep:    deep,
	}
	v := &probe{ctx: ctx, ar: ar, deep: deep, res: res}

	segs, err := evidence.Segments(dir)
	if err != nil {
		return nil, fmt.Errorf("archive-verify: read %s: %w", dir, err)
	}
	// local is what a snapshot key may be built for, keyed by the name a
	// checkpoint uses for its segment.
	local := map[string]string{}
	for _, seg := range segs {
		local[filepath.Base(seg.Path)] = seg.Path
	}
	// The newest segment is the one a store appends to. It is sealed only when
	// the next one is created, and until then the archive holds it only as the
	// shutdown snapshot checkOpenSnapshots looks for.
	sealed := segs
	if len(sealed) > 0 {
		sealed = sealed[:len(sealed)-1]
	}
	for _, seg := range sealed {
		name := filepath.Base(seg.Path)
		v.check(Object{
			Key:      archive.JoinKey(prefix, name),
			Kind:     KindSealedSegment,
			Local:    seg.Path,
			Required: true,
		})
	}

	anchor, err := evidence.ReadPruneAnchor(dir)
	if err != nil {
		return nil, fmt.Errorf("archive-verify: %w", err)
	}
	if anchor != nil {
		for _, name := range anchor.Segments {
			// Retention deleted the local copy, so presence is the whole of
			// what can be established about these: there is nothing left here
			// to compare the bytes against.
			v.check(Object{
				Key:      archive.JoinKey(prefix, name),
				Kind:     KindPrunedSegment,
				Required: true,
				Detail:   "retention deleted the local copy, so what the archive holds is the only copy there is",
			})
		}
		res.NotChecked = append(res.NotChecked, fmt.Sprintf(
			"the contents of the %d segment(s) %s says retention deleted: nothing local remains to compare them against",
			len(anchor.Segments), evidence.PruneAnchorFile))
	}

	keyPath := filepath.Join(dir, evidence.PublicKeyFile)
	if _, err := os.Stat(keyPath); err == nil {
		v.checkPublicKey(dir, archive.JoinKey(prefix, evidence.PublicKeyFile), keyPath)
	}
	if err := v.checkRetiredKeys(dir, prefix); err != nil {
		return nil, err
	}

	checkpoints, err := evidence.ReadCheckpoints(dir)
	if err != nil {
		return nil, fmt.Errorf("archive-verify: %w", err)
	}
	v.checkCheckpoints(dir, prefix, checkpoints)
	snapshotted := v.checkOpenSnapshots(prefix, checkpoints, local)
	if len(segs) > 0 {
		if newest := filepath.Base(segs[len(segs)-1].Path); !snapshotted[newest] {
			res.NotChecked = append(res.NotChecked, fmt.Sprintf(
				"the segment still being written, %s: the archive holds no snapshot of it under any head the checkpoints attest to, which is what an archive looks like until a run shuts down cleanly while writing to that segment",
				newest))
		}
	}

	res.NotChecked = append(res.NotChecked,
		"whether the archive holds anything the local directory does not name: object stores are asked about keys here, never listed",
		"the chain in the archived segments: this command compares objects, it does not verify records; run flugschreiber verify against this directory, or against a copy restored from the archive")
	if _, err := os.Stat(filepath.Join(dir, evidence.TimestampsFile)); err == nil {
		res.NotChecked = append(res.NotChecked, fmt.Sprintf(
			"the archived copies of %s: the store keys them by the head the writer held when it uploaded them, which after an unclean shutdown is a sequence no checkpoint attests to, so the key cannot be derived from this directory",
			evidence.TimestampsFile))
	}
	if !deep {
		res.NotChecked = append(res.NotChecked,
			"what is inside the archived objects: this run asked only whether each key exists, so it proves the archive has something under that name and nothing about its contents; pass --deep to compare the bytes")
	}
	res.Notes = append(res.Notes,
		fmt.Sprintf("the store uploads sealed segments, snapshots of the open segment, checkpoint snapshots, the anchors in %s, %s and every retired public key. %s and %s stay on this host, so a copy restored from the archive is not by itself a complete evidence directory",
			evidence.TimestampsFile, evidence.PublicKeyFile, evidence.PruneAnchorFile, evidence.LegalHoldFile))
	return res, nil
}

// probe carries the state one run of checks shares.
type probe struct {
	ctx  context.Context
	ar   Reader
	deep bool
	res  *VerifyResult
}

// check probes one key and records the outcome.
func (p *probe) check(o Object) {
	if p.deep && o.Local != "" {
		p.compare(&o)
	} else {
		p.exists(&o)
	}
	p.record(o)
}

func (p *probe) exists(o *Object) {
	switch present, err := p.ar.Exists(p.ctx, o.Key); {
	case err != nil:
		o.Status = StatusUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the %s backend did not answer: %v", p.ar.Name(), err))
	case present:
		o.Status = StatusPresent
	default:
		o.Status = StatusMissing
	}
}

// compare reads the object back and holds it against the local file.
func (p *probe) compare(o *Object) {
	body, err := p.ar.Get(p.ctx, o.Key)
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			o.Status = StatusMissing
			return
		}
		o.Status = StatusUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the %s backend did not answer: %v", p.ar.Name(), err))
		return
	}
	defer body.Close()

	local, err := os.Open(o.Local)
	if err != nil {
		o.Status = StatusUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the local copy could not be read: %v", err))
		return
	}
	defer local.Close()

	rel, n, err := compareArchived(local, body)
	o.Bytes = n
	switch {
	case err != nil:
		o.Status = StatusUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the comparison stopped after %d bytes: %v", n, err))
	case rel == bytesIdentical:
		o.Status = StatusPresent
	case rel == bytesPrefix && o.Kind == KindCheckpoints:
		// The checkpoint file grows; what the archive holds is the snapshot the
		// key names, so being a prefix of the local file is what agreement
		// looks like here.
		o.Status = StatusPresent
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the snapshot is the first %d bytes of the current %s and agrees with them", n, evidence.CheckpointsFile))
	case rel == bytesPrefix && o.Kind == KindOpenSegment:
		// Same for a segment that was still open: the key names the head the
		// snapshot covers, and a later run appended past it.
		o.Status = StatusPresent
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the snapshot is the first %d bytes of %s and agrees with them", n, filepath.Base(o.Local)))
	case rel == bytesPrefix:
		o.Status = StatusMismatch
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the archived object stops after %d bytes and the local file continues", n))
	case rel == bytesLonger:
		o.Status = StatusMismatch
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the archived object carries bytes past the end of the local file at offset %d", n))
	default:
		o.Status = StatusMismatch
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the two disagree from byte %d", n))
	}
}

// checkPublicKey compares the archived key against every key this directory
// still accepts, not only the current one.
//
// The store uploads public-key.pem once and skips a key that is already there,
// so after a rotation the archive keeps the key it first saw. That is expected
// and it is not a mismatch: the archived checkpoints were signed under it. What
// would be a finding is a key this directory has no record of at all.
func (p *probe) checkPublicKey(dir, key, localPath string) {
	o := Object{Key: key, Kind: KindPublicKey, Local: localPath, Required: true}
	if !p.deep {
		p.exists(&o)
		p.record(o)
		return
	}

	body, err := p.ar.Get(p.ctx, key)
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			o.Status = StatusMissing
		} else {
			o.Status = StatusUnknown
			o.Detail = fmt.Sprintf("the %s backend did not answer: %v", p.ar.Name(), err)
		}
		p.record(o)
		return
	}
	defer body.Close()

	archived, err := io.ReadAll(io.LimitReader(body, maxKeyPEMBytes))
	if err != nil {
		o.Status = StatusUnknown
		o.Detail = fmt.Sprintf("the archived key could not be read: %v", err)
		p.record(o)
		return
	}
	o.Bytes = int64(len(archived))

	local, err := os.ReadFile(localPath)
	if err != nil {
		o.Status = StatusUnknown
		o.Detail = fmt.Sprintf("the local %s could not be read, so there is nothing to compare against: %v", evidence.PublicKeyFile, err)
		p.record(o)
		return
	}
	if bytes.Equal(local, archived) {
		o.Status = StatusPresent
		p.record(o)
		return
	}

	retired, matchErr := matchRetiredKey(dir, archived)
	switch {
	case matchErr != nil:
		o.Status = StatusUnknown
		o.Detail = fmt.Sprintf("the archived key differs from %s and the retired keys could not be read: %v", evidence.PublicKeyFile, matchErr)
	case retired != "":
		o.Status = StatusPresent
		o.Detail = fmt.Sprintf(
			"this object holds the key this directory retired to %s; the store uploads the public key once, so a rotation since then is not reflected in it",
			retired)
	default:
		o.Status = StatusMismatch
		o.Detail = fmt.Sprintf(
			"the archived key is neither the current %s nor any key in %s/; nothing here accounts for it",
			evidence.PublicKeyFile, evidence.RetiredKeysDir)
	}
	p.record(o)
}

// checkRetiredKeys probes the public half of every key a rotation has retired.
//
// The store uploads them beside the key in force, because a reader who holds
// only the bucket cannot check a checkpoint signed before a rotation without
// them. They are not required: a rotation is followed by an upload the next
// time a run starts, so between the two the archive legitimately lacks the
// newest one. Absence is therefore reported as a note naming the key rather
// than as a gap, and a copy that differs from the local one is a finding,
// because a retired key is written once and never changes again.
func (p *probe) checkRetiredKeys(dir, prefix string) error {
	files, err := evidence.RetiredKeyFiles(dir)
	if err != nil {
		return fmt.Errorf("archive-verify: %w", err)
	}
	for _, name := range files {
		o := Object{
			Key:   archive.JoinKey(prefix, name),
			Kind:  KindRetiredKey,
			Local: filepath.Join(dir, filepath.FromSlash(name)),
		}
		if p.deep {
			p.compare(&o)
		} else {
			p.exists(&o)
		}
		if o.Status == StatusMissing {
			p.res.Probed++
			p.res.Notes = append(p.res.Notes, fmt.Sprintf(
				"the archive holds no %s, so a checkpoint in it that was signed before that rotation cannot be checked from the archive alone; the next run of the server uploads it, or copy the file into the archive under that key",
				name))
			continue
		}
		p.record(o)
	}
	return nil
}

// checkOpenSnapshots probes the shutdown snapshot of a segment that was still
// being written.
//
// The key carries the segment and the head sequence the writer had when it
// stopped, and checkpoints.jsonl names both: shutdown appends a checkpoint for
// that segment at that head and queues the snapshot immediately afterwards. So
// every pair a checkpoint names is a key the archive may hold, and the object
// carrying the newest evidence there is stops being invisible from here.
//
// A snapshot exists only where a run shut down cleanly with something in the
// open segment, so most candidates are absent and none is required. A present
// one is compared as a prefix of the local segment, because a later run went on
// appending to the file the snapshot was taken from.
func (p *probe) checkOpenSnapshots(prefix string, checkpoints []evidence.Checkpoint, local map[string]string) map[string]bool {
	found := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range checkpoints {
		// A checkpoint names a segment as a bare file name. Anything that is
		// not a segment this directory still holds is skipped rather than
		// turned into a key or a path: there would be nothing to compare it
		// against, and a checkpoint file is not a source of path components.
		path, ok := local[c.Segment]
		if !ok || c.Seq == 0 {
			continue
		}
		key := openSegmentSnapshotKey(c.Segment, c.Seq)
		if seen[key] {
			continue
		}
		seen[key] = true

		o := Object{Key: archive.JoinKey(prefix, key), Kind: KindOpenSegment, Local: path}
		if p.deep {
			p.compare(&o)
		} else {
			p.exists(&o)
		}
		if o.Status == StatusMissing {
			p.res.Probed++
			continue
		}
		if o.Status == StatusPresent {
			p.res.OpenSnapshots++
			found[c.Segment] = true
		}
		p.record(o)
	}
	return found
}

// checkCheckpoints probes the snapshot key of every attested head.
//
// A snapshot is uploaded when a run starts and when one shuts down, not once
// per checkpoint, so most of these keys are legitimately absent and none of
// them is required. What the count answers is the question that matters: does
// the archive hold anything at all that attests to the segments in it.
func (p *probe) checkCheckpoints(dir, prefix string, checkpoints []evidence.Checkpoint) {
	p.res.CheckpointHeads = len(checkpoints)
	localPath := filepath.Join(dir, evidence.CheckpointsFile)

	seen := map[uint64]bool{}
	for _, c := range checkpoints {
		if seen[c.Seq] {
			continue
		}
		seen[c.Seq] = true

		o := Object{Key: archive.JoinKey(prefix, checkpointSnapshotKey(c.Seq)), Kind: KindCheckpoints, Local: localPath}
		if p.deep {
			p.compare(&o)
		} else {
			p.exists(&o)
		}
		// An absent snapshot is the ordinary case. It is counted as probed and
		// left out of the object list, which would otherwise carry one line
		// per checkpoint saying nothing.
		if o.Status == StatusMissing {
			p.res.Probed++
			continue
		}
		if o.Status == StatusPresent {
			p.res.CheckpointSnapshots++
		}
		p.record(o)
	}

	if len(checkpoints) > 0 && p.res.CheckpointSnapshots == 0 {
		// Under none of the keys the attested heads name, which is as far as
		// this can be put: a run that started after an unclean shutdown files
		// its snapshot under the head it recovered, and that head is one no
		// checkpoint attests to.
		p.res.Notes = append(p.res.Notes, fmt.Sprintf(
			"the archive holds no %s under any key the %d attested head(s) name, so as far as this run can tell nothing in it attests to the segments it holds; a snapshot is uploaded when a run starts and when one shuts down cleanly",
			evidence.CheckpointsFile, len(checkpoints)))
	}
}

func (p *probe) record(o Object) {
	p.res.Probed++
	p.res.BytesCompared += o.Bytes
	switch o.Status {
	case StatusPresent:
		p.res.Present++
	case StatusMissing:
		p.res.Missing++
	case StatusMismatch:
		p.res.Mismatched++
	case StatusUnknown:
		p.res.Unknown++
	}
	p.res.Objects = append(p.res.Objects, o)
}

// checkpointSnapshotKey and openSegmentSnapshotKey render the keys the store
// files its two kinds of snapshot under.
//
// Both layouts are the ones internal/evidence writes, in archiveCheckpoints and
// archiveOpenSegment, which are unexported there. They are duplicated rather
// than imported, and the tests that cover this command drive a real store
// against a real backend so that the two cannot drift apart without failing the
// build.
func checkpointSnapshotKey(seq uint64) string {
	return fmt.Sprintf("checkpoints/checkpoints.seq-%012d.jsonl", seq)
}

func openSegmentSnapshotKey(segment string, seq uint64) string {
	return fmt.Sprintf("open/%s.seq-%012d.jsonl", strings.TrimSuffix(segment, ".jsonl"), seq)
}

// matchRetiredKey returns the retired key file holding exactly these bytes, or
// the empty string when none does.
func matchRetiredKey(dir string, pem []byte) (string, error) {
	files, err := evidence.RetiredKeyFiles(dir)
	if err != nil {
		return "", err
	}
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return "", err
		}
		if bytes.Equal(body, pem) {
			return name, nil
		}
	}
	return "", nil
}

// byteRelation is how an archived object stands to the local file it was made
// from.
type byteRelation string

const (
	bytesIdentical byteRelation = "identical"
	bytesPrefix    byteRelation = "prefix"
	bytesLonger    byteRelation = "longer"
	bytesDiffer    byteRelation = "differs"
)

// compareArchived reads both streams in step and reports how they relate,
// along with the offset the answer was settled at.
//
// It compares rather than hashing because the answer an operator needs from a
// mismatch is where it starts, and because a sealed segment and its archived
// copy are the same bytes or they are not: there is nothing a digest would add
// beyond a shorter thing to print.
func compareArchived(local, archived io.Reader) (byteRelation, int64, error) {
	const chunk = 64 << 10
	ab := make([]byte, chunk)
	lb := make([]byte, chunk)
	var off int64

	for {
		an, aerr := io.ReadFull(archived, ab)
		if aerr != nil && !errors.Is(aerr, io.EOF) && !errors.Is(aerr, io.ErrUnexpectedEOF) {
			return bytesDiffer, off, aerr
		}
		if an > 0 {
			ln, lerr := io.ReadFull(local, lb[:an])
			if lerr != nil && !errors.Is(lerr, io.EOF) && !errors.Is(lerr, io.ErrUnexpectedEOF) {
				return bytesDiffer, off, lerr
			}
			if d := firstDifference(ab[:min(an, ln)], lb[:min(an, ln)]); d >= 0 {
				return bytesDiffer, off + int64(d), nil
			}
			if ln < an {
				return bytesLonger, off + int64(ln), nil
			}
			off += int64(an)
		}
		if aerr != nil {
			break
		}
	}

	// The archived object has ended. Anything left in the local file means the
	// archive holds a shorter version of it.
	if n, err := io.ReadFull(local, lb[:1]); n > 0 {
		return bytesPrefix, off, nil
	} else if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return bytesDiffer, off, err
	}
	return bytesIdentical, off, nil
}

// firstDifference returns the index of the first differing byte, or -1.
func firstDifference(a, b []byte) int {
	if bytes.Equal(a, b) {
		return -1
	}
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return len(a)
}

func joinDetail(existing, added string) string {
	if existing == "" {
		return added
	}
	return existing + "; " + added
}
