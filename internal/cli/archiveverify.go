package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/archive"
	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// archiveReader is the read half of an archive backend. Verification never
// writes, so it takes the two methods it needs and not the Archiver the store
// depends on; both backends satisfy it structurally.
type archiveReader interface {
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
	objectPresent  = "present"
	objectMissing  = "missing"
	objectMismatch = "mismatch"
	objectUnknown  = "unknown"
)

// The parts of an evidence directory that reach an archive at all.
const (
	kindSealedSegment = "sealed_segment"
	kindPrunedSegment = "pruned_segment"
	kindOpenSegment   = "open_segment"
	kindPublicKey     = "public_key"
	kindRetiredKey    = "retired_key"
	kindCheckpoints   = "checkpoints"
)

// maxKeyPEMBytes bounds what is read back for a key comparison. A PEM public
// key is a few hundred bytes; the cap is what keeps a misconfigured bucket
// from streaming a segment into memory in its place.
const maxKeyPEMBytes = 64 << 10

// archiveObject is one key the archive was asked about.
type archiveObject struct {
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

// archiveVerifyResult is what one run checked, and what it could not.
type archiveVerifyResult struct {
	Dir     string `json:"dir"`
	Backend string `json:"backend"`
	Target  string `json:"target"`
	Prefix  string `json:"prefix,omitempty"`
	Deep    bool   `json:"deep"`

	Objects []archiveObject `json:"objects,omitempty"`

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
func (r *archiveVerifyResult) OK() bool {
	return r.Missing == 0 && r.Mismatched == 0 && r.Unknown == 0
}

// ArchiveVerify checks an archived copy of the evidence against the local
// directory it was made from.
func ArchiveVerify(args []string) error {
	fs := flag.NewFlagSet("archive-verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: flugschreiber archive-verify --dir DIR [flags]

Checks that the archive holds what the local evidence directory says it should:
one object per sealed segment, one per segment retention has already deleted
locally, the public key and every key a rotation has retired, plus the
snapshots that carry the checkpoints and the segment still being written. With
--deep it reads each object back and compares it against the local copy byte
for byte.

An archive is a subset of the evidence directory, not a copy of it. pruned.json
and LEGAL_HOLD are not in it, and neither is anything the local directory does
not name, since neither backend offers a listing. The output states what this
run could not check rather than leaving it to be assumed.

The archive settings come from the same config file and %sARCHIVE_*
environment variables serve uses. Credentials are never taken from a flag,
because a command line is readable by every process on the host.

Exit status is 0 when every object was found and matched, and 1 when one was
missing, differed, or could not be checked at all.

Flags:
`, config.EnvPrefix)
		fs.PrintDefaults()
	}

	var (
		dir        = fs.String("dir", "", "evidence directory the archive was made from (required)")
		configPath = fs.String("config", "", "JSON config file holding the archive settings")
		backend    = fs.String("archive-backend", "", "archive backend: dir or s3")
		archiveDir = fs.String("archive-dir", "", "root directory of the dir backend")
		bucket     = fs.String("archive-bucket", "", "bucket of the s3 backend")
		region     = fs.String("archive-region", "", "region of the s3 backend")
		endpoint   = fs.String("archive-endpoint", "", "endpoint of the s3 backend, e.g. https://minio.internal:9000")
		addressing = fs.String("archive-addressing", "", "s3 addressing style: auto, virtual or path")
		prefix     = fs.String("archive-prefix", "", "key prefix the evidence was archived under")
		deep       = fs.Bool("deep", false, "read every object back and compare it against the local copy")
		asJSON     = fs.Bool("json", false, "emit the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("archive-verify: --dir is required")
	}

	cfg, err := commandConfig(*configPath)
	if err != nil {
		return err
	}
	setString(&cfg.Archive.Backend, *backend)
	setString(&cfg.Archive.Dir, *archiveDir)
	setString(&cfg.Archive.Bucket, *bucket)
	setString(&cfg.Archive.Region, *region)
	setString(&cfg.Archive.Endpoint, *endpoint)
	setString(&cfg.Archive.Addressing, *addressing)
	setString(&cfg.Archive.Prefix, *prefix)

	reader, err := openArchiveReader(cfg.Archive)
	if err != nil {
		return err
	}

	res, err := verifyArchive(context.Background(), reader, *dir, cfg.Archive.Prefix, *deep)
	if err != nil {
		return err
	}

	if *asJSON {
		if err := emitJSON(res); err != nil {
			return err
		}
	} else {
		printArchiveVerify(res)
	}
	if res.OK() {
		return nil
	}
	return archiveVerifyFailure(res)
}

// openArchiveReader builds the backend to read from. It never creates an
// archive: a verification that quietly brought its own empty directory into
// existence would report every object missing and look like data loss.
//
// The key prefix is deliberately not passed to the backend. Both the evidence
// store and the backend can prepend one, and this command builds keys the way
// the store does, so letting the backend add it as well would look for every
// object under the prefix twice over (D27).
func openArchiveReader(cfg config.Archive) (archiveReader, error) {
	switch cfg.Backend {
	case "", config.ArchiveNone:
		return nil, fmt.Errorf(
			"archive-verify: no archive is configured; set archive.backend to %s or %s in the config file, or pass --archive-backend",
			config.ArchiveDir, config.ArchiveS3)

	case config.ArchiveDir:
		if cfg.Dir == "" {
			return nil, fmt.Errorf("archive-verify: archive backend %q needs --archive-dir (archive.dir)", config.ArchiveDir)
		}
		if _, err := os.Stat(cfg.Dir); err != nil {
			return nil, fmt.Errorf("archive-verify: %s is not readable, so there is no archive to check: %w", cfg.Dir, err)
		}
		return archive.NewDir(cfg.Dir)

	case config.ArchiveS3:
		if cfg.Bucket == "" {
			return nil, fmt.Errorf("archive-verify: archive backend %q needs --archive-bucket (archive.bucket)", config.ArchiveS3)
		}
		return archive.NewS3(archive.Config{
			Bucket:     cfg.Bucket,
			Region:     cfg.Region,
			Endpoint:   cfg.Endpoint,
			Addressing: cfg.Addressing,
			Credentials: archive.Credentials{
				AccessKeyID:     cfg.AccessKeyID,
				SecretAccessKey: cfg.SecretAccessKey,
				SessionToken:    cfg.SessionToken,
			},
		})

	default:
		return nil, fmt.Errorf(
			"archive-verify: archive backend %q must be one of %s, %s or %s",
			cfg.Backend, config.ArchiveNone, config.ArchiveDir, config.ArchiveS3)
	}
}

// verifyArchive derives the keys the store would have written from what the
// local directory holds, and asks the archive about each of them.
//
// Deriving rather than listing is not a shortcut: neither backend offers a
// listing, and an archive is checked against the evidence it was made from, so
// the local directory is the authority on what should be there. The cost is
// that an object the local directory does not name cannot be seen from here,
// which the result says out loud.
func verifyArchive(ctx context.Context, ar archiveReader, dir, prefix string, deep bool) (*archiveVerifyResult, error) {
	res := &archiveVerifyResult{
		Dir:     dir,
		Backend: ar.Name(),
		Target:  ar.Target(),
		Prefix:  prefix,
		Deep:    deep,
	}
	v := &archiveProbe{ctx: ctx, ar: ar, deep: deep, res: res}

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
		v.check(archiveObject{
			Key:      archive.JoinKey(prefix, name),
			Kind:     kindSealedSegment,
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
			v.check(archiveObject{
				Key:      archive.JoinKey(prefix, name),
				Kind:     kindPrunedSegment,
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

// archiveProbe carries the state one run of checks shares.
type archiveProbe struct {
	ctx  context.Context
	ar   archiveReader
	deep bool
	res  *archiveVerifyResult
}

// check probes one key and records the outcome.
func (p *archiveProbe) check(o archiveObject) {
	if p.deep && o.Local != "" {
		p.compare(&o)
	} else {
		p.exists(&o)
	}
	p.record(o)
}

func (p *archiveProbe) exists(o *archiveObject) {
	switch present, err := p.ar.Exists(p.ctx, o.Key); {
	case err != nil:
		o.Status = objectUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the %s backend did not answer: %v", p.ar.Name(), err))
	case present:
		o.Status = objectPresent
	default:
		o.Status = objectMissing
	}
}

// compare reads the object back and holds it against the local file.
func (p *archiveProbe) compare(o *archiveObject) {
	body, err := p.ar.Get(p.ctx, o.Key)
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			o.Status = objectMissing
			return
		}
		o.Status = objectUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the %s backend did not answer: %v", p.ar.Name(), err))
		return
	}
	defer body.Close()

	local, err := os.Open(o.Local)
	if err != nil {
		o.Status = objectUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the local copy could not be read: %v", err))
		return
	}
	defer local.Close()

	rel, n, err := compareArchived(local, body)
	o.Bytes = n
	switch {
	case err != nil:
		o.Status = objectUnknown
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the comparison stopped after %d bytes: %v", n, err))
	case rel == bytesIdentical:
		o.Status = objectPresent
	case rel == bytesPrefix && o.Kind == kindCheckpoints:
		// The checkpoint file grows; what the archive holds is the snapshot the
		// key names, so being a prefix of the local file is what agreement
		// looks like here.
		o.Status = objectPresent
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the snapshot is the first %d bytes of the current %s and agrees with them", n, evidence.CheckpointsFile))
	case rel == bytesPrefix && o.Kind == kindOpenSegment:
		// Same for a segment that was still open: the key names the head the
		// snapshot covers, and a later run appended past it.
		o.Status = objectPresent
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the snapshot is the first %d bytes of %s and agrees with them", n, filepath.Base(o.Local)))
	case rel == bytesPrefix:
		o.Status = objectMismatch
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the archived object stops after %d bytes and the local file continues", n))
	case rel == bytesLonger:
		o.Status = objectMismatch
		o.Detail = joinDetail(o.Detail, fmt.Sprintf("the archived object carries bytes past the end of the local file at offset %d", n))
	default:
		o.Status = objectMismatch
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
func (p *archiveProbe) checkPublicKey(dir, key, localPath string) {
	o := archiveObject{Key: key, Kind: kindPublicKey, Local: localPath, Required: true}
	if !p.deep {
		p.exists(&o)
		p.record(o)
		return
	}

	body, err := p.ar.Get(p.ctx, key)
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			o.Status = objectMissing
		} else {
			o.Status = objectUnknown
			o.Detail = fmt.Sprintf("the %s backend did not answer: %v", p.ar.Name(), err)
		}
		p.record(o)
		return
	}
	defer body.Close()

	archived, err := io.ReadAll(io.LimitReader(body, maxKeyPEMBytes))
	if err != nil {
		o.Status = objectUnknown
		o.Detail = fmt.Sprintf("the archived key could not be read: %v", err)
		p.record(o)
		return
	}
	o.Bytes = int64(len(archived))

	local, err := os.ReadFile(localPath)
	if err != nil {
		o.Status = objectUnknown
		o.Detail = fmt.Sprintf("the local %s could not be read, so there is nothing to compare against: %v", evidence.PublicKeyFile, err)
		p.record(o)
		return
	}
	if bytes.Equal(local, archived) {
		o.Status = objectPresent
		p.record(o)
		return
	}

	retired, matchErr := matchRetiredKey(dir, archived)
	switch {
	case matchErr != nil:
		o.Status = objectUnknown
		o.Detail = fmt.Sprintf("the archived key differs from %s and the retired keys could not be read: %v", evidence.PublicKeyFile, matchErr)
	case retired != "":
		o.Status = objectPresent
		o.Detail = fmt.Sprintf(
			"this object holds the key this directory retired to %s; the store uploads the public key once, so a rotation since then is not reflected in it",
			retired)
	default:
		o.Status = objectMismatch
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
func (p *archiveProbe) checkRetiredKeys(dir, prefix string) error {
	files, err := evidence.RetiredKeyFiles(dir)
	if err != nil {
		return fmt.Errorf("archive-verify: %w", err)
	}
	for _, name := range files {
		o := archiveObject{
			Key:   archive.JoinKey(prefix, name),
			Kind:  kindRetiredKey,
			Local: filepath.Join(dir, filepath.FromSlash(name)),
		}
		if p.deep {
			p.compare(&o)
		} else {
			p.exists(&o)
		}
		if o.Status == objectMissing {
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
func (p *archiveProbe) checkOpenSnapshots(prefix string, checkpoints []evidence.Checkpoint, local map[string]string) map[string]bool {
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

		o := archiveObject{Key: archive.JoinKey(prefix, key), Kind: kindOpenSegment, Local: path}
		if p.deep {
			p.compare(&o)
		} else {
			p.exists(&o)
		}
		if o.Status == objectMissing {
			p.res.Probed++
			continue
		}
		if o.Status == objectPresent {
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
func (p *archiveProbe) checkCheckpoints(dir, prefix string, checkpoints []evidence.Checkpoint) {
	p.res.CheckpointHeads = len(checkpoints)
	localPath := filepath.Join(dir, evidence.CheckpointsFile)

	seen := map[uint64]bool{}
	for _, c := range checkpoints {
		if seen[c.Seq] {
			continue
		}
		seen[c.Seq] = true

		o := archiveObject{Key: archive.JoinKey(prefix, checkpointSnapshotKey(c.Seq)), Kind: kindCheckpoints, Local: localPath}
		if p.deep {
			p.compare(&o)
		} else {
			p.exists(&o)
		}
		// An absent snapshot is the ordinary case. It is counted as probed and
		// left out of the object list, which would otherwise carry one line
		// per checkpoint saying nothing.
		if o.Status == objectMissing {
			p.res.Probed++
			continue
		}
		if o.Status == objectPresent {
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

func (p *archiveProbe) record(o archiveObject) {
	p.res.Probed++
	p.res.BytesCompared += o.Bytes
	switch o.Status {
	case objectPresent:
		p.res.Present++
	case objectMissing:
		p.res.Missing++
	case objectMismatch:
		p.res.Mismatched++
	case objectUnknown:
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

// archiveVerifyFailure turns the counts into the one sentence an operator
// reads first, naming the keys rather than only counting them.
func archiveVerifyFailure(res *archiveVerifyResult) error {
	var parts []string
	if res.Missing > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) missing from the archive (%s)",
			res.Missing, namedKeys(res, objectMissing)))
	}
	if res.Mismatched > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) differ from the local evidence (%s)",
			res.Mismatched, namedKeys(res, objectMismatch)))
	}
	if res.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) could not be checked at all (%s)",
			res.Unknown, namedKeys(res, objectUnknown)))
	}
	return fmt.Errorf("archive-verify: %s", strings.Join(parts, "; "))
}

// namedKeys lists the keys in one state, up to a few, so that an error line
// stays an error line.
func namedKeys(res *archiveVerifyResult, status string) string {
	const show = 3
	var keys []string
	for _, o := range res.Objects {
		if o.Status != status {
			continue
		}
		if len(keys) == show {
			keys = append(keys, "...")
			break
		}
		keys = append(keys, o.Key)
	}
	return strings.Join(keys, ", ")
}

func printArchiveVerify(res *archiveVerifyResult) {
	if res.OK() {
		fmt.Printf("archive holds every object the evidence directory names\n\n")
	} else {
		fmt.Printf("ARCHIVE VERIFICATION FOUND GAPS\n\n")
	}

	fmt.Printf("  evidence    %s\n", res.Dir)
	fmt.Printf("  archive     %s  %s\n", res.Backend, res.Target)
	if res.Prefix != "" {
		fmt.Printf("  prefix      %s\n", res.Prefix)
	}
	if res.Deep {
		fmt.Printf("  mode        deep, every object read back and compared (%s)\n", humanBytes(res.BytesCompared))
	} else {
		fmt.Printf("  mode        presence only; pass --deep to compare the bytes\n")
	}
	fmt.Printf("  probed      %d key(s): %d present", res.Probed, res.Present)
	if res.Missing > 0 {
		fmt.Printf(", %d MISSING", res.Missing)
	}
	if res.Mismatched > 0 {
		fmt.Printf(", %d MISMATCHED", res.Mismatched)
	}
	if res.Unknown > 0 {
		fmt.Printf(", %d unanswered", res.Unknown)
	}
	fmt.Printf("\n")
	if res.CheckpointHeads > 0 {
		fmt.Printf("  checkpoints %d of %d attested head(s) have a snapshot in the archive\n",
			res.CheckpointSnapshots, res.CheckpointHeads)
	}
	if res.OpenSnapshots > 0 {
		fmt.Printf("  open        %d snapshot(s) of a segment that was still being written\n", res.OpenSnapshots)
	}

	if !res.OK() {
		fmt.Printf("\n  what is wrong\n\n")
		for _, o := range res.Objects {
			if o.Status == objectPresent {
				continue
			}
			fmt.Printf("    [%s] %s\n", strings.ToUpper(o.Status), o.Key)
			if o.Detail != "" {
				fmt.Printf("      %s\n", o.Detail)
			}
		}
	}

	// A present object with something particular to say about it. Snapshots and
	// pruned segments each carry the same sentence as their neighbours, and a
	// summary line already covers them, so printing them per object would bury
	// the one remark that is not routine.
	for _, o := range res.Objects {
		if o.Status != objectPresent || o.Detail == "" {
			continue
		}
		switch o.Kind {
		case kindCheckpoints, kindOpenSegment, kindPrunedSegment:
			continue
		}
		fmt.Printf("\n  %s\n    %s\n", o.Key, o.Detail)
	}

	fmt.Printf("\n  not checked\n\n")
	for _, s := range res.NotChecked {
		fmt.Printf("    - %s\n", s)
	}
	for _, s := range res.Notes {
		fmt.Printf("\n  %s\n", s)
	}
}
