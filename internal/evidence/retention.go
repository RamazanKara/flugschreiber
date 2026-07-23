package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultRetentionReason is recorded in the anchor when the operator gives no
// reason of their own. Deletion of evidence always names a cause.
const DefaultRetentionReason = "scheduled retention enforcement"

// RetentionPolicy is the minimum time evidence must be kept. This package
// enforces only what it is told; the six-month floor from Article 19 lives in
// internal/config, where an operator meets it at startup rather than at
// deletion time.
type RetentionPolicy struct {
	// MinDays is the minimum age, in days, of every record in a segment
	// before that segment may be deleted.
	MinDays int

	// MaxBytes caps the total size of the evidence segments. It is a pressure
	// valve, not a second retention rule, and it never overrides MinDays:
	// segments are removed oldest first while they are beyond retention, and
	// when everything left is still inside retention the result says the
	// directory is over its cap and nothing was deleted.
	//
	// Deciding to keep less evidence than the law requires is not a decision a
	// tool gets to make quietly at three in the morning. Zero disables the cap.
	MaxBytes int64

	// Now is injectable so that tests do not have to wait six months.
	Now func() time.Time
}

// Hold describes a legal hold. While one is in force nothing is deleted, no
// matter what the retention policy says.
type Hold struct {
	InForce bool   `json:"in_force"`
	Path    string `json:"path,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// SegmentStatus is one segment as retention sees it.
type SegmentStatus struct {
	Segment    string `json:"segment"`
	Index      int    `json:"index"`
	Records    uint64 `json:"records"`
	Bytes      int64  `json:"bytes"`
	FirstSeq   uint64 `json:"first_seq,omitempty"`
	LastSeq    uint64 `json:"last_seq,omitempty"`
	OldestTime string `json:"oldest_time,omitempty"`
	NewestTime string `json:"newest_time,omitempty"`

	// BeyondRetention is true only when every record in the segment is older
	// than the cutoff, which is what makes whole-segment deletion safe.
	BeyondRetention bool `json:"beyond_retention"`

	// Active marks the segment the store is currently appending to.
	Active bool `json:"active,omitempty"`

	// Eligible is BeyondRetention plus every other condition that has to hold
	// before this segment may actually be removed.
	Eligible bool `json:"eligible"`

	// Note explains a status that is not obvious from the other fields.
	Note string `json:"note,omitempty"`
}

// RetentionReport is what Inspect produces. Inspect never deletes anything, so
// this is safe to run on a schedule and to show an auditor.
type RetentionReport struct {
	Dir      string          `json:"dir"`
	MinDays  int             `json:"min_days"`
	Cutoff   string          `json:"cutoff"`
	Hold     Hold            `json:"hold"`
	Segments []SegmentStatus `json:"segments"`

	Records uint64 `json:"records"`
	Bytes   int64  `json:"bytes"`

	// MaxBytes and the two fields under it describe the size cap as it stands
	// right now, before anything is deleted.
	MaxBytes     int64  `json:"max_bytes,omitempty"`
	OverCap      bool   `json:"over_cap,omitempty"`
	BytesOverCap int64  `json:"bytes_over_cap,omitempty"`
	CapNote      string `json:"cap_note,omitempty"`

	Eligible        []string `json:"eligible,omitempty"`
	EligibleRecords uint64   `json:"eligible_records"`
	EligibleBytes   int64    `json:"eligible_bytes"`

	OldestTime string `json:"oldest_time,omitempty"`
	NewestTime string `json:"newest_time,omitempty"`
}

// EnforceOptions tunes one enforcement run.
type EnforceOptions struct {
	// DryRun reports exactly what would be deleted and writes nothing.
	DryRun bool

	// Reason is recorded in the prune anchor.
	Reason string

	// Keys signs the anchor. A nil KeyPair leaves the anchor unsigned, which
	// is still a valid anchor: the chain linkage it records is checkable
	// without a signature.
	Keys *KeyPair
}

// EnforceResult is what an enforcement run did, or would have done.
type EnforceResult struct {
	Dir     string `json:"dir"`
	DryRun  bool   `json:"dry_run"`
	MinDays int    `json:"min_days"`
	Cutoff  string `json:"cutoff"`
	Hold    Hold   `json:"hold"`

	// Eligible lists what qualified for deletion, whether or not it was
	// deleted. Deleted lists what was actually removed, and is empty for a dry
	// run and for a run blocked by a hold.
	Eligible        []string `json:"eligible,omitempty"`
	EligibleRecords uint64   `json:"eligible_records"`
	EligibleBytes   int64    `json:"eligible_bytes"`
	Deleted         []string `json:"deleted,omitempty"`

	LastPrunedSeq  uint64 `json:"last_pruned_seq,omitempty"`
	LastPrunedHash string `json:"last_pruned_hash,omitempty"`
	AnchorWritten  bool   `json:"anchor_written"`

	RetainedRecords uint64 `json:"retained_records"`
	RetainedBytes   int64  `json:"retained_bytes"`

	// MaxBytes and the three fields under it describe the size cap after this
	// run. OverCap true means the run finished with the directory still over
	// its cap, which can only happen when everything left is inside retention:
	// the cap has run out of things it is allowed to delete, and CapNote says
	// so in a sentence an operator can act on.
	MaxBytes     int64  `json:"max_bytes,omitempty"`
	OverCap      bool   `json:"over_cap,omitempty"`
	BytesOverCap int64  `json:"bytes_over_cap,omitempty"`
	CapNote      string `json:"cap_note,omitempty"`
}

// ReadLegalHold reports whether a LEGAL_HOLD file exists in dir and what it
// says. It is read at the moment enforcement runs and never cached, so
// dropping the file into the directory stops the next run without a restart.
func ReadLegalHold(dir string) (Hold, error) {
	path := filepath.Join(dir, LegalHoldFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Hold{}, nil
		}
		return Hold{}, fmt.Errorf("evidence: read %s: %w", LegalHoldFile, err)
	}
	reason := strings.TrimSpace(string(raw))
	if reason == "" {
		reason = fmt.Sprintf("no reason stated in %s", path)
	}
	return Hold{InForce: true, Path: path, Reason: reason}, nil
}

// Inspect reports the retention status of every segment in dir. It opens files
// read-only and deletes nothing, ever.
func (p RetentionPolicy) Inspect(dir string) (*RetentionReport, error) {
	cutoff, err := p.cutoff()
	if err != nil {
		return nil, err
	}
	hold, err := ReadLegalHold(dir)
	if err != nil {
		return nil, err
	}
	scans, err := scanSegments(dir)
	if err != nil {
		return nil, err
	}

	rep := &RetentionReport{
		Dir:     dir,
		MinDays: p.MinDays,
		Cutoff:  cutoff.UTC().Format(time.RFC3339Nano),
		Hold:    hold,
	}
	statuses := classify(scans, cutoff)
	for i, st := range statuses {
		rep.Segments = append(rep.Segments, st)
		rep.Records += st.Records
		rep.Bytes += st.Bytes
		if st.Eligible {
			rep.Eligible = append(rep.Eligible, st.Segment)
			rep.EligibleRecords += st.Records
			rep.EligibleBytes += st.Bytes
		}
		// A segment whose records all carry an unreadable timestamp contributes
		// no time at all, and must not blank out the range the others establish.
		if s := scans[i]; s.records > 0 && s.newestStr != "" {
			if rep.OldestTime == "" {
				rep.OldestTime = s.oldestStr
			}
			rep.NewestTime = s.newestStr
		}
	}
	p.reportCap(rep)
	return rep, nil
}

// reportCap describes the size cap as Inspect finds it, before anything has
// been deleted, and says what enforcement would be able to do about it.
func (p RetentionPolicy) reportCap(rep *RetentionReport) {
	if p.MaxBytes <= 0 {
		return
	}
	rep.MaxBytes = p.MaxBytes
	if rep.Bytes <= p.MaxBytes {
		return
	}
	rep.OverCap = true
	rep.BytesOverCap = rep.Bytes - p.MaxBytes

	switch {
	case rep.EligibleBytes >= rep.BytesOverCap:
		rep.CapNote = fmt.Sprintf(
			"the segments hold %d bytes, %d over the %d-byte cap; enforcement would delete %d bytes that are beyond retention, which brings the directory back under it",
			rep.Bytes, rep.BytesOverCap, p.MaxBytes, rep.EligibleBytes)
	case rep.EligibleBytes > 0:
		rep.CapNote = fmt.Sprintf(
			"the segments hold %d bytes, %d over the %d-byte cap; enforcement would delete the %d bytes that are beyond retention, which is not enough, and everything else is inside the %d-day retention floor",
			rep.Bytes, rep.BytesOverCap, p.MaxBytes, rep.EligibleBytes, p.MinDays)
	default:
		rep.CapNote = fmt.Sprintf(
			"the segments hold %d bytes, %d over the %d-byte cap, and nothing is beyond retention: every record is inside the %d-day floor, so enforcement would delete nothing",
			rep.Bytes, rep.BytesOverCap, p.MaxBytes, p.MinDays)
	}
}

// Enforce deletes whole segments from the front of the log once every record
// in them is beyond retention. It never deletes the segment the store is
// writing to, never deletes part of a segment, and never deletes anything
// while a legal hold is in force. A segment holding no records goes with the
// run it sits in and never blocks it, because there is nothing in it for
// retention to protect.
//
// The prune anchor is written and fsynced before the first unlink. A crash
// between the two leaves an anchor that claims more than was deleted, which
// Verify reports as an incomplete prune and which a second Enforce finishes.
// The opposite order would leave a log with no anchor and no way to prove the
// missing records were removed by policy rather than by an attacker, and that
// damage is permanent.
func (p RetentionPolicy) Enforce(dir string, opts EnforceOptions) (res *EnforceResult, err error) {
	cutoff, err := p.cutoff()
	if err != nil {
		return nil, err
	}
	res = &EnforceResult{
		Dir:     dir,
		DryRun:  opts.DryRun,
		MinDays: p.MinDays,
		Cutoff:  cutoff.UTC().Format(time.RFC3339Nano),
	}
	// Every successful exit from this function has to account for the size
	// cap, including the ones that delete nothing, because "over the cap and
	// refusing to act" is precisely the state an operator has to be told about.
	defer func() { p.reportCapAfter(res) }()

	hold, err := ReadLegalHold(dir)
	if err != nil {
		return nil, err
	}
	res.Hold = hold

	scans, err := scanSegments(dir)
	if err != nil {
		return nil, err
	}
	statuses := classify(scans, cutoff)

	var eligible []*segmentScan
	for i, st := range statuses {
		if !st.Eligible {
			break
		}
		eligible = append(eligible, scans[i])
		res.Eligible = append(res.Eligible, st.Segment)
		res.EligibleRecords += st.Records
		res.EligibleBytes += st.Bytes
	}
	for _, s := range scans[len(eligible):] {
		res.RetainedRecords += s.records
		res.RetainedBytes += s.bytes
	}

	if hold.InForce {
		// A hold is a normal state of the system rather than a failure, so it
		// is reported instead of returned as an error. The eligible list is
		// kept so that an operator can see exactly what the hold is holding.
		res.RetainedRecords, res.RetainedBytes = 0, 0
		for _, s := range scans {
			res.RetainedRecords += s.records
			res.RetainedBytes += s.bytes
		}
		return res, nil
	}
	if len(eligible) == 0 {
		return res, nil
	}

	// The anchor has to name a real record, so it comes from the newest
	// eligible segment that holds one rather than from the newest eligible
	// file. Empty segments in the run carry nothing, so removing them moves the
	// anchor point nowhere.
	last := lastWithRecords(eligible)
	if last != nil {
		res.LastPrunedSeq = last.lastSeq
		res.LastPrunedHash = last.lastRecordHash
		if res.LastPrunedHash == "" || res.LastPrunedSeq == 0 {
			return nil, fmt.Errorf(
				"evidence: refusing to prune: cannot read the last record of %s, so the surviving log would have no anchor to link to",
				last.name)
		}

		if err := p.checkAnchorNeverRewinds(dir, res.LastPrunedSeq); err != nil {
			return nil, err
		}
		if err := checkSurvivorLinks(scans[len(eligible):], last); err != nil {
			return nil, err
		}
	}

	if opts.DryRun {
		return res, nil
	}

	// Removing only empty segments deletes no record, so there is no gap for an
	// anchor to explain and an existing anchor keeps saying exactly what it
	// said before.
	if last != nil {
		anchor, err := buildAnchor(dir, p.now(), res, eligible, opts)
		if err != nil {
			return nil, err
		}
		if err := WritePruneAnchor(dir, *anchor); err != nil {
			return nil, err
		}
		res.AnchorWritten = true
	}

	for _, s := range eligible {
		if err := os.Remove(s.path); err != nil {
			return res, fmt.Errorf("evidence: delete %s after writing the prune anchor: %w", s.name, err)
		}
		res.Deleted = append(res.Deleted, s.name)
	}
	syncDir(dir)
	return res, nil
}

// reportCapAfter describes the size cap as the run leaves it.
//
// Enforcement deletes every segment that is beyond retention, oldest first, so
// by the time this runs there is nothing further the cap is permitted to take:
// what is left is either inside the retention floor or held by a legal hold.
// Being over the cap at that point is therefore a report and never an
// escalation. Disk pressure against a legal floor is the operator's decision,
// and a tool that resolved it by deleting evidence early would be making the
// one choice it must never make on its own.
func (p RetentionPolicy) reportCapAfter(res *EnforceResult) {
	if res == nil || p.MaxBytes <= 0 {
		return
	}
	res.MaxBytes = p.MaxBytes
	if res.RetainedBytes <= p.MaxBytes {
		return
	}
	res.OverCap = true
	res.BytesOverCap = res.RetainedBytes - p.MaxBytes

	switch {
	case res.Hold.InForce:
		res.CapNote = fmt.Sprintf(
			"the segments hold %d bytes, %d over the %d-byte cap, and a legal hold is in force, so nothing was deleted: %s",
			res.RetainedBytes, res.BytesOverCap, p.MaxBytes, res.Hold.Reason)
	case res.DryRun:
		res.CapNote = fmt.Sprintf(
			"after the deletions this run would make, the segments would still hold %d bytes, %d over the %d-byte cap, with everything left inside the %d-day retention floor",
			res.RetainedBytes, res.BytesOverCap, p.MaxBytes, p.MinDays)
	default:
		res.CapNote = fmt.Sprintf(
			"the segments still hold %d bytes, %d over the %d-byte cap, and everything left is inside the %d-day retention floor, so nothing further was deleted; add storage or record less, because keeping fewer than %d days of evidence is an operator's decision and not this tool's",
			res.RetainedBytes, res.BytesOverCap, p.MaxBytes, p.MinDays, p.MinDays)
	}
}

// lastWithRecords returns the newest scan in the run that holds at least one
// record, or nil when the whole run is empty files.
func lastWithRecords(scans []*segmentScan) *segmentScan {
	for i := len(scans) - 1; i >= 0; i-- {
		if scans[i].records > 0 {
			return scans[i]
		}
	}
	return nil
}

func (p RetentionPolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p RetentionPolicy) cutoff() (time.Time, error) {
	if p.MinDays <= 0 {
		return time.Time{}, errors.New("evidence: retention policy has no minimum retention set; refusing to treat that as delete everything")
	}
	return p.now().UTC().Add(-time.Duration(p.MinDays) * 24 * time.Hour), nil
}

// checkAnchorNeverRewinds refuses a prune that would move an existing anchor
// backwards, which means either that segments were restored out of order or
// that the anchor belongs to a different log.
//
// An unchanged anchor point is allowed, because that is what finishing an
// interrupted run looks like: the anchor is already on disk and the segments
// it names are still there.
func (p RetentionPolicy) checkAnchorNeverRewinds(dir string, newSeq uint64) error {
	existing, err := ReadPruneAnchor(dir)
	if err != nil {
		return err
	}
	if existing == nil || newSeq >= existing.LastPrunedSeq {
		return nil
	}
	return fmt.Errorf(
		"evidence: refusing to prune: %s already records deletion through seq %d and this run would move it back to seq %d",
		PruneAnchorFile, existing.LastPrunedSeq, newSeq)
}

// checkSurvivorLinks refuses to delete when the first surviving record does not
// link to the last record being deleted. If the chain is already broken there,
// pruning would make the break permanent and unattributable.
func checkSurvivorLinks(survivors []*segmentScan, last *segmentScan) error {
	for _, s := range survivors {
		if s.records == 0 {
			continue
		}
		if s.firstPrevHash != last.lastRecordHash || s.firstSeq != last.lastSeq+1 {
			return fmt.Errorf(
				"evidence: refusing to prune: %s begins at seq %d with prev_hash %s but %s ends at seq %d with record_hash %s; verify the chain before deleting anything",
				s.name, s.firstSeq, short(s.firstPrevHash), last.name, last.lastSeq, short(last.lastRecordHash))
		}
		return nil
	}
	return nil
}

func buildAnchor(dir string, at time.Time, res *EnforceResult, eligible []*segmentScan, opts EnforceOptions) (*PruneAnchor, error) {
	existing, err := ReadPruneAnchor(dir)
	if err != nil {
		return nil, err
	}

	reason := strings.TrimSpace(opts.Reason)
	if reason == "" {
		reason = fmt.Sprintf("%s, minimum retention %d days", DefaultRetentionReason, res.MinDays)
	}

	a := &PruneAnchor{
		Version:        PruneAnchorVersion,
		PrunedAt:       at.UTC().Format(time.RFC3339Nano),
		LastPrunedSeq:  res.LastPrunedSeq,
		LastPrunedHash: res.LastPrunedHash,
		Reason:         reason,
	}
	already := map[string]bool{}
	if existing != nil {
		// The anchor is cumulative: it names every segment ever pruned, so an
		// auditor can account for the whole history from one file.
		a.Segments = append(a.Segments, existing.Segments...)
		a.Records = existing.Records
		for _, name := range existing.Segments {
			already[name] = true
		}
	}
	for _, s := range eligible {
		// Finishing an interrupted run sees segments the anchor already names.
		// Counting them twice would overstate what was deleted.
		if already[s.name] {
			continue
		}
		a.Segments = append(a.Segments, s.name)
		a.Records += s.records
	}

	if opts.Keys != nil {
		if err := SignPruneAnchor(opts.Keys.Private, opts.Keys.ID, a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// classify turns raw segment scans into statuses. The newest segment is always
// the one the store appends to, so it is never eligible however old its
// records are.
func classify(scans []*segmentScan, cutoff time.Time) []SegmentStatus {
	out := make([]SegmentStatus, 0, len(scans))
	for i, s := range scans {
		st := SegmentStatus{
			Segment:    s.name,
			Index:      s.index,
			Records:    s.records,
			Bytes:      s.bytes,
			FirstSeq:   s.firstSeq,
			LastSeq:    s.lastSeq,
			OldestTime: s.oldestStr,
			NewestTime: s.newestStr,
			Active:     i == len(scans)-1,
		}
		switch {
		case s.records == 0:
			// An empty segment holds no record, so retention is not protecting
			// anything in it and it can never age out on its own. Leaving it
			// short of the cutoff would strand it at the front of the log, and
			// because deletion only ever takes a prefix, that one file would
			// keep every segment behind it unprunable forever. A crash between
			// rotating and writing the first record leaves exactly this file.
			st.BeyondRetention = true
			st.Note = "empty segment, holds nothing that retention protects"
		case s.undated > 0:
			st.Note = fmt.Sprintf("%d record(s) have an unreadable timestamp, so the segment is kept", s.undated)
		default:
			st.BeyondRetention = s.newest.Before(cutoff)
		}
		// A segment that holds records may only go once its last record can
		// anchor the survivors. An empty segment anchors nothing and so needs
		// no hash.
		st.Eligible = st.BeyondRetention && !st.Active && (s.records == 0 || s.lastRecordHash != "")
		if st.Active && st.BeyondRetention {
			st.Note = "the log is still being written here, so it is never deleted"
		}
		out = append(out, st)
	}
	return out
}

// segmentScan is everything retention needs to know about one segment file.
type segmentScan struct {
	name  string
	index int
	path  string
	bytes int64

	records  uint64
	firstSeq uint64
	lastSeq  uint64

	firstPrevHash  string
	lastRecordHash string

	oldest, newest       time.Time
	oldestStr, newestStr string
	undated              uint64
}

func scanSegments(dir string) ([]*segmentScan, error) {
	segs, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*segmentScan, 0, len(segs))
	for _, seg := range segs {
		s, err := scanSegment(seg)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// scanSegment reads one segment and refuses to guess. A record it cannot parse
// is an error, because everything downstream of this decides what to delete.
func scanSegment(seg SegmentInfo) (*segmentScan, error) {
	name := filepath.Base(seg.Path)
	info, err := os.Stat(seg.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(seg.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := &segmentScan{name: name, index: seg.Index, path: seg.Path, bytes: info.Size()}
	sc := newLineScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("evidence: %s:%d: %w", name, sc.Line(), err)
		}
		if s.records == 0 {
			s.firstSeq = rec.Seq
			s.firstPrevHash = rec.PrevHash
		}
		s.records++
		s.lastSeq = rec.Seq
		s.lastRecordHash = rec.RecordHash

		ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp)
		if err != nil {
			// A record whose age cannot be established is treated as young,
			// which keeps the segment. Deleting on a guess is the one mistake
			// this package must not make.
			s.undated++
			continue
		}
		ts = ts.UTC()
		if s.oldestStr == "" || ts.Before(s.oldest) {
			s.oldest, s.oldestStr = ts, rec.Timestamp
		}
		// Take the maximum rather than the last record, so that a clock that
		// stepped backwards mid-segment cannot make the segment look older
		// than its newest record really is.
		if s.newestStr == "" || ts.After(s.newest) {
			s.newest, s.newestStr = ts, rec.Timestamp
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", name, err)
	}
	return s, nil
}
