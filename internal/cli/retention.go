package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Retention reports on, and optionally enforces, the retention policy.
//
// Deleting evidence is the most destructive thing this tool can do, so the
// command reports by default, dry-runs when asked to enforce, and only deletes
// when a second explicit flag says so. Nobody should be able to destroy six
// months of audit records with a typo.
func Retention(args []string) error {
	fs := flag.NewFlagSet("retention", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber retention [flags]

With no action flag, reports which segments are beyond the retention period and
what a deletion would remove. It changes nothing.

  flugschreiber retention --dir DIR                    report only
  flugschreiber retention --dir DIR --enforce          dry run, shows the plan
  flugschreiber retention --dir DIR --enforce --confirm   actually delete
  flugschreiber retention --dir DIR --max-bytes N      report against a size cap
  flugschreiber retention --dir DIR --hold "reason"    place a legal hold
  flugschreiber retention --dir DIR --release-hold     lift it

Deletion removes whole segments only, oldest first, and only when every record
in a segment is beyond retention. It records what it removed in pruned.json so
that the surviving chain still verifies and a reader can see that the log was
pruned rather than complete.

--max-bytes adds a size cap on top of that, and it deletes nothing the age rule
would not have deleted anyway. Enforcement removes beyond-retention segments
oldest first, and if the directory is still over the cap once they are gone,
everything left is inside the retention floor: the run reports that it is over
and stops. Keeping less evidence than Article 19 asks for is an operator's
decision, so the cap reports it rather than making it at three in the morning.

While a LEGAL_HOLD file is present nothing is deleted.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir      = fs.String("dir", "", "evidence directory (required)")
		minDays  = fs.Int("min-days", config.RetentionFloorDays, "minimum retention in days")
		maxBytes = fs.Int64("max-bytes", 0,
			"size cap in bytes, reported and never enforced past the retention floor (0 disables it)")
		enforce     = fs.Bool("enforce", false, "plan a deletion; combine with --confirm to carry it out")
		confirm     = fs.Bool("confirm", false, "carry out the deletion planned by --enforce")
		reason      = fs.String("reason", evidence.DefaultRetentionReason, "reason recorded in the prune anchor")
		hold        = fs.String("hold", "", "place a legal hold with this reason, blocking all deletion")
		releaseHold = fs.Bool("release-hold", false, "remove an existing legal hold")
		asJSON      = fs.Bool("json", false, "emit the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("retention: --dir is required")
	}
	if *hold != "" && *releaseHold {
		return errors.New("retention: --hold and --release-hold are mutually exclusive")
	}
	if *confirm && !*enforce {
		return errors.New("retention: --confirm only means anything with --enforce")
	}
	if *minDays < config.RetentionFloorDays {
		return fmt.Errorf(
			"retention: --min-days %d is below the %d-day floor; AI Act Article 19 expects at least six months of logs",
			*minDays, config.RetentionFloorDays)
	}
	if *maxBytes < 0 {
		return fmt.Errorf("retention: --max-bytes %d is negative; use 0 to run without a size cap", *maxBytes)
	}

	switch {
	case *hold != "":
		return placeHold(*dir, *hold)
	case *releaseHold:
		return liftHold(*dir)
	}

	policy := evidence.RetentionPolicy{MinDays: *minDays, MaxBytes: *maxBytes}

	if !*enforce {
		report, err := policy.Inspect(*dir)
		if err != nil {
			return err
		}
		if *asJSON {
			return emitJSON(report)
		}
		printRetentionReport(report)
		return nil
	}

	// Signing the anchor is best effort: an unsigned anchor still records the
	// chain linkage, and refusing to enforce retention because no key exists
	// would be the wrong trade.
	var keys *evidence.KeyPair
	if kp, err := evidence.LoadOrCreateKeyPair(*dir); err == nil {
		keys = kp
	}

	// Enforce returns what it managed to do alongside the error when an unlink
	// fails after the prune anchor was written. Reporting that before the error
	// is the difference between an operator who knows which segments are
	// already gone and one who has to work it out from the directory.
	result, err := policy.Enforce(*dir, evidence.EnforceOptions{
		DryRun: !*confirm,
		Reason: *reason,
		Keys:   keys,
	})
	if result == nil {
		return err
	}
	if *asJSON {
		if jsonErr := emitJSON(result); jsonErr != nil && err == nil {
			return jsonErr
		}
	} else {
		printEnforceResult(result, err != nil)
	}
	return err
}

func placeHold(dir, reason string) error {
	path := filepath.Join(dir, "LEGAL_HOLD")
	if _, err := os.Stat(path); err == nil {
		existing, _ := evidence.ReadLegalHold(dir)
		return fmt.Errorf("retention: a legal hold is already in force: %s", strings.TrimSpace(existing.Reason))
	}
	body := strings.TrimSpace(reason) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("retention: place legal hold: %w", err)
	}
	fmt.Printf("legal hold placed\n\n")
	fmt.Printf("  file    %s\n", path)
	fmt.Printf("  reason  %s\n", strings.TrimSpace(reason))
	fmt.Printf("\nNothing will be deleted from this directory while that file exists.\n")
	return nil
}

func liftHold(dir string) error {
	h, err := evidence.ReadLegalHold(dir)
	if err != nil {
		return err
	}
	if !h.InForce {
		return errors.New("retention: no legal hold is in force")
	}
	if err := os.Remove(h.Path); err != nil {
		return fmt.Errorf("retention: release legal hold: %w", err)
	}
	fmt.Printf("legal hold released\n\n")
	fmt.Printf("  was    %s\n", strings.TrimSpace(h.Reason))
	fmt.Printf("\nRetention enforcement can delete from this directory again.\n")
	return nil
}

func printRetentionReport(r *evidence.RetentionReport) {
	fmt.Printf("retention report\n\n")
	fmt.Printf("  directory   %s\n", r.Dir)
	fmt.Printf("  policy      keep at least %d days\n", r.MinDays)
	fmt.Printf("  cutoff      %s\n", r.Cutoff)
	fmt.Printf("  records     %d in %d segment(s), %s\n", r.Records, len(r.Segments), humanBytes(r.Bytes))
	if r.OldestTime != "" {
		fmt.Printf("  window      %s\n              %s\n", r.OldestTime, r.NewestTime)
	}
	printSizeCap(sizeCap{
		Max: r.MaxBytes, Size: r.Bytes, Over: r.BytesOverCap,
		OverCap: r.OverCap, Note: r.CapNote, Held: "holding",
	})

	if r.Hold.InForce {
		fmt.Printf("\n  LEGAL HOLD IN FORCE\n")
		fmt.Printf("  reason      %s\n", strings.TrimSpace(r.Hold.Reason))
		fmt.Printf("  Nothing will be deleted while %s exists.\n", r.Hold.Path)
	}

	if len(r.Segments) > 0 {
		fmt.Printf("\n  %-22s %8s %10s  %s\n", "segment", "records", "size", "status")
		for _, s := range r.Segments {
			fmt.Printf("  %-22s %8d %10s  %s\n",
				s.Segment, s.Records, humanBytes(s.Bytes), segmentStatus(s))
		}
	}

	if len(r.Eligible) == 0 {
		fmt.Printf("\nNothing is beyond retention. No segment can be deleted.\n")
		return
	}
	fmt.Printf("\n  %d segment(s) beyond retention: %d records, %s\n",
		len(r.Eligible), r.EligibleRecords, humanBytes(r.EligibleBytes))
	if r.Hold.InForce {
		fmt.Printf("  They will not be deleted while the legal hold is in force.\n")
		return
	}
	fmt.Printf("\nTo see exactly what would be removed:\n")
	fmt.Printf("  flugschreiber retention --dir %s --enforce\n", r.Dir)
}

func segmentStatus(s evidence.SegmentStatus) string {
	switch {
	case s.Note != "":
		return s.Note
	case s.Active:
		return "being written to"
	case s.Eligible:
		return "beyond retention, eligible for deletion"
	case s.BeyondRetention:
		return "beyond retention, not eligible"
	default:
		return "within retention"
	}
}

// printEnforceResult reports one enforcement run. stopped marks a run that
// failed part way through, where the list of deleted segments is the only
// record of how far it got.
func printEnforceResult(r *evidence.EnforceResult, stopped bool) {
	switch {
	case stopped:
		fmt.Printf("RETENTION STOPPED PART WAY THROUGH\n\n")
	case r.DryRun:
		fmt.Printf("retention plan (dry run, nothing was deleted)\n\n")
	default:
		fmt.Printf("retention enforced\n\n")
	}
	fmt.Printf("  directory   %s\n", r.Dir)
	fmt.Printf("  policy      keep at least %d days\n", r.MinDays)
	fmt.Printf("  cutoff      %s\n", r.Cutoff)
	// The cap is reported on every path out of this function, including the
	// ones that delete nothing, because being over the cap and holding the line
	// is exactly the state an operator has to be told about.
	printSizeCap(sizeCap{
		Max: r.MaxBytes, Size: r.RetainedBytes, Over: r.BytesOverCap,
		OverCap: r.OverCap, Note: r.CapNote, Held: "keeping",
	})

	if r.Hold.InForce {
		fmt.Printf("\n  LEGAL HOLD IN FORCE, nothing was deleted\n")
		fmt.Printf("  reason      %s\n", strings.TrimSpace(r.Hold.Reason))
		fmt.Printf("  file        %s\n", r.Hold.Path)
		return
	}

	if len(r.Eligible) == 0 {
		fmt.Printf("\nNothing is beyond retention. No segment was deleted.\n")
		return
	}

	if stopped {
		// The record and byte totals describe the whole eligible set, so a run
		// that stopped part way through must not print them beside a shorter
		// list as though it had taken all of them. Every segment the run was
		// working through is named with what actually became of it, because
		// that list is the only account of how far it got.
		printInterruptedDeletion(r)
		return
	}

	verb := "would be deleted"
	list := r.Eligible
	if !r.DryRun {
		verb = "deleted"
		list = r.Deleted
	}
	fmt.Printf("\n  %s: %d segment(s), %d records, %s\n\n",
		verb, len(list), r.EligibleRecords, humanBytes(r.EligibleBytes))
	for _, name := range list {
		fmt.Printf("    %s\n", name)
	}

	fmt.Printf("\n  retained    %d records, %s\n", r.RetainedRecords, humanBytes(r.RetainedBytes))
	if r.LastPrunedSeq > 0 {
		fmt.Printf("  chain resumes after seq %d (%s)\n", r.LastPrunedSeq, shortHex(r.LastPrunedHash))
	}

	if r.DryRun {
		fmt.Printf("\nNothing has been deleted. To carry this out:\n")
		fmt.Printf("  flugschreiber retention --dir %s --enforce --confirm\n", r.Dir)
		return
	}

	if r.AnchorWritten {
		fmt.Printf("  anchor      pruned.json records what was removed\n")
	}
	fmt.Printf("\nThe surviving chain still verifies, and now reports itself as pruned\n")
	fmt.Printf("rather than complete from the beginning. Run:\n")
	fmt.Printf("  flugschreiber verify --dir %s\n", r.Dir)
}

// printInterruptedDeletion accounts for a run that stopped between two
// unlinks, which is the state D26 has verify report as an incomplete prune.
//
// pruned.json is written and fsynced before the first unlink, so on this path
// it already claims every segment listed here, including the ones still on
// disk. Saying which are which is what stops an operator reading the anchor as
// evidence that records are gone when they are not.
func printInterruptedDeletion(r *evidence.EnforceResult) {
	deleted := make(map[string]bool, len(r.Deleted))
	for _, name := range r.Deleted {
		deleted[name] = true
	}
	fmt.Printf("\n  deleted before it stopped: %d of %d segment(s)\n\n", len(r.Deleted), len(r.Eligible))
	for _, name := range r.Eligible {
		state := "still on disk"
		if deleted[name] {
			state = "deleted"
		}
		fmt.Printf("    %-22s %s\n", name, state)
	}
	if r.AnchorWritten {
		fmt.Printf("\n  %s already names every segment above, so the ones still on disk are\n", evidence.PruneAnchorFile)
		fmt.Printf("  what verify reports as an incomplete prune until this finishes.\n")
	}
	fmt.Printf("\nThe error this run reported says where it stopped. Fix what blocked the\n")
	fmt.Printf("deletion and run the same command again to finish it, then:\n")
	fmt.Printf("  flugschreiber verify --dir %s\n", r.Dir)
}

// sizeCap is the size-cap view the two retention outputs share. Held names
// what Size counts, which is everything for a report and what survives for an
// enforcement run.
type sizeCap struct {
	Max     int64
	Size    int64
	Over    int64
	OverCap bool
	Note    string
	Held    string
}

// printSizeCap reports the cap, never an action. The note comes from
// internal/evidence and is printed as it was written: it is the sentence that
// says why nothing further was deleted, and paraphrasing it here would let the
// two outputs disagree about a deletion decision.
func printSizeCap(c sizeCap) {
	if c.Max <= 0 {
		return
	}
	if !c.OverCap {
		fmt.Printf("  size cap    %s, %s %s, under it\n", humanBytes(c.Max), c.Held, humanBytes(c.Size))
		return
	}
	fmt.Printf("  size cap    %s, %s %s, %s OVER\n",
		humanBytes(c.Max), c.Held, humanBytes(c.Size), humanBytes(c.Over))
	if c.Note != "" {
		fmt.Printf("\n  %s\n", c.Note)
	}
}

func shortHex(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
