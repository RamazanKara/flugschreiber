package cli

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// repairReport is what the command did, or would do.
type repairReport struct {
	Dir        string               `json:"directory"`
	DryRun     bool                 `json:"dry_run"`
	Torn       *evidence.TornRecord `json:"torn_record,omitempty"`
	Repaired   bool                 `json:"repaired"`
	RecordedAt string               `json:"recorded_at,omitempty"`
	Seq        uint64               `json:"system_event_seq,omitempty"`
}

// Repair finishes a write the machine did not.
func Repair(args []string) error {
	fs := flag.NewFlagSet("repair", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber repair --dir DIR [--confirm]

Removes a partial final record left by a write that did not finish, which is
what a power loss or a full disk leaves inside the one-second fsync window.
Until it is removed the server refuses to start, because the chain head cannot
be established, and every interaction after that point goes unrecorded.

  flugschreiber repair --dir DIR             say what would be removed
  flugschreiber repair --dir DIR --confirm   remove it

The fragment is not a record. It never completed, nothing counted it, no hash
covers it and no checkpoint attests to it, so removing it destroys nothing that
was ever evidence. Only the final line of the newest segment is ever touched;
damage anywhere else was not caused by an interrupted append and this command
will not edit it.

The repair is appended to the chain as a system_event naming the segment, the
offset and the byte count, so the log carries its own account of what was
removed rather than quietly being shorter than it was.

Stop the server first. This refuses while a writer holds the directory.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir     = fs.String("dir", "", "evidence directory (required)")
		confirm = fs.Bool("confirm", false, "carry out the repair")
		asJSON  = fs.Bool("json", false, "emit the result as JSON")
		actor   = fs.String("actor", "", "who carried out the repair, recorded in the chain")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		fs.Usage()
		return errors.New("repair: --dir is required")
	}

	torn, err := evidence.FindTornRecord(*dir)
	if err != nil {
		return err
	}
	out := repairReport{Dir: *dir, DryRun: !*confirm, Torn: torn}

	if torn == nil {
		if *asJSON {
			return emitJSON(out)
		}
		fmt.Printf("nothing to repair\n\n")
		fmt.Printf("  directory   %s\n", *dir)
		fmt.Printf("\nThe newest segment ends on a record boundary. If the server still refuses to\n")
		fmt.Printf("start, the damage is not an interrupted write; run flugschreiber verify --dir %s\n", *dir)
		fmt.Printf("to see what it is.\n")
		return nil
	}

	if !*confirm {
		if *asJSON {
			return emitJSON(out)
		}
		printTorn(torn)
		fmt.Printf("\nNothing has been changed. Re-run with --confirm to remove the fragment.\n")
		return nil
	}

	removed, err := evidence.Repair(*dir)
	if err != nil {
		return err
	}
	out.Repaired = removed != nil
	out.Torn = removed

	// The chain records its own repair. A log that silently loses bytes is the
	// thing this project exists to make impossible, and that applies to bytes
	// this command removes as much as to bytes an attacker does.
	seq, err := recordRepair(*dir, removed, *actor)
	if err != nil {
		return fmt.Errorf("the fragment was removed but the repair could not be recorded in the chain: %w", err)
	}
	out.Seq = seq
	out.RecordedAt = time.Now().UTC().Format(time.RFC3339)

	if *asJSON {
		return emitJSON(out)
	}
	fmt.Printf("repaired\n\n")
	printTorn(removed)
	fmt.Printf("  recorded    system_event at seq %d\n", seq)
	fmt.Printf("\nThe server can start again. The chain is unchanged before the fragment, and\n")
	fmt.Printf("the record above says what was removed and when.\n")
	return nil
}

func printTorn(t *evidence.TornRecord) {
	fmt.Printf("  segment     %s\n", t.Segment)
	fmt.Printf("  fragment    %d byte(s) at offset %d, line %d\n", t.Bytes, t.Offset, t.Line)
	fmt.Printf("  parse error %s\n", t.Detail)
	if t.Preview != "" {
		fmt.Printf("  bytes       %s\n", t.Preview)
	}
}

// recordRepair appends the system_event describing what was removed.
func recordRepair(dir string, torn *evidence.TornRecord, actor string) (uint64, error) {
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		return 0, err
	}
	note := fmt.Sprintf(
		"repaired a partial final record: %d byte(s) at offset %d of %s, left by a write that did not finish. "+
			"The fragment was never a complete record, so no hash or checkpoint covered it.",
		torn.Bytes, torn.Offset, torn.Segment)
	ev := &evidence.Event{
		EventType: evidence.EventSystemEvent,
		Actor:     actor,
		Note:      note,
	}
	if err := store.Append(ev); err != nil {
		// The append failed, so the close error is the lesser of two and the
		// caller needs the one that says the repair went unrecorded.
		_ = store.Close()
		return 0, err
	}
	if err := store.Close(); err != nil {
		return 0, err
	}
	return store.Appended(), nil
}
