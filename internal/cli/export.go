package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/audit"
	"github.com/RamazanKara/flugschreiber/internal/version"
)

// Export writes an evidence bundle a third party can verify on their own
// machine.
func Export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber export [flags]

Writes a self-contained evidence bundle: the log segments, the signed
checkpoints, the public key, a manifest of SHA-256 digests, and instructions a
recipient can follow without knowing anything about this tool.

The signing key and the client identity salt are never included, so a recipient
can verify everything and reverse nothing.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir  = fs.String("dir", "", "evidence directory to export (or FLUGSCHREIBER_DATA_DIR)")
		out  = fs.String("out", "", "path to write the bundle to (required)")
		note = fs.String("note", "", "a note to include in the bundle for its recipient")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "export", dir); err != nil {
		return err
	}
	if *out == "" {
		fs.Usage()
		return errors.New("export: --out is required")
	}

	res, err := audit.Export(audit.ExportOptions{
		ToolVersion: version.String(),
		Dir:         *dir, Out: *out, Note: *note, Now: time.Now,
	})
	if err != nil {
		return err
	}

	m := res.Manifest

	// When the bundle itself is going to stdout, the summary cannot also go
	// there: the two interleave and the recipient gets an archive with prose
	// in the middle of it. Streaming out of a distroless pod is the shape the
	// Kubernetes handover uses, so it has to be the one that works.
	w := os.Stdout
	if isStreamPath(*out) {
		w = os.Stderr
	}
	fmt.Fprintf(w, "wrote %s\n\n", res.Path)
	fmt.Fprintf(w, "  files       %d (%s)\n", len(m.Files), humanBytes(m.TotalBytes))
	fmt.Fprintf(w, "  records     %d (sequence %d to %d)\n", m.Records, m.FirstSeq, m.LastSeq)
	if m.FirstRecord != "" {
		fmt.Fprintf(w, "  window      %s\n              %s\n", m.FirstRecord, m.LastRecord)
	}
	fmt.Fprintf(w, "  head hash   %s\n", m.HeadHash)
	if m.Checkpoints > 0 {
		fmt.Fprintf(w, "  checkpoints %d signed\n", m.Checkpoints)
	} else {
		fmt.Fprintf(w, "  checkpoints none; the chain shows internal consistency only\n")
	}
	if n := len(m.RetiredKeys); n > 0 {
		fmt.Fprintf(w, "  keys        %d retired public key(s) carried, so checkpoints signed before a rotation still verify\n", n)
	}
	if m.Timestamps > 0 {
		fmt.Fprintf(w, "  anchors     %d RFC 3161 token(s)\n", m.Timestamps)
	}
	if m.SealedRecords > 0 {
		fmt.Fprintf(w, "  sealed      %d record(s) carry encrypted content; the keys are not in the bundle\n", m.SealedRecords)
	}
	if m.Pruned {
		fmt.Fprintf(w, "  pruned      yes; pruned.json records what was removed and why\n")
	}
	if m.ChainVerified {
		fmt.Fprintf(w, "  integrity   verified intact at export\n")
	} else {
		fmt.Fprintf(w, "  integrity   FAILED at export, %d problem(s) recorded in the manifest\n", len(m.Problems))
	}

	fmt.Fprintf(w, "\nThe bundle contains no signing key, no client salt and no content keys.\n")
	return nil
}

// isStreamPath reports whether --out names a stream rather than a file to
// create. It mirrors the rule in internal/audit, deliberately by repeating it
// rather than exporting one: this decides where prose goes and that one decides
// how bytes are written, and they should be free to diverge.
func isStreamPath(out string) bool {
	return out == "-" || out == os.DevNull || strings.HasPrefix(filepath.ToSlash(out), "/dev/")
}
