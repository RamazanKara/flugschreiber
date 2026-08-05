package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/archive"
	"github.com/RamazanKara/flugschreiber/internal/archivecheck"
	"github.com/RamazanKara/flugschreiber/internal/config"
)

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
		dir        = fs.String("dir", "", "evidence directory the archive was made from (or FLUGSCHREIBER_DATA_DIR)")
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
	if err := resolveDir(fs, "archive-verify", dir); err != nil {
		return err
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

	res, err := archivecheck.Verify(context.Background(), reader, *dir, cfg.Archive.Prefix, *deep)
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
func openArchiveReader(cfg config.Archive) (archivecheck.Reader, error) {
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

// archiveVerifyFailure turns the counts into the one sentence an operator
// reads first, naming the keys rather than only counting them.
func archiveVerifyFailure(res *archivecheck.VerifyResult) error {
	var parts []string
	if res.Missing > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) missing from the archive (%s)",
			res.Missing, namedKeys(res, archivecheck.StatusMissing)))
	}
	if res.Mismatched > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) differ from the local evidence (%s)",
			res.Mismatched, namedKeys(res, archivecheck.StatusMismatch)))
	}
	if res.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d object(s) could not be checked at all (%s)",
			res.Unknown, namedKeys(res, archivecheck.StatusUnknown)))
	}
	return fmt.Errorf("archive-verify: %s", strings.Join(parts, "; "))
}

// namedKeys lists the keys in one state, up to a few, so that an error line
// stays an error line.
func namedKeys(res *archivecheck.VerifyResult, status string) string {
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

func printArchiveVerify(res *archivecheck.VerifyResult) {
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
			if o.Status == archivecheck.StatusPresent {
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
		if o.Status != archivecheck.StatusPresent || o.Detail == "" {
			continue
		}
		switch o.Kind {
		case archivecheck.KindCheckpoints, archivecheck.KindOpenSegment, archivecheck.KindPrunedSegment:
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
