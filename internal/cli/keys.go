package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

const keysUsage = `Usage: flugschreiber keys <subcommand> [flags]

Subcommands:
  list    Show the active checkpoint signing key and every key rotation retired
  rotate  Replace the signing key, keeping the old public half
  retire  File a public key under keys/ so its checkpoints stay verifiable

A rotation retires the old public key to keys/retired-<key id>.pem before it
touches anything else. Every checkpoint already on disk was signed with that
key, so a rotation that discarded it would make the log's own history
unverifiable. The old private key is gone once rotation finishes: nothing on
this host can sign under it again, which is the point of rotating.

With an external signer the rotation happens at the helper, where this command
cannot reach the private key. Retire the old public key first, then point
signer_public_key at the new one; without that step every checkpoint signed
before the change is attributed to a key this directory no longer holds and
verify reports it as unverifiable, permanently.

Rotation needs the server stopped. It refuses while a writer holds the
directory, because one writer and one total order is an operational rule this
tool cannot enforce from the outside.

Run "flugschreiber keys <subcommand> -h" for the flags of a subcommand.
`

// Keys shows or rotates the checkpoint signing key.
func Keys(args []string) error {
	if len(args) == 0 {
		fmt.Print(keysUsage)
		return errors.New("keys: a subcommand is required, one of list, retire or rotate")
	}
	switch args[0] {
	case "list":
		return keysList(args[1:])
	case "retire":
		return keysRetire(args[1:])
	case "rotate":
		return keysRotate(args[1:])
	case "-h", "--help", "help":
		fmt.Print(keysUsage)
		return nil
	default:
		fmt.Print(keysUsage)
		return fmt.Errorf("keys: unknown subcommand %q, expected list or rotate", args[0])
	}
}

// keysListResult is what "keys list" found. Every key a verifier will accept
// is in here, which is the question the command exists to answer.
type keysListResult struct {
	Dir     string              `json:"dir"`
	Active  *evidence.KnownKey  `json:"active,omitempty"`
	Retired []evidence.KnownKey `json:"retired,omitempty"`
	Broken  []brokenKeyFile     `json:"unreadable,omitempty"`
	Signer  string              `json:"signer,omitempty"`
	Signing string              `json:"signing"`
}

// brokenKeyFile is a key file that exists and cannot be used. It is reported
// rather than returned as an error, because the readable keys still verify
// everything they signed.
type brokenKeyFile struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

func keysList(args []string) error {
	fs := flag.NewFlagSet("keys list", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber keys list --dir DIR [flags]

Lists every public key a verifier in this directory will accept: the active
one in public-key.pem and every key a rotation has retired into keys/.

A retired key is kept forever and never signs again. Checkpoints written
before its rotation are still checked against it, so removing one would strand
that part of the log, not tidy it up.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir        = fs.String("dir", "", "evidence directory (or FLUGSCHREIBER_DATA_DIR)")
		configPath = fs.String("config", "", "JSON config file, read to report how signing is configured")
		asJSON     = fs.Bool("json", false, "emit the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "keys list", dir); err != nil {
		return err
	}
	cfg, err := commandConfig(*configPath)
	if err != nil {
		return err
	}

	ks := evidence.LoadKeySet(*dir)
	if len(ks.Keys) == 0 && len(ks.Unreadable) == 0 {
		return fmt.Errorf(
			"keys list: %s holds no %s and no retired key in %s/; %s",
			*dir, evidence.PublicKeyFile, evidence.RetiredKeysDir, noKeyExplanation(cfg))
	}

	res := keysListResult{Dir: *dir, Signing: signingDescription(cfg)}
	if cfg.Signer != "" {
		res.Signer = cfg.Signer
	}
	if current, ok := ks.Current(); ok {
		res.Active = &current
	}
	for _, k := range ks.Keys {
		if k.Retired {
			res.Retired = append(res.Retired, k)
		}
	}
	for _, u := range ks.Unreadable {
		res.Broken = append(res.Broken, brokenKeyFile{File: u.Source, Error: u.Err.Error()})
	}

	if *asJSON {
		return emitJSON(res)
	}
	printKeysList(res)
	return nil
}

func printKeysList(res keysListResult) {
	fmt.Printf("checkpoint signing keys\n\n")
	fmt.Printf("  directory   %s\n", res.Dir)
	if res.Active != nil {
		fmt.Printf("  active      %s  %s\n", res.Active.ID, res.Active.Source)
	} else {
		fmt.Printf("  active      none; nothing in this directory signs checkpoints now\n")
	}
	for i, k := range res.Retired {
		label := "retired"
		if i > 0 {
			label = ""
		}
		fmt.Printf("  %-10s  %s  %s\n", label, k.ID, k.Source)
	}
	if res.Signer != "" {
		fmt.Printf("  signer      %s; the private key is held there, not here\n", res.Signer)
	}

	if len(res.Broken) > 0 {
		fmt.Printf("\n  unreadable\n\n")
		for _, b := range res.Broken {
			fmt.Printf("    %s: %s\n", b.File, b.Error)
		}
		fmt.Printf("\n  A checkpoint signed by a key that cannot be read here is reported by\n")
		fmt.Printf("  verify as signed by an unknown key. Restore the file from a backup or\n")
		fmt.Printf("  from an export bundle rather than deleting it.\n")
	}

	if len(res.Retired) == 0 {
		return
	}
	fmt.Printf("\nA retired key never signs again and is kept forever, so every checkpoint\n")
	fmt.Printf("written before its rotation still verifies.\n")
}

func keysRotate(args []string) error {
	fs := flag.NewFlagSet("keys rotate", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber keys rotate --dir DIR [flags]

Generates a new Ed25519 signing key for an evidence directory.

The old public key is copied to keys/retired-<old key id>.pem first, so that
every checkpoint signed under it stays verifiable; the old private key is then
replaced and is gone from the host. The rotation itself is appended to the
chain as a config_change event naming both key ids, so the log documents its
own custody history instead of leaving it to be inferred from file dates.

Stop the server first. Rotation refuses while a writer holds the directory.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		dir        = fs.String("dir", "", "evidence directory (or FLUGSCHREIBER_DATA_DIR)")
		configPath = fs.String("config", "", "JSON config file, read to refuse a rotation that would change nothing")
		asJSON     = fs.Bool("json", false, "emit the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "keys rotate", dir); err != nil {
		return err
	}
	cfg, err := commandConfig(*configPath)
	if err != nil {
		return err
	}
	if err := refuseRotationWithoutALocalKey(cfg); err != nil {
		return err
	}

	// A rotation that fails to record itself has still replaced the key, and
	// RotateKey returns the result in that case precisely so the operator can
	// be told which key is now in force. Reporting it before the error is what
	// keeps them from rotating a second time to "fix" it.
	res, err := evidence.RotateKey(*dir)
	if res == nil {
		return err
	}
	if *asJSON {
		// A failed write to stdout must not displace the rotation error: which
		// key is in force, and whether the chain records the change, outranks
		// the fate of this run's output.
		if jsonErr := emitJSON(res); jsonErr != nil && err == nil {
			return jsonErr
		}
	} else {
		printRotation(res)
	}
	return err
}

func printRotation(res *evidence.RotationResult) {
	fmt.Printf("signing key rotated\n\n")
	fmt.Printf("  directory   %s\n", res.Dir)
	fmt.Printf("  old key     %s  retired to %s\n", res.OldKeyID, res.RetiredKeyFile)
	fmt.Printf("  new key     %s  %s\n", res.NewKeyID, evidence.PublicKeyFile)
	fmt.Printf("  rotated at  %s\n", res.RotatedAt)
	if res.RecordSeq > 0 {
		fmt.Printf("  recorded    config_change at seq %d\n", res.RecordSeq)
	}
	fmt.Printf("\nThe retired public key stays in this directory forever. Checkpoints signed\n")
	fmt.Printf("before this rotation verify against it; nothing on this host can produce\n")
	fmt.Printf("another signature under it.\n")
}

// refuseRotationWithoutALocalKey stops a rotation that would not rotate what
// the operator thinks it rotates. Both cases end with the same key still
// signing checkpoints, so both are refused rather than reported afterwards.
func refuseRotationWithoutALocalKey(cfg config.Config) error {
	if strings.HasPrefix(cfg.Signer, config.SignerExecPrefix) {
		return fmt.Errorf(
			"keys rotate: checkpoints are signed by the external helper %q, so the private key is not in this directory and this command cannot reach it; rotate it wherever the helper keeps it, run \"flugschreiber keys retire --dir DIR --key <old public key>\" so the checkpoints it already signed stay verifiable, and only then point signer_public_key at the new key",
			strings.TrimPrefix(cfg.Signer, config.SignerExecPrefix))
	}
	if cfg.SigningDisabled {
		return errors.New(
			"keys rotate: this configuration has signing switched off, so there is no key in use to replace; a directory gets its signing key from a server started without --no-sign")
	}
	return nil
}

// signingDescription says how checkpoints are signed under this configuration,
// so that a list of key files is not read as proof that they are in use.
func signingDescription(cfg config.Config) string {
	switch {
	case cfg.SigningDisabled:
		return "disabled"
	case strings.HasPrefix(cfg.Signer, config.SignerExecPrefix):
		return "external signer"
	default:
		return "built-in key"
	}
}

// noKeyExplanation names the reason there is no key, when the configuration
// states one, and otherwise gives both possibilities rather than guessing.
func noKeyExplanation(cfg config.Config) string {
	switch {
	case cfg.SigningDisabled:
		return "signing is switched off in this configuration, so nothing here signs checkpoints and the chain proves internal consistency only"
	case strings.HasPrefix(cfg.Signer, config.SignerExecPrefix):
		return fmt.Sprintf(
			"checkpoints are signed by the external helper %q, whose public key is configured as %q rather than kept here",
			strings.TrimPrefix(cfg.Signer, config.SignerExecPrefix), cfg.SignerPublicKey)
	default:
		return "either no server has ever recorded here, or the one that did ran with --no-sign, in which case the chain proves internal consistency only"
	}
}

// keysRetire files a public key under keys/ so its checkpoints stay verifiable.
func keysRetire(args []string) error {
	fs := flag.NewFlagSet("keys retire", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: flugschreiber keys retire --dir DIR --key FILE

Files a public key under keys/retired-<key id>.pem, so that checkpoints signed
with it stay verifiable after it stops being the active key.

This is the step an external-signer rotation needs. The private key lives at the
helper, so "keys rotate" cannot reach it and refuses; the operator rotates it
there and repoints signer_public_key. Without retiring the old public key first,
every checkpoint signed before the change is attributed to a key this directory
no longer holds, and verify reports it as unverifiable from then on.

  flugschreiber keys retire --dir DIR --key ./old-public-key.pem

Retiring a key already on file is not an error and changes nothing, so this is
safe to put in a runbook. It refuses while a writer holds the directory.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		dir    = fs.String("dir", "", "evidence directory (or FLUGSCHREIBER_DATA_DIR)")
		key    = fs.String("key", "", "PEM public key to retire (required)")
		asJSON = fs.Bool("json", false, "emit the result as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := resolveDir(fs, "keys retire", dir); err != nil {
		return err
	}
	if *key == "" {
		fs.Usage()
		return errors.New("keys retire: --key is required")
	}

	res, err := evidence.RetirePublicKey(*dir, *key)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitJSON(res)
	}
	if res.Existing {
		fmt.Printf("key %s was already retired\n\n", res.KeyID)
	} else {
		fmt.Printf("key retired\n\n")
	}
	fmt.Printf("  directory   %s\n", *dir)
	fmt.Printf("  key id      %s\n", res.KeyID)
	fmt.Printf("  kept at     %s\n", res.Path)
	fmt.Printf("\nCheckpoints signed with this key verify against that file. It stays in the\n")
	fmt.Printf("directory permanently and travels with every export.\n")
	return nil
}
