package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/RamazanKara/flugschreiber/internal/config"
)

// commandConfig assembles the configuration a read-only command needs: the
// file when one is named, then the environment. It is deliberately not
// validated: a command that reads an evidence directory has no upstream and no
// listen address, and refusing to list a key because no model server is
// configured would be absurd.
func commandConfig(path string) (config.Config, error) {
	cfg := config.Default()
	if path != "" {
		if err := cfg.LoadFile(path); err != nil {
			return cfg, err
		}
	}
	if err := cfg.ApplyEnv(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// resolveDir fills an empty --dir from FLUGSCHREIBER_DATA_DIR, the same
// variable serve reads for --data-dir, so one exported name serves the whole
// binary. The flag wins when both are given, which is the layering the
// stability contract promises. With neither set, the command shows its usage
// and refuses.
func resolveDir(fs *flag.FlagSet, command string, dir *string) error {
	if *dir != "" {
		return nil
	}
	if v := os.Getenv(config.EnvPrefix + "DATA_DIR"); v != "" {
		*dir = v
		return nil
	}
	fs.Usage()
	return fmt.Errorf("%s: --dir is required, or set %sDATA_DIR", command, config.EnvPrefix)
}

func setString(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
