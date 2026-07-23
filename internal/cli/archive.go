package cli

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/archive"
	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// buildArchiver turns the archive configuration into a backend, or returns nil
// when archival is switched off.
//
// The key prefix is applied by the evidence store and never by the backend.
// Both can prepend one, and setting both would concatenate them into a path
// nobody intended, so exactly one owns it.
func buildArchiver(cfg config.Config, log *slog.Logger) (evidence.Archiver, error) {
	switch cfg.Archive.Backend {
	case "", config.ArchiveNone:
		return nil, nil

	case config.ArchiveDir:
		if cfg.Archive.Dir == "" {
			return nil, fmt.Errorf("config: archive backend %q needs archive.dir", config.ArchiveDir)
		}
		dir, err := archive.NewDir(cfg.Archive.Dir)
		if err != nil {
			return nil, fmt.Errorf("config: archive to %s: %w", cfg.Archive.Dir, err)
		}
		log.Info("archiving sealed segments",
			slog.String("backend", dir.Name()),
			slog.String("target", cfg.Archive.Dir))
		return dir, nil

	case config.ArchiveS3:
		if cfg.Archive.Bucket == "" {
			return nil, fmt.Errorf("config: archive backend %q needs archive.bucket", config.ArchiveS3)
		}
		client, err := archive.NewS3(archive.Config{
			Bucket:     cfg.Archive.Bucket,
			Region:     cfg.Archive.Region,
			Endpoint:   cfg.Archive.Endpoint,
			Addressing: cfg.Archive.Addressing,
			Credentials: archive.Credentials{
				AccessKeyID:     cfg.Archive.AccessKeyID,
				SecretAccessKey: cfg.Archive.SecretAccessKey,
				SessionToken:    cfg.Archive.SessionToken,
			},
			StorageClass:        cfg.Archive.StorageClass,
			SSE:                 cfg.Archive.SSE,
			SSEKMSKeyID:         cfg.Archive.SSEKMSKeyID,
			ObjectLockMode:      cfg.Archive.ObjectLockMode,
			ObjectLockRetainFor: time.Duration(cfg.Archive.ObjectLockRetainFor),
		})
		if err != nil {
			return nil, fmt.Errorf("config: archive to s3: %w", err)
		}
		log.Info("archiving sealed segments",
			slog.String("backend", client.Name()),
			slog.String("bucket", cfg.Archive.Bucket),
			slog.String("prefix", cfg.Archive.Prefix),
			slog.String("object_lock", cfg.Archive.ObjectLockMode))
		return client, nil

	default:
		return nil, fmt.Errorf(
			"config: archive backend %q must be one of %s, %s or %s",
			cfg.Archive.Backend, config.ArchiveNone, config.ArchiveDir, config.ArchiveS3)
	}
}
