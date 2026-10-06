// Package archive copies sealed evidence files to a second, independent
// location.
//
// It is deliberately not on the write path. The evidence log is append-only
// JSONL and object stores cannot append, so a segment is uploaded only once
// rotation has sealed it and it will never change again. That restriction is
// what makes an object-lock (WORM) bucket a usable target: every object this
// package writes is final at the moment it is written, so a retention period
// can be attached to it.
package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// MaxKeyBytes is the S3 key length limit. The filesystem backend enforces it
// too, so that a layout which works locally also works against a bucket.
const MaxKeyBytes = 1024

// ErrNotFound reports that a key names no object in the archive. Get wraps it,
// so a deep archive verification can tell a genuinely missing object from a
// backend that is only unreachable: the first is a gap in the archive, the
// second is a gap in the check, and the two call for opposite responses.
var ErrNotFound = errors.New("archive: object not found")

// CleanKey validates an object key and returns it in canonical form.
//
// Keys come from segment file names, so this is not defending against a hostile
// caller so much as making sure a mistake in the calling code cannot escape the
// archive root on the filesystem backend or produce a key that only one of the
// two backends accepts.
func CleanKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("archive: empty object key")
	}
	if len(key) > MaxKeyBytes {
		return "", fmt.Errorf("archive: object key is %d bytes, over the %d byte limit", len(key), MaxKeyBytes)
	}
	if !utf8.ValidString(key) {
		return "", errors.New("archive: object key is not valid UTF-8")
	}
	if strings.Contains(key, `\`) {
		return "", fmt.Errorf("archive: object key %q contains a backslash; use '/' as the separator", key)
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("archive: object key %q contains a control character", key)
		}
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("archive: object key %q must be relative", key)
	}
	for _, seg := range strings.Split(key, "/") {
		switch seg {
		case "":
			return "", fmt.Errorf("archive: object key %q has an empty path element", key)
		case ".", "..":
			return "", fmt.Errorf("archive: object key %q must not contain %q", key, seg)
		}
	}
	return key, nil
}

// JoinKey combines a prefix and a key, tolerating a prefix written with or
// without a trailing slash.
func JoinKey(prefix, key string) string {
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

// Dir archives to a directory on a filesystem, which is the useful backend
// when the second location is a mounted volume, an NFS share or a device that
// is swapped out and taken off site. It is also what makes the interface
// testable without a network.
//
// Writes are atomic: the object appears under its final name only once every
// byte of it is on disk, so a crash mid-upload leaves no half-file that a
// later run would mistake for a complete one.
type Dir struct {
	root string
}

// NewDir prepares root as an archive directory, creating it if needed.
func NewDir(root string) (*Dir, error) {
	if root == "" {
		return nil, errors.New("archive: a directory archive needs a root path")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("archive: resolve %s: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, fmt.Errorf("archive: create archive directory %s: %w", abs, err)
	}
	return &Dir{root: abs}, nil
}

// Name returns the backend kind.
func (d *Dir) Name() string { return "dir" }

// Target is the destination, for log lines and for the operator-facing part of
// an error. Unlike Name it is not safe to use as a metric label.
func (d *Dir) Target() string { return d.root }

// Put writes body to key. The content type is dropped, because a filesystem
// has nowhere to keep it and inventing a sidecar file to hold it would make
// the archive harder to read, not easier.
func (d *Dir) Put(ctx context.Context, key string, body io.Reader, size int64, _ string) error {
	clean, err := CleanKey(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	dst := filepath.Join(d.root, filepath.FromSlash(clean))
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("archive: create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return fmt.Errorf("archive: create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// The partial file is removed on every path that does not reach the
	// rename, so a failed upload leaves the archive as it was.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	n, err := io.Copy(tmp, &ctxReader{ctx: ctx, r: body})
	if err != nil {
		return fmt.Errorf("archive: write %s: %w", clean, err)
	}
	if size >= 0 && n != size {
		return fmt.Errorf("archive: %s: read %d bytes but %d were declared", clean, n, size)
	}
	if err := tmp.Chmod(0o640); err != nil {
		return fmt.Errorf("archive: set mode on %s: %w", clean, err)
	}
	// fsync before the rename, so that the name never appears over content the
	// kernel has not written yet.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("archive: sync %s: %w", clean, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("archive: close %s: %w", clean, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("archive: publish %s: %w", clean, err)
	}
	syncDir(dir)
	return nil
}

// Exists reports whether key is present as a regular file.
func (d *Dir) Exists(ctx context.Context, key string) (bool, error) {
	clean, err := CleanKey(key)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	info, err := os.Stat(filepath.Join(d.root, filepath.FromSlash(clean)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("archive: stat %s: %w", clean, err)
	}
	return info.Mode().IsRegular(), nil
}

// Get opens the object stored under key for reading. It is the os.Open behind a
// deep archive verification, which reads the archived bytes back to compare
// them against the local segment. The caller closes the returned reader.
//
// A key that names no object returns an error satisfying
// errors.Is(err, ErrNotFound), the same sentinel the S3 backend returns for a
// 404, so a caller checking one archive kind checks them all the same way.
func (d *Dir) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	clean, err := CleanKey(key)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(d.root, filepath.FromSlash(clean)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("archive: get %s: %w", clean, ErrNotFound)
		}
		return nil, fmt.Errorf("archive: open %s: %w", clean, err)
	}
	return f, nil
}

// syncDir durably records the rename. It is best effort because directory
// fsync is not available on every platform this builds for, and the rename is
// already atomic: the cost of losing it in a machine crash is that the segment
// is uploaded again on the next run.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer f.Close()
	_ = f.Sync()
}

// ctxReader aborts a long copy when the caller gives up. An archive upload can
// be tens of megabytes over a slow link, and shutdown should not have to wait
// for it.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
