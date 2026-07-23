package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"sync"
)

// tap observes a byte stream as it passes through, hashing all of it and
// retaining a bounded prefix. Hashing the full stream while buffering only a
// prefix is what lets Flugschreiber attest to a 100 MB request without holding
// it in memory.
type tap struct {
	mu    sync.Mutex
	h     hash.Hash
	buf   bytes.Buffer
	max   int
	n     int64
	trunc bool
}

func newTap(max int) *tap {
	return &tap{h: sha256.New(), max: max}
}

func (t *tap) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.h.Write(p)
	t.n += int64(len(p))
	if room := t.max - t.buf.Len(); room > 0 {
		if len(p) <= room {
			t.buf.Write(p)
		} else {
			t.buf.Write(p[:room])
			t.trunc = true
		}
	} else if len(p) > 0 {
		t.trunc = true
	}
	return len(p), nil
}

// snapshot returns the digest, byte count and retained prefix observed so far.
func (t *tap) snapshot() (sum string, n int64, prefix []byte, truncated bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return hex.EncodeToString(t.h.Sum(nil)), t.n, bytes.Clone(t.buf.Bytes()), t.trunc
}

// teeReadCloser copies everything read from rc into w, and reports the read
// error (if any other than EOF) to the finalizer.
type teeReadCloser struct {
	rc  io.ReadCloser
	w   io.Writer
	err error

	onClose func(readErr error)
	once    sync.Once
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.w.Write(p[:n])
	}
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

func (t *teeReadCloser) Close() error {
	err := t.rc.Close()
	if t.onClose != nil {
		t.once.Do(func() { t.onClose(t.err) })
	}
	return err
}
