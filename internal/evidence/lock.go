package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriterLockFile names the file an open Store leaves behind it in the evidence
// directory.
//
// It is advisory and it is deliberately not a mutual exclusion mechanism. Two
// writers in one directory is not a race this package tries to arbitrate, it is
// an operational error the design forbids outright (one writer, one total
// order). What the file is for is the opposite direction: operations that
// mutate key material or delete files can see that a writer holds the
// directory and refuse, instead of doing half of something underneath it.
const WriterLockFile = "writer.lock"

// WriterLock is what an open Store records about itself, so that a refusal can
// name the process an operator has to stop.
type WriterLock struct {
	PID       int    `json:"pid"`
	Host      string `json:"host,omitempty"`
	StartedAt string `json:"started_at"`
}

// String renders the lock for an error message.
func (l WriterLock) String() string {
	switch {
	case l.PID == 0:
		return "an unidentified writer"
	case l.Host == "":
		return fmt.Sprintf("process %d, started %s", l.PID, l.StartedAt)
	default:
		return fmt.Sprintf("process %d on %s, started %s", l.PID, l.Host, l.StartedAt)
	}
}

// ReadWriterLock returns the lock held on dir, or nil when no writer has
// claimed it.
//
// It reports no error, because it has no failure to report: a file that exists
// but cannot be read or parsed is a lock held by an unidentified writer, not an
// absent lock. The caller is about to delete a key or a segment, and the safe
// reading of a damaged lock file is that somebody is writing.
func ReadWriterLock(dir string) *WriterLock {
	raw, err := os.ReadFile(filepath.Join(dir, WriterLockFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return &WriterLock{}
	}
	var l WriterLock
	if err := json.Unmarshal(raw, &l); err != nil {
		return &WriterLock{}
	}
	return &l
}

// writeWriterLock claims dir for this process. It replaces a lock left behind
// by a process that died rather than refusing to start: a proxy that will not
// record because of a stale file has turned a crash into an outage, and the
// single-writer rule is an operational guarantee rather than one this file can
// enforce.
func writeWriterLock(dir string) error {
	host, _ := os.Hostname()
	body, err := json.Marshal(WriterLock{
		PID:       os.Getpid(),
		Host:      host,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("evidence: marshal %s: %w", WriterLockFile, err)
	}
	body = append(body, '\n')
	if err := atomicWriteFile(filepath.Join(dir, WriterLockFile), body, 0o644); err != nil {
		return fmt.Errorf("evidence: write %s: %w", WriterLockFile, err)
	}
	return nil
}

// removeWriterLock releases the claim. A failure here is not worth reporting:
// the next Open replaces the file, and every operation that consults it names
// the file so that an operator can remove a stale one.
func removeWriterLock(dir string) {
	_ = os.Remove(filepath.Join(dir, WriterLockFile))
}

// refuseWhileWriterHolds is the guard in front of every operation that mutates
// key material. It names what to stop and, because a lock can outlive the
// process that wrote it, what to remove if nothing is running.
func refuseWhileWriterHolds(dir, operation string) error {
	lock := ReadWriterLock(dir)
	if lock == nil {
		return nil
	}
	return fmt.Errorf(
		"evidence: refusing to %s while %s holds %s: stop the server first, and if nothing is running remove %s",
		operation, lock, dir, filepath.Join(dir, WriterLockFile))
}
