package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// WriterLockFile names the file an open Store holds while it owns the evidence
// directory.
//
// It serves two purposes. Operations that mutate key material or delete files
// consult it and refuse rather than working underneath a running writer. And
// Open consults it to enforce the single-writer rule, which used to be left to
// the operator: two servers on one directory both started, interleaved their
// records, and produced a chain that fails from the first concurrent append
// onwards and fails in a way that is indistinguishable from tampering. The
// damage is permanent and there is no repair, so it has to be refused rather
// than documented.
//
// A lock outlives the process that wrote it when that process is killed, and a
// proxy that will not record because of a stale file has turned a crash into an
// outage. So the refusal is conditional on the holder actually being alive; see
// claimWriterLock.
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

// claimWriterLock takes the directory for this process, or explains who has it.
//
// The three cases are different and only one of them is a refusal worth making:
//
//   - No lock, or a lock whose holder is gone. Take it. A crash must not cost
//     an outage, and the previous holder is provably not appending.
//   - A lock whose holder is alive on this host. Refuse. This is the case that
//     corrupts the chain, and the operator can see both processes.
//   - A lock from another host. Refuse, because liveness cannot be checked
//     across a shared volume and guessing wrong corrupts the log permanently.
//     This is the case force is for.
//
// force skips the refusal for an operator who knows the holder is gone and
// cannot prove it to us, which is the shared-volume case after a node failure.
func claimWriterLock(dir string, force bool) error {
	held := ReadWriterLock(dir)
	if held != nil && !force {
		host, _ := os.Hostname()
		switch {
		case held.PID == 0:
			return fmt.Errorf(
				"evidence: %s exists but names no process, so this directory may already have a writer; "+
					"stop any running server, then remove %s or start with --force-writer-lock",
				WriterLockFile, filepath.Join(dir, WriterLockFile))
		case held.Host != "" && host != "" && held.Host != host:
			return fmt.Errorf(
				"evidence: %s is held by %s and this is %s, so whether it is still writing cannot be checked from here; "+
					"two writers on one directory break the chain permanently. Confirm the other host is stopped, then start with --force-writer-lock",
				WriterLockFile, held, host)
		case processAlive(held.PID):
			return fmt.Errorf(
				"evidence: %s is held by %s, which is still running; two writers on one directory interleave records and break the chain permanently. "+
					"Stop it first, or point this server at a different --data-dir",
				WriterLockFile, held)
		}
	}
	return writeWriterLock(dir)
}

// processAlive reports whether pid is a process this host still has. It answers
// conservatively: anything it cannot determine counts as alive, because a wrong
// "dead" lets a second writer in and a wrong "alive" costs one manual override.
func processAlive(pid int) bool {
	if pid <= 0 {
		return true
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		// Windows reports a missing process here. Unix never does.
		return false
	}
	err = p.Signal(syscall.Signal(0))
	switch {
	case err == nil:
		return true
	case errors.Is(err, os.ErrProcessDone):
		return false
	case errors.Is(err, os.ErrPermission):
		// Somebody else's process, which means it exists.
		return true
	default:
		// A platform that does not implement signal probing, or an error we do
		// not recognise. Assume the holder is alive and make the operator say
		// otherwise.
		return true
	}
}

// writeWriterLock records this process as the holder.
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
