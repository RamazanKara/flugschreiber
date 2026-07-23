//go:build windows

package acceptance_test

import (
	"os/exec"
	"syscall"
)

// configureServe puts the child in its own process group, which is what makes
// a console control event deliverable to it alone rather than to the whole
// test run.
func configureServe(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// generateConsoleCtrlEvent is loaded by hand because the stdlib syscall
// package does not export it and this project takes no dependencies, x/sys
// included.
var generateConsoleCtrlEvent = syscall.NewLazyDLL("kernel32.dll").NewProc("GenerateConsoleCtrlEvent")

// interrupt asks the serve process to shut down cleanly. Windows has no
// Process.Signal for arbitrary processes; CTRL_BREAK to the child's process
// group is the Windows spelling of the same request, and Go's runtime delivers
// it to the binary's interrupt handler like any other SIGINT.
func interrupt(cmd *exec.Cmd) error {
	r, _, err := generateConsoleCtrlEvent.Call(
		uintptr(syscall.CTRL_BREAK_EVENT), uintptr(cmd.Process.Pid))
	if r == 0 {
		return err
	}
	return nil
}
