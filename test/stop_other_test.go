//go:build !windows

package acceptance_test

import (
	"os"
	"os/exec"
)

// configureServe needs no preparation where signals exist.
func configureServe(*exec.Cmd) {}

// interrupt asks the serve process to shut down cleanly.
func interrupt(cmd *exec.Cmd) error {
	return cmd.Process.Signal(os.Interrupt)
}
