//go:build unix

package tool

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group so that a
// cancellation can reach every process it spawns, not just the child itself.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// interruptGroup asks the whole process group to stop. SIGINT first gives the
// go tool and golangci-lint a chance to clean up their own temporary state;
// exec.Cmd.WaitDelay escalates to a kill if they do not take it.
func interruptGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGINT); err != nil {
		return cmd.Process.Signal(syscall.SIGINT)
	}
	return nil
}
