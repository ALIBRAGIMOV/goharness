//go:build !unix

package tool

import "os/exec"

// configureProcessGroup is a no-op where process groups are not available.
func configureProcessGroup(*exec.Cmd) {}

// interruptGroup falls back to killing the child directly.
func interruptGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
