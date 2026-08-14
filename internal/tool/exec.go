// Package tool runs the external programs the harness depends on and pins their
// versions. Nothing here interprets policy; runners return raw results and
// distinguish a tool failure from a finding.
package tool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// KillGrace is how long a cancelled process has to exit after its interrupt
// before the group is killed outright.
const KillGrace = 5 * time.Second

// Command describes one external process invocation.
type Command struct {
	Dir  string
	Name string
	Args []string
	Env  []string
}

// Result is the captured outcome of a process that ran to completion.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes external processes. It is the process-execution test seam;
// production code uses ExecRunner.
type Runner interface {
	Run(ctx context.Context, cmd Command) (Result, error)
}

// ExecRunner runs commands with os/exec.
//
// Every process starts in its own process group and is interrupted rather than
// killed on cancellation, so that go test and golangci-lint get the chance to
// tear down their own children. If the group has not exited after KillGrace it
// is killed, which is what keeps a Ctrl+C from leaving worker processes behind.
type ExecRunner struct{}

// Run executes cmd and returns its captured output. A non-zero exit status is
// reported through Result.ExitCode, not as an error; an error means the process
// could not be started, or the context ended it.
func (ExecRunner) Run(ctx context.Context, cmd Command) (Result, error) {
	proc := exec.CommandContext(ctx, cmd.Name, cmd.Args...)
	proc.Dir = cmd.Dir
	if len(cmd.Env) > 0 {
		proc.Env = cmd.Env
	}
	proc.WaitDelay = KillGrace
	proc.Cancel = func() error { return interruptGroup(proc) }
	configureProcessGroup(proc)

	var stdout, stderr bytes.Buffer
	proc.Stdout = &stdout
	proc.Stderr = &stderr

	err := proc.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return res, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, fmt.Errorf("%s: %w", cmd.Name, ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("running %s: %w", cmd.Name, err)
}
