// Package tool runs the external programs the harness depends on and pins their
// versions. Nothing here interprets policy; runners return raw results and
// distinguish a tool failure from a finding.
package tool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

// Environment settings a verification subprocess is never allowed to inherit,
// and the toolchain setting it always receives instead.
const (
	envGoFlags     = "GOFLAGS"
	envGoToolchain = "GOTOOLCHAIN"
	envHarness     = "GOHARNESS_"
	// ForcedToolchain keeps the go command on the toolchain that is installed.
	ForcedToolchain = envGoToolchain + "=local"
)

// VerificationEnv returns the environment a child process runs with, starting
// from base or from this process's environment when base is empty.
//
// Three settings are taken out of the caller's hands because they change what a
// check concludes without changing the code under it: GOFLAGS is spliced into
// every go invocation, where one -run pattern turns an empty test run into a
// passing one; GOTOOLCHAIN is pinned to local so verification downloads
// nothing; and GOHARNESS_ settings are dropped so code under test cannot
// redirect the cache its own verdict rests on. Everything else is inherited,
// because module resolution in a real repository rides on GOPRIVATE, GOPROXY
// and their neighbours.
func VerificationEnv(base []string) []string {
	if len(base) == 0 {
		base = os.Environ()
	}
	out := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if name, _, ok := strings.Cut(entry, "="); !ok || stripped(name) {
			continue
		}
		out = append(out, entry)
	}
	return append(out, ForcedToolchain)
}

func stripped(name string) bool {
	return name == envGoFlags || name == envGoToolchain || strings.HasPrefix(name, envHarness)
}

// Run executes cmd and returns its captured output. A non-zero exit status is
// reported through Result.ExitCode, not as an error; an error means the process
// could not be started, or the context ended it.
func (ExecRunner) Run(ctx context.Context, cmd Command) (Result, error) {
	proc := exec.CommandContext(ctx, cmd.Name, cmd.Args...)
	proc.Dir = cmd.Dir
	proc.Env = VerificationEnv(cmd.Env)
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
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("running %s: %w", cmd.Name, err)
}
