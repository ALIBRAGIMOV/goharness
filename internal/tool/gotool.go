package tool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// GoVersion reports the toolchain version string, for example "go1.26.4".
func GoVersion() string {
	return runtime.Version()
}

// VetDiagnostic is one go vet finding, already resolved to a position.
type VetDiagnostic struct {
	Package  string
	Analyzer string
	File     string
	Line     int
	Column   int
	Message  string
}

// RunVet runs the official vet analyzers over the given package patterns and
// returns parsed diagnostics. Diagnostics are findings, not failures; only an
// inability to run vet is an error.
func RunVet(ctx context.Context, runner Runner, dir string, patterns []string) ([]VetDiagnostic, error) {
	args := append([]string{"vet", "-json"}, patterns...)
	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if err != nil {
		return nil, err
	}
	stream := res.Stdout
	if strings.TrimSpace(stream) == "" {
		stream = res.Stderr
	}
	diags, parseErr := parseVetJSON(stream)
	if parseErr != nil {
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("go vet exited %d: %s", res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
		}
		return nil, parseErr
	}
	if res.ExitCode != 0 && len(diags) == 0 {
		return nil, fmt.Errorf("go vet exited %d without diagnostics: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
	}
	return diags, nil
}

func parseVetJSON(stream string) ([]VetDiagnostic, error) {
	entries, err := decodeAnalysisJSON(stream)
	if err != nil {
		return nil, err
	}
	var out []VetDiagnostic
	for _, entry := range entries {
		if entry.Failure != "" {
			return nil, fmt.Errorf("vet analyzer %s failed on %s: %s",
				entry.Analyzer, entry.Package, entry.Failure)
		}
		for _, d := range entry.Diagnostics {
			file, line, col := splitPosition(d.Posn)
			out = append(out, VetDiagnostic{
				Package:  entry.Package,
				Analyzer: entry.Analyzer,
				File:     file,
				Line:     line,
				Column:   col,
				Message:  d.Message,
			})
		}
	}
	return out, nil
}

func splitPosition(posn string) (file string, line, col int) {
	parts := strings.Split(posn, ":")
	switch len(parts) {
	case 0:
		return "", 0, 0
	case 1:
		return parts[0], 0, 0
	case 2:
		return parts[0], parseInt(parts[1]), 0
	default:
		return strings.Join(parts[:len(parts)-2], ":"),
			parseInt(parts[len(parts)-2]), parseInt(parts[len(parts)-1])
	}
}

// parseInt returns zero for anything that is not a decimal number, which is how
// a caller reads a missing line or column.
func parseInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// BuildFailure is a compile error reported by go build.
type BuildFailure struct {
	File    string
	Line    int
	Column  int
	Message string
}

// RunBuild compiles the given patterns. When the scope contains a main package,
// the linked executables go to a scratch directory so nothing is written inside
// the worktree; library-only scopes produce no output files at all, and go
// build refuses an output directory in that case.
func RunBuild(ctx context.Context, runner Runner, dir string, patterns []string, hasMain bool) (failures []BuildFailure, err error) {
	args := []string{"build"}
	if hasMain {
		outDir, mkErr := os.MkdirTemp("", "goharness-build-")
		if mkErr != nil {
			return nil, fmt.Errorf("creating build output directory: %w", mkErr)
		}
		defer func() { err = errors.Join(err, os.RemoveAll(outDir)) }()
		args = append(args, "-o", outDir)
	}
	args = append(args, patterns...)
	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 0 {
		return nil, nil
	}
	failures = parseCompilerOutput(res.Stderr)
	if len(failures) == 0 {
		return nil, fmt.Errorf("go build exited %d without parsable diagnostics: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
	}
	return failures, nil
}

func parseCompilerOutput(stderr string) []BuildFailure {
	var out []BuildFailure
	for line := range strings.SplitSeq(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "go: ") {
			continue
		}
		loc, msg, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		file, lineNo, col := splitPosition(loc)
		if lineNo == 0 {
			continue
		}
		out = append(out, BuildFailure{File: file, Line: lineNo, Column: col, Message: msg})
	}
	return out
}

// TestFailure is a failing test or test binary.
type TestFailure struct {
	Package string
	Test    string
	Output  string
}

type testEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

// RunTests runs go test over the given patterns and returns failures. Extra
// arguments such as -race are appended by the caller.
func RunTests(ctx context.Context, runner Runner, dir string, patterns, extraArgs []string) ([]TestFailure, error) {
	// Vet is a separate producer with the full analyzer set; letting go test
	// re-run its subset would surface vet findings as test failures and would
	// refuse overlay-injected virtual packages it cannot chdir into.
	args := []string{"test", "-json", "-count=1", "-vet=off"}
	args = append(args, extraArgs...)
	args = append(args, patterns...)

	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if err != nil {
		return nil, err
	}
	failures, parseErr := parseTestJSON(res.Stdout)
	if parseErr != nil {
		return nil, fmt.Errorf("%w (go test exit %d, stderr: %s)",
			parseErr, res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 10)))
	}
	if res.ExitCode != 0 && len(failures) == 0 {
		return nil, fmt.Errorf("go test exited %d without reporting a failing test: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr+res.Stdout, 20)))
	}
	return failures, nil
}

func parseTestJSON(stdout string) ([]TestFailure, error) {
	dec := json.NewDecoder(strings.NewReader(stdout))
	output := map[string][]string{}
	var failures []TestFailure
	for {
		var ev testEvent
		if err := dec.Decode(&ev); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decoding go test JSON: %w", err)
		}
		key := ev.Package + "\x00" + ev.Test
		switch ev.Action {
		case "output":
			output[key] = append(output[key], ev.Output)
		case "fail":
			failures = append(failures, TestFailure{
				Package: ev.Package,
				Test:    ev.Test,
				Output:  strings.Join(output[key], ""),
			})
		}
	}
	return keepLeafFailures(failures), nil
}

// keepLeafFailures drops the package-level failure event when at least one
// named test in that package already failed, so one defect is one finding.
func keepLeafFailures(failures []TestFailure) []TestFailure {
	named := map[string]bool{}
	for _, f := range failures {
		if f.Test != "" {
			named[f.Package] = true
		}
	}
	out := failures[:0]
	for _, f := range failures {
		if f.Test == "" && named[f.Package] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// RunModTidy checks module tidiness without writing anything.
func RunModTidy(ctx context.Context, runner Runner, dir string) (string, error) {
	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: []string{"mod", "tidy", "-diff"}})
	if err != nil {
		return "", err
	}
	if res.ExitCode == 0 {
		return "", nil
	}
	diff := strings.TrimSpace(res.Stdout)
	if diff == "" {
		return "", fmt.Errorf("go mod tidy -diff exited %d: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
	}
	return diff, nil
}

// ResolveGoVersion reports the toolchain version the go command in dir will
// actually use, as a "go1.26.6" string.
//
// GoVersion names the toolchain this binary was built with, which is a
// different question and the wrong one for anything that judges the module: a
// harness built with one release can be asked to verify a module another
// release compiles. The answer is read through the same sanitised environment
// every other check runs under, so a stray GOFLAGS or GOTOOLCHAIN in the
// operator's shell cannot move it.
func ResolveGoVersion(ctx context.Context, runner Runner, dir string) (string, error) {
	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: []string{"env", "GOVERSION"}})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("go env GOVERSION exited %d: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 5)))
	}
	version := strings.TrimSpace(res.Stdout)
	if version == "" {
		return "", errors.New("go env GOVERSION reported nothing")
	}
	return version, nil
}

// CompareGoVersions orders two "go1.26.6" strings by their numeric components,
// returning a negative number when a precedes b.
//
// Release numbers are compared as integers because they are integers: go1.26.10
// is newer than go1.26.9 and sorts before it as text, so a string comparison
// would report a patched host as older than the floor it satisfies and turn a
// clean security scan inconclusive.
func CompareGoVersions(a, b string) int {
	return slices.Compare(goVersionParts(a), goVersionParts(b))
}

// goVersionParts reduces a version string to its numeric components. Anything
// that is not a release number, such as a devel or gccgo string, yields no
// components and therefore compares equal to every other unparsable value; the
// caller treats that as "no opinion" rather than as an ordering.
func goVersionParts(version string) []int {
	trimmed, ok := strings.CutPrefix(strings.TrimSpace(version), "go")
	if !ok {
		return nil
	}
	// A release candidate or beta suffix carries no ordering this comparison
	// needs, and the numbers before it are the ones a floor is written against.
	for _, cut := range []string{"rc", "beta", "-", "+", " "} {
		trimmed, _, _ = strings.Cut(trimmed, cut)
	}
	var parts []int
	for field := range strings.SplitSeq(trimmed, ".") {
		n, err := strconv.Atoi(field)
		if err != nil {
			return nil
		}
		parts = append(parts, n)
	}
	return parts
}
