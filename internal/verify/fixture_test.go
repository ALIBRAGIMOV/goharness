package verify_test

import (
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// fixture is a throwaway git repository containing a single Go module, built
// per test so that no case can observe another's state.
//
// dir and moduleDir are distinct on purpose: a very large share of real Go
// repositories keep their module in a subdirectory, and every path defect the
// field report exposed lived in the gap between the two.
type fixture struct {
	t         *testing.T
	dir       string
	moduleDir string
	layout    layout
}

const fixtureModule = "example.com/fixture"

// cwdTarget is where a layout puts the process working directory before the
// harness runs. It exists because a verdict must not depend on it, and the only
// way to hold that is to keep running from more than one.
type cwdTarget string

// Working directories an acceptance case runs the harness from.
const (
	cwdUnchanged cwdTarget = ""
	cwdGitRoot   cwdTarget = "git-root"
	cwdModule    cwdTarget = "module"
)

// layout is one repository shape and invocation style that every acceptance
// case must hold under.
//
// prefix is the module directory below the git root, empty when they coincide.
// dirIsDot selects the defaulted --dir, which only resolves a module when the
// working directory is already inside one.
type layout struct {
	name     string
	prefix   string
	cwd      cwdTarget
	dirIsDot bool
}

// layouts enumerates the reachable cells of {module at git root, module in a
// subdirectory} x {cwd at git root, cwd at module dir} x {--dir given,
// defaulted}. Two combinations are omitted because they cannot resolve a
// module at all: a defaulted --dir from the git root of a subdirectory module
// has no go.mod at or above it, which is an argument error rather than a
// property of the code.
func layouts() []layout {
	return []layout{
		{name: "root_dir-given", prefix: "", cwd: cwdUnchanged},
		{name: "root_cwd-module_dir-dot", prefix: "", cwd: cwdModule, dirIsDot: true},
		{name: "subdir_dir-given", prefix: "backend", cwd: cwdUnchanged},
		{name: "subdir_cwd-gitroot_dir-given", prefix: "backend", cwd: cwdGitRoot},
		{name: "subdir_cwd-module_dir-dot", prefix: "backend", cwd: cwdModule, dirIsDot: true},
	}
}

// subdirLayout is the single cell that reproduces the field report's subject:
// a module below the git root, driven from the git root with an explicit --dir.
func subdirLayout() layout {
	return layout{name: "subdir_cwd-gitroot_dir-given", prefix: "backend", cwd: cwdGitRoot}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureIn(t, layout{})
}

// newFixtureIn builds the fixture in one layout. The working directory is
// changed here rather than per run so that a case cannot accidentally observe
// two of them; t.Chdir restores it and refuses to run under t.Parallel, which
// is what keeps this safe.
func newFixtureIn(t *testing.T, lay layout) *fixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	moduleDir := dir
	if lay.prefix != "" {
		moduleDir = filepath.Join(dir, filepath.FromSlash(lay.prefix))
		if mkErr := os.MkdirAll(moduleDir, 0o750); mkErr != nil {
			t.Fatalf("creating module directory: %v", mkErr)
		}
	}
	f := &fixture{t: t, dir: dir, moduleDir: moduleDir, layout: lay}
	f.git("init", "--initial-branch=main")
	f.git("config", "user.email", "harness@example.invalid")
	f.git("config", "user.name", "goharness fixture")
	f.write("go.mod", "module "+fixtureModule+"\n\ngo 1.26\n")
	switch lay.cwd {
	case cwdGitRoot:
		t.Chdir(dir)
	case cwdModule:
		t.Chdir(moduleDir)
	case cwdUnchanged:
	}
	return f
}

// verifyDir is what the layout passes as the --dir option: the defaulted "."
// when the working directory is already the module, and the absolute module
// path otherwise.
func (f *fixture) verifyDir() string {
	if f.layout.dirIsDot {
		return "."
	}
	return f.moduleDir
}

// eachLayout runs body once per layout cell as a subtest. Every case that
// reads a path, and every case that guards a bypass, belongs here: the two
// closures the field report found broken were both green in the first cell and
// silently absent in the rest.
func eachLayout(t *testing.T, body func(t *testing.T, lay layout)) {
	t.Helper()
	for _, lay := range layouts() {
		t.Run(lay.name, func(t *testing.T) { body(t, lay) })
	}
}

// gitEnv pins identity and timestamps so commit hashes and therefore reports
// are reproducible across machines and runs.
func gitEnv() []string {
	const stamp = "2026-01-01T00:00:00+00:00"
	return append(os.Environ(),
		"GIT_AUTHOR_NAME=goharness fixture",
		"GIT_AUTHOR_EMAIL=harness@example.invalid",
		"GIT_AUTHOR_DATE="+stamp,
		"GIT_COMMITTER_NAME=goharness fixture",
		"GIT_COMMITTER_EMAIL=harness@example.invalid",
		"GIT_COMMITTER_DATE="+stamp,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
}

func (f *fixture) git(args ...string) string {
	f.t.Helper()
	cmd := exec.CommandContext(f.t.Context(), "git", args...)
	cmd.Dir = f.dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// write places a file at a module-relative path, so a case reads the same in
// every layout.
func (f *fixture) write(rel, content string) {
	f.t.Helper()
	f.writeAt(f.moduleDir, rel, content)
}

// writeRepo places a file at a path relative to the git root, which is how a
// case reaches the part of a monorepo that lies outside the module.
func (f *fixture) writeRepo(rel, content string) {
	f.t.Helper()
	f.writeAt(f.dir, rel, content)
}

func (f *fixture) writeAt(base, rel, content string) {
	f.t.Helper()
	full := filepath.Join(base, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		f.t.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		f.t.Fatalf("writing %s: %v", rel, err)
	}
}

func (f *fixture) writeExecutable(rel, content string) {
	f.t.Helper()
	f.write(rel, content)
	if err := os.Chmod(filepath.Join(f.moduleDir, filepath.FromSlash(rel)), 0o700); err != nil {
		f.t.Fatalf("making %s executable: %v", rel, err)
	}
}

// goCmd runs a go subcommand inside the fixture module, which is how a case
// builds the module states a real repository arrives in: vendored, tidied, or
// broken.
func (f *fixture) goCmd(args ...string) (string, error) {
	f.t.Helper()
	cmd := exec.CommandContext(f.t.Context(), "go", args...)
	cmd.Dir = f.moduleDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *fixture) mustGo(args ...string) {
	f.t.Helper()
	if out, err := f.goCmd(args...); err != nil {
		f.t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// anchor commits once more so that the commit before it becomes a resolvable
// base revision. Everything written before anchor is what the base holds, which
// is how a case puts pre-existing debt behind the change it is testing.
func (f *fixture) anchor() {
	f.t.Helper()
	f.write("NOTES.md", "a second commit, so that the first is a base revision\n")
	f.commit("second commit so a parent revision exists")
}

// move renames a module-relative path with git, so the change set carries the
// rename git reports rather than an unrelated deletion and addition.
func (f *fixture) move(from, to string) {
	f.t.Helper()
	f.git("mv", f.repoPath(from), f.repoPath(to))
}

// repoPath translates a module-relative path into the repository-relative one
// git answers in, which is the same translation the change set performs and the
// only reason a case reads the same in every layout.
func (f *fixture) repoPath(rel string) string {
	if f.layout.prefix == "" {
		return rel
	}
	return f.layout.prefix + "/" + rel
}

func (f *fixture) commit(message string) {
	f.t.Helper()
	f.git("add", "-A")
	f.git("commit", "--no-gpg-sign", "-m", message)
}

func (f *fixture) porcelain() string {
	f.t.Helper()
	return f.git("status", "--porcelain", "--untracked-files=all")
}

// useGolangci points a case at a trusted linter, found the same way the product
// finds one, and skips when the machine has none. Sharing the discovery path
// matters: a helper that only looked in .tools would quietly skip every
// acceptance case on a machine provisioned by `goharness setup`, and a suite
// that skips itself is indistinguishable from a suite that passes.
func useGolangci(t *testing.T) {
	t.Helper()
	discovered, err := tool.DiscoverGolangci(moduleRoot(t))
	if err != nil {
		t.Skipf("no trusted golangci-lint on this machine: %v; run `goharness setup`", err)
	}
	t.Setenv(tool.GolangciLintEnvVar, discovered.Path)
}

// moduleRoot walks up to the checkout, which is where the repository-local
// .tools directory lives.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolving the working directory: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			if _, toolsErr := os.Stat(filepath.Join(dir, ".tools")); toolsErr == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// Fixture sources. They are deliberately small and gofmt-clean so that only the
// defect a test introduces shows up in the report.
const (
	cleanLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 42
}
`

	cleanLibraryTest = `package lib

import "testing"

func TestAnswer(t *testing.T) {
	if got := Answer(); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
}
`

	uncheckedErrorLibrary = `package lib

import "os"

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 42
}

// Touch opens a file and discards the error, which errcheck reports.
func Touch(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`

	// uncheckedErrorLibraryTest puts a discarded error in a test file, which is
	// where an incumbent configuration's wholesale test exclusion hides it.
	uncheckedErrorLibraryTest = `package lib

import (
	"os"
	"testing"
)

func TestAnswer(t *testing.T) {
	f, _ := os.Open(os.DevNull)
	f.Close()
	if got := Answer(); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
}
`

	consumerLibrary = `package consumer

import "example.com/fixture/lib"

// Doubled returns twice the library answer.
func Doubled() int {
	return lib.Answer() * 2
}
`

	consumerTest = `package consumer

import "testing"

func TestDoubled(t *testing.T) {
	if got := Doubled(); got != 84 {
		t.Fatalf("Doubled() = %d, want 84", got)
	}
}
`

	suppressedLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	//nolint:errcheck
	return 42
}
`

	emDashLibrary = "package lib\n" +
		"\n" +
		"// Answer returns a constant \u2014 the fixture tests observe it.\n" +
		"func Answer() int {\n" +
		"\treturn 42\n" +
		"}\n"

	literalsOnlyLibrary = "package lib\n" +
		"\n" +
		"// Answer returns a constant the fixture tests can observe.\n" +
		"func Answer() int {\n" +
		"\treturn 42\n" +
		"}\n" +
		"\n" +
		"// Directives returns text that only looks like directives and typography.\n" +
		"func Directives() []string {\n" +
		"\treturn []string{\"//nolint:errcheck\", \"//lint:ignore SA1000 reason\", \"an \u2014 em dash\"}\n" +
		"}\n"

	// suppressedSecondLibrary carries an inline suppression in a file that can be
	// added beside an existing one, which is how a case mixes baselineable debt
	// with debt no ledger may ever accept.
	suppressedSecondLibrary = `package lib

// Tripled returns three times the answer.
func Tripled() int {
	//nolint:errcheck
	return 126
}
`

	renamedAnswerLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 40 + 2
}
`

	cleanSecondLibrary = `package lib

// Doubled returns twice the answer.
func Doubled() int {
	return 84
}
`

	wrongAnswerLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 43
}
`

	brokenLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return "not an int"
}
`

	debtPlusAdditionLibrary = `package lib

import "os"

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 42
}

// Doubled returns twice the answer and adds no new findings.
func Doubled() int {
	return Answer() * 2
}

// Touch opens a file and discards the error, which errcheck reports.
func Touch(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`

	// generatedHeaderLibrary carries the generated marker on hand-written code
	// that a linter would otherwise report. It is the file-wide suppression a
	// change must never get for free.
	generatedHeaderLibrary = `// Code generated by fixturegen. DO NOT EDIT.

package lib

import "os"

// Touch opens a file and discards the error, which errcheck reports.
func Touch(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`

	// excludedLibrary is code no build configuration of this run compiles, which
	// is how a change can carry logic past every tool that reads the package
	// graph.
	excludedLibrary = `//go:build ignore

package lib

import "os"

// Touch opens a file and discards the error, which errcheck reports.
func Touch(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`

	// flakyLibraryTest fails the first time it runs in a checkout and passes
	// afterwards, which is how a flake presents itself to the harness: one
	// failure that the same code does not reproduce.
	flakyLibraryTest = `package lib

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestFlakyOnce(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	sum := sha256.Sum256([]byte(dir))
	marker := filepath.Join(os.TempDir(), "goharness-flake-"+hex.EncodeToString(sum[:8]))
	if _, statErr := os.Stat(marker); statErr == nil {
		if err := os.Remove(marker); err != nil {
			t.Fatalf("removing marker: %v", err)
		}
		return
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatalf("writing marker: %v", err)
	}
	t.Fatal("first run of a flaky test")
}
`

	ineffectiveLibraryTest = `package lib

import "testing"

func TestAnswer(t *testing.T) {
	if got := Answer(); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
}

func TestAnswerAgain(t *testing.T) {
	Answer()
}
`
)

// TestFixtureSourcesAreCanonical guards the fixtures themselves: a fixture that
// is not gofmt-clean would make every acceptance test fail for the wrong
// reason.
func TestFixtureSourcesAreCanonical(t *testing.T) {
	sources := map[string]string{
		"cleanLibrary":              cleanLibrary,
		"cleanLibraryTest":          cleanLibraryTest,
		"uncheckedErrorLibrary":     uncheckedErrorLibrary,
		"uncheckedErrorLibraryTest": uncheckedErrorLibraryTest,
		"consumerLibrary":           consumerLibrary,
		"consumerTest":              consumerTest,
		"suppressedLibrary":         suppressedLibrary,
		"suppressedSecondLibrary":   suppressedSecondLibrary,
		"emDashLibrary":             emDashLibrary,
		"brokenLibrary":             brokenLibrary,
		"literalsOnlyLibrary":       literalsOnlyLibrary,
		"renamedAnswerLibrary":      renamedAnswerLibrary,
		"wrongAnswerLibrary":        wrongAnswerLibrary,
		"debtPlusAdditionLibrary":   debtPlusAdditionLibrary,
		"excludedLibrary":           excludedLibrary,
		"flakyLibraryTest":          flakyLibraryTest,
		"generatedHeaderLibrary":    generatedHeaderLibrary,
		"ineffectiveLibraryTest":    ineffectiveLibraryTest,
		"incompatibleAnswerLibrary": incompatibleAnswerLibrary,
		"suppressedConsumer":        suppressedConsumer,
	}
	for name, src := range sources {
		formatted, err := format.Source([]byte(src))
		if err != nil {
			t.Errorf("fixture %s does not parse: %v", name, err)
			continue
		}
		if string(formatted) != src {
			t.Errorf("fixture %s is not gofmt-clean; canonical form:\n%s", name, formatted)
		}
	}
}

// Fixture sources for the admission-model acceptance cases.
const (
	weakTestLibrary = `package lib

// Classify reports whether a score is a pass, and the branch a weak test never
// observes.
func Classify(score int) string {
	if score >= 50 {
		return "pass"
	}
	return "fail"
}
`

	weakTestSource = `package lib

import "testing"

func TestClassifyRuns(t *testing.T) {
	got := Classify(80)
	if got == "" {
		t.Fatal("Classify returned nothing")
	}
}
`

	strongTestSource = `package lib

import "testing"

func TestClassifyBoundary(t *testing.T) {
	if got := Classify(50); got != "pass" {
		t.Fatalf("Classify(50) = %q, want pass", got)
	}
	if got := Classify(49); got != "fail" {
		t.Fatalf("Classify(49) = %q, want fail", got)
	}
}
`

	publicAPIBase = `package api

// Greet returns a greeting for name.
func Greet(name string) string {
	return "hello " + name
}

// Farewell returns a parting message for name.
func Farewell(name string) string {
	return "bye " + name
}
`

	publicAPIBreak = `package api

// Greet returns a greeting for name.
func Greet(name string) string {
	return "hello " + name
}
`

	publicAPITest = `package api

import "testing"

func TestGreet(t *testing.T) {
	if got := Greet("x"); got != "hello x" {
		t.Fatalf("Greet(x) = %q", got)
	}
}
`

	assertiveTest = `package lib

import "testing"

func TestAnswerIsExact(t *testing.T) {
	if got := Answer(); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
	if got := Answer(); got < 0 {
		t.Fatalf("Answer() = %d, want a positive value", got)
	}
}
`

	weakenedTest = `package lib

import "testing"

func TestAnswerIsExact(t *testing.T) {
	Answer()
}
`

	benchmarkedLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 42
}

// Sum adds the first n integers.
func Sum(n int) int {
	total := 0
	for i := range n {
		total += i
	}
	return total
}
`

	benchmarkSource = `package lib

import "testing"

func TestSum(t *testing.T) {
	if got := Sum(4); got != 6 {
		t.Fatalf("Sum(4) = %d, want 6", got)
	}
}

func BenchmarkSum(b *testing.B) {
	for b.Loop() {
		_ = Sum(100)
	}
}
`
)
