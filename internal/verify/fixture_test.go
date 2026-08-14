package verify_test

import (
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is a throwaway git repository containing a single Go module, built
// per test so that no case can observe another's state.
type fixture struct {
	t   *testing.T
	dir string
}

const fixtureModule = "example.com/fixture"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	f := &fixture{t: t, dir: dir}
	f.git("init", "--initial-branch=main")
	f.git("config", "user.email", "harness@example.invalid")
	f.git("config", "user.name", "goharness fixture")
	f.write("go.mod", "module "+fixtureModule+"\n\ngo 1.26\n")
	return f
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

func (f *fixture) write(rel, content string) {
	f.t.Helper()
	full := filepath.Join(f.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		f.t.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		f.t.Fatalf("writing %s: %v", rel, err)
	}
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

// useGolangci points the harness at the repository-local pinned binary and
// skips the test when it is absent, because a missing linter would otherwise
// look like a policy failure.
func useGolangci(t *testing.T) {
	t.Helper()
	path, ok := findGolangci()
	if !ok {
		t.Skip("pinned golangci-lint not found at .tools/golangci-lint; run the repository bootstrap first")
	}
	t.Setenv("GOHARNESS_GOLANGCI_LINT", path)
}

func findGolangci() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(dir, ".tools", "golangci-lint")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
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

	renamedAnswerLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 40 + 2
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
		"cleanLibrary":            cleanLibrary,
		"cleanLibraryTest":        cleanLibraryTest,
		"uncheckedErrorLibrary":   uncheckedErrorLibrary,
		"consumerLibrary":         consumerLibrary,
		"consumerTest":            consumerTest,
		"suppressedLibrary":       suppressedLibrary,
		"emDashLibrary":           emDashLibrary,
		"brokenLibrary":           brokenLibrary,
		"literalsOnlyLibrary":     literalsOnlyLibrary,
		"renamedAnswerLibrary":    renamedAnswerLibrary,
		"wrongAnswerLibrary":      wrongAnswerLibrary,
		"debtPlusAdditionLibrary": debtPlusAdditionLibrary,
		"ineffectiveLibraryTest":  ineffectiveLibraryTest,
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
