package leakcheck_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func newLeakModule(t *testing.T, testBody string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	writeFile(t, dir, "go.mod", "module example.com/leakfixture\n\ngo 1.26\n")
	writeFile(t, dir, "lib/lib.go", `package lib

// Start launches a worker and returns the function that stops it.
func Start() func() {
	stop := make(chan struct{})
	go func() { <-stop }()
	return func() { close(stop) }
}
`)
	writeFile(t, dir, "lib/lib_test.go", testBody)
	return dir
}

func runInjected(t *testing.T, moduleRoot string) []tool.TestFailure {
	t.Helper()
	overlay, err := leakcheck.Overlay(t.TempDir(), moduleRoot,
		[]leakcheck.Package{{Dir: "lib", Name: "lib"}})
	if err != nil {
		t.Fatalf("building overlay: %v", err)
	}
	failures, err := tool.RunTests(t.Context(), tool.ExecRunner{}, moduleRoot,
		[]string{"example.com/leakfixture/lib"}, []string{"-overlay", overlay})
	if err != nil {
		t.Fatalf("running injected tests: %v", err)
	}
	return failures
}

func TestInjectedTestMainCatchesALeakedGoroutine(t *testing.T) {
	t.Parallel()
	dir := newLeakModule(t, `package lib

import "testing"

func TestStart(t *testing.T) {
	if Start() == nil {
		t.Fatal("expected a stop function")
	}
}
`)
	failures := runInjected(t, dir)
	if len(failures) != 1 {
		t.Fatalf("failures = %v, want exactly the leak", failures)
	}
	if !leakcheck.IsLeakFailure(failures[0].Output) {
		t.Fatalf("failure output does not look like a leak:\n%s", failures[0].Output)
	}
	msg, ok := leakcheck.LeakMessage(failures[0].Output)
	if !ok {
		t.Fatalf("no leaked function extracted from:\n%s", failures[0].Output)
	}
	const leakedFunc = "example.com/leakfixture/lib.Start.func1"
	if want := "tests leave goroutines running after completion: " + leakedFunc; msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
}

func TestInjectedTestMainPassesWhenGoroutinesAreStopped(t *testing.T) {
	t.Parallel()
	dir := newLeakModule(t, `package lib

import "testing"

func TestStart(t *testing.T) {
	stop := Start()
	if stop == nil {
		t.Fatal("expected a stop function")
	}
	stop()
}
`)
	if failures := runInjected(t, dir); len(failures) != 0 {
		t.Fatalf("clean suite reported failures: %v", failures)
	}
}

func TestHasTestMainDetection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "a_test.go", "package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { t.Log(1) }\n")
	found, err := leakcheck.HasTestMain(os.DirFS(dir), ".")
	if err != nil || found {
		t.Fatalf("HasTestMain = %v, %v; want false, nil", found, err)
	}
	writeFile(t, dir, "main_test.go", "package p\n\nimport \"testing\"\n\nfunc TestMain(m *testing.M) { m.Run() }\n")
	found, err = leakcheck.HasTestMain(os.DirFS(dir), ".")
	if err != nil || !found {
		t.Fatalf("HasTestMain = %v, %v; want true, nil", found, err)
	}
}

// profileOutput is what the injected TestMain prints for two leaked goroutines
// parked in different functions, exactly as the runtime formats the profile at
// debug level 1: one header per distinct stack, then its frames with the
// runtime's own frames already elided.
const profileOutput = `goharness leak check: 2 goroutine(s) blocked forever after the tests finished
goroutineleak profile: total 2
1 @ 0x1043c4428 0x104358670 0x1043581f4 0x104468524 0x1043cacc4
#	0x104468523	example.com/x/lib.Start.func1+0x23	/src/x/lib/lib.go:19

1 @ 0x1043c4428 0x104358670 0x1043581f4 0x104468999 0x1043cacc4
#	0x104468998	example.com/x/lib.(*Pool).run+0x58	/src/x/lib/pool.go:41
#	0x104468777	example.com/x/lib.(*Pool).loop+0x11	/src/x/lib/pool.go:30

`

// TestLeakOriginNamesASourceLocation covers the anchor that turns a
// package-scoped leak finding into something a reader can open: the parked
// frame of the first leaked goroutine, with its line and without the address.
func TestLeakOriginNamesASourceLocation(t *testing.T) {
	t.Parallel()
	got, ok := leakcheck.LeakOrigin(profileOutput)
	if !ok {
		t.Fatalf("no origin extracted from the profile")
	}
	if got != "/src/x/lib/lib.go:19" {
		t.Fatalf("origin = %q, want the parked frame with its line and no address", got)
	}
}

// TestLeakFunctionsNamesTheParkedFrames pins the identity input: one function
// per leaked goroutine, the innermost non-runtime frame, sorted, no repeats.
func TestLeakFunctionsNamesTheParkedFrames(t *testing.T) {
	t.Parallel()
	got := leakcheck.LeakFunctions(profileOutput + profileOutput)
	want := []string{"example.com/x/lib.(*Pool).run", "example.com/x/lib.Start.func1"}
	if !slices.Equal(got, want) {
		t.Fatalf("LeakFunctions = %v, want %v", got, want)
	}
	if !leakcheck.IsLeakFailure(profileOutput) {
		t.Fatal("the profile output is not recognised as a leak")
	}
}

func TestLeakOriginReportsAbsenceRatherThanGuessing(t *testing.T) {
	t.Parallel()
	if got, ok := leakcheck.LeakOrigin("goharness leak check: 1 goroutine(s) blocked forever after the tests finished\nno frames here\n"); ok {
		t.Fatalf("an output with no stack frame yielded %q", got)
	}
}

// TestUnavailableProfileIsNotALeakAndNotClean pins the third outcome: a go
// command older than the profile makes the injected TestMain fail with the
// unavailable marker, which is missing evidence rather than either verdict.
func TestUnavailableProfileIsNotALeakAndNotClean(t *testing.T) {
	t.Parallel()
	const output = "goharness leak check: unavailable\n"
	if !leakcheck.IsLeakUnavailable(output) {
		t.Fatal("the unavailable marker is not recognised")
	}
	if leakcheck.IsLeakFailure(output) {
		t.Fatal("an unavailable profile was read as a leak")
	}
}
