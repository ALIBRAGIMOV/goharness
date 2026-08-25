package leakcheck_test

import (
	"os"
	"path/filepath"
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
	overlay, err := leakcheck.Overlay(t.TempDir(), moduleRoot, "example.com/leakfixture",
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

func TestInjectedGoleakCatchesALeakedGoroutine(t *testing.T) {
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

func TestInjectedGoleakPassesWhenGoroutinesAreStopped(t *testing.T) {
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
	found, err := leakcheck.HasTestMain(dir)
	if err != nil || found {
		t.Fatalf("HasTestMain = %v, %v; want false, nil", found, err)
	}
	writeFile(t, dir, "main_test.go", "package p\n\nimport \"testing\"\n\nfunc TestMain(m *testing.M) { m.Run() }\n")
	found, err = leakcheck.HasTestMain(dir)
	if err != nil || !found {
		t.Fatalf("HasTestMain = %v, %v; want true, nil", found, err)
	}
}

// TestLeakOriginNamesASourceLocation covers the anchor that turns a
// package-scoped leak finding into something a reader can open. goleak has the
// leaked goroutine's stack at detection time and the harness discarded it,
// leaving every leak finding with no location at all.
func TestLeakOriginNamesASourceLocation(t *testing.T) {
	t.Parallel()
	const output = `found unexpected goroutines:
[Goroutine 21 in state chan receive, with example.com/x/lib.Start.func1 on top of the stack:
goroutine 21 [chan receive]:
example.com/x/lib.Start.func1()
	/src/x/lib/lib.go:19 +0x34
created by example.com/x/lib.Start in goroutine 20
	/src/x/lib/lib.go:17 +0x64
]
`
	got, ok := leakcheck.LeakOrigin(output)
	if !ok {
		t.Fatalf("no origin extracted from goleak output")
	}
	if got != "/src/x/lib/lib.go:19" {
		t.Fatalf("origin = %q, want the first stack frame with its line and no address", got)
	}
}

func TestLeakOriginReportsAbsenceRatherThanGuessing(t *testing.T) {
	t.Parallel()
	if got, ok := leakcheck.LeakOrigin("found unexpected goroutines:\nno frames here\n"); ok {
		t.Fatalf("an output with no stack frame yielded %q", got)
	}
}
