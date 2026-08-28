// Package leakcheck injects goroutine-leak verification into a module's test
// packages without touching the worktree. It materializes a pinned, embedded
// copy of go.uber.org/goleak as a virtual package inside the module and adds a
// generated TestMain per test package, all through a `go test -overlay` file.
package leakcheck

import (
	"embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// Version is the embedded goleak release. The sources under goleaksrc are that
// release verbatim (MIT licensed, see goleaksrc/LICENSE) with only the internal
// import path rewritten at materialization time.
const Version = "v1.3.0"

// overlayDir is the virtual directory injected at the module root. The name is
// chosen to collide with nothing a real module would contain.
const overlayDir = "zz_goharness_leakcheck"

// TestMainFileName is the generated per-package file. It only ever exists
// inside the overlay, never on disk.
const TestMainFileName = "zz_goharness_leak_test.go"

const upstreamStackImport = "go.uber.org/goleak/internal/stack"

//go:embed goleaksrc
var embedded embed.FS

// Package identifies one test package to instrument.
type Package struct {
	// Dir is the module-relative package directory in slash form.
	Dir string
	// Name is the package's non-test name, so the generated file can join the
	// external test package.
	Name string
}

// Overlay writes the embedded goleak sources and one generated TestMain per
// package into scratchDir and returns the path of a `go test -overlay` file
// mapping virtual module paths onto them. The module itself is never written.
func Overlay(scratchDir, moduleRoot, modulePath string, pkgs []Package) (string, error) {
	if modulePath == "" {
		return "", fmt.Errorf("leakcheck overlay: module path is empty")
	}
	fakeImport := modulePath + "/" + overlayDir + "/goleak"
	replacements := map[string]string{}

	place := func(embeddedDir, virtualDir string) error {
		entries, err := embedded.ReadDir(embeddedDir)
		if err != nil {
			return fmt.Errorf("reading embedded goleak sources: %w", err)
		}
		for _, entry := range entries {
			name, ok := strings.CutSuffix(entry.Name(), ".gosrc")
			if !ok {
				continue
			}
			src, err := embedded.ReadFile(embeddedDir + "/" + entry.Name())
			if err != nil {
				return fmt.Errorf("reading embedded %s: %w", entry.Name(), err)
			}
			rewritten := strings.ReplaceAll(string(src),
				upstreamStackImport, fakeImport+"/internal/stack")
			onDisk := filepath.Join(scratchDir, filepath.FromSlash(virtualDir), name+".go")
			if err := writeScratch(onDisk, rewritten); err != nil {
				return err
			}
			virtual := filepath.Join(moduleRoot, filepath.FromSlash(virtualDir), name+".go")
			replacements[virtual] = onDisk
		}
		return nil
	}
	if err := place("goleaksrc/goleak", overlayDir+"/goleak"); err != nil {
		return "", err
	}
	if err := place("goleaksrc/stack", overlayDir+"/goleak/internal/stack"); err != nil {
		return "", err
	}

	for _, pkg := range pkgs {
		src := testMainSource(pkg.Name, fakeImport)
		onDisk := filepath.Join(scratchDir, "testmain", filepath.FromSlash(pkg.Dir), TestMainFileName)
		if err := writeScratch(onDisk, src); err != nil {
			return "", err
		}
		virtual := filepath.Join(moduleRoot, filepath.FromSlash(pkg.Dir), TestMainFileName)
		replacements[virtual] = onDisk
	}
	return tool.OverlayPath(scratchDir, replacements)
}

func writeScratch(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating overlay scratch directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing overlay scratch file: %w", err)
	}
	return nil
}

func testMainSource(pkgName, fakeImport string) string {
	return fmt.Sprintf(`package %s_test

import (
	"testing"

	goleak %q
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
`, pkgName, fakeImport)
}

// HasTestMain reports whether any _test.go file in absDir already declares a
// TestMain. Injection there would not compile, so the caller reports the
// obligation as unproducible instead of guessing.
func HasTestMain(absDir string) (bool, error) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return false, fmt.Errorf("listing %s: %w", absDir, err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(absDir, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			// A malformed test file is the compile check's finding; it cannot
			// hide a TestMain from us and from the compiler at the same time.
			continue
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "TestMain" {
				return true, nil
			}
		}
	}
	return false, nil
}

// HasTestFiles reports whether absDir contains any _test.go file at all.
func HasTestFiles(absDir string) (bool, error) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return false, fmt.Errorf("listing %s: %w", absDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), "_test.go") {
			return true, nil
		}
	}
	return false, nil
}

// LeakOrigin is the first source location goleak attributed to a leaked
// goroutine's stack, in "file:line" form as the runtime printed it.
//
// goleak knows where the goroutine came from and prints it; dropping that on
// the floor left every leak finding with no location at all, so a reader had no
// place to jump to and a scoped exception had nothing to match against. The
// line number is not part of any fingerprint, so surfacing it costs no
// stability.
func LeakOrigin(output string) (string, bool) {
	for line := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(trimmed, "/")
		if !ok {
			continue
		}
		// A stack frame line is a path followed by ":line +0xoffset"; the offset is
		// an address and must not reach the report.
		location, _, _ := strings.Cut(rest, " ")
		if path, lineNo, found := strings.Cut(location, ":"); found && lineNo != "" {
			return "/" + path + ":" + lineNo, true
		}
	}
	return "", false
}

// LeakFunctions extracts the functions goleak found on top of the leaked
// goroutines' stacks, sorted and without repeats.
//
// Sorted, because goleak reports the goroutines in whatever order the runtime
// hands them over and the set itself varies between runs of the same code. A
// description built in that order is a different string every time, and a
// finding named by its description is then a different finding every time: on a
// production run the same leak arrived as new, fixed and pre-existing inside one
// report. Order and membership belong in the message; neither may reach an
// identity.
func LeakFunctions(output string) []string {
	seen := map[string]bool{}
	var funcs []string
	for line := range strings.SplitSeq(output, "\n") {
		_, rest, found := strings.Cut(line, "with ")
		if !found {
			continue
		}
		fn, _, found := strings.Cut(rest, " on top of the stack")
		if !found || fn == "" || seen[fn] {
			continue
		}
		seen[fn] = true
		funcs = append(funcs, fn)
	}
	slices.Sort(funcs)
	return funcs
}

// LeakMessage extracts a deterministic description from goleak output, keeping
// the leaked functions and dropping goroutine IDs and addresses.
func LeakMessage(output string) (string, bool) {
	funcs := LeakFunctions(output)
	if len(funcs) == 0 {
		return "", false
	}
	return "tests leave goroutines running after completion: " + strings.Join(funcs, ", "), true
}

// IsLeakFailure reports whether a test failure's output is goleak reporting
// leaked goroutines rather than an ordinary assertion failure.
func IsLeakFailure(output string) bool {
	return strings.Contains(output, "found unexpected goroutines")
}
