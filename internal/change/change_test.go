package change_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

const graphModule = "example.com/graph"

// buildModule writes a three-package chain: base is imported by middle, which is
// imported by top.
func buildModule(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	files := map[string]string{
		"go.mod":                 "module " + graphModule + "\n\ngo 1.26\n",
		"base/base.go":           "package base\n\n// Value is the leaf constant.\nconst Value = 1\n",
		"base/base_test.go":      "package base\n\nimport \"testing\"\n\nfunc TestValue(t *testing.T) {\n\tif Value != 1 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n",
		"middle/middle.go":       "package middle\n\nimport \"" + graphModule + "/base\"\n\n// Doubled doubles the leaf.\nfunc Doubled() int { return base.Value * 2 }\n",
		"top/top.go":             "package top\n\nimport \"" + graphModule + "/middle\"\n\n// Quadrupled quadruples the leaf.\nfunc Quadrupled() int { return middle.Doubled() * 2 }\n",
		"unrelated/unrelated.go": "package unrelated\n\n// Standalone touches nothing else.\nfunc Standalone() int { return 0 }\n",
		"cmd/app/main.go":        "package main\n\nfunc main() {}\n",
	}
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}
	return root
}

func loadGraph(t *testing.T) change.PackageGraph {
	t.Helper()
	g, err := change.LoadGraph(t.Context(), buildModule(t))
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	return g
}

func TestGraphContainsOnlyModulePackages(t *testing.T) {
	g := loadGraph(t)
	want := []string{
		graphModule + "/base",
		graphModule + "/cmd/app",
		graphModule + "/middle",
		graphModule + "/top",
		graphModule + "/unrelated",
	}
	if !slices.Equal(g.Packages(), want) {
		t.Fatalf("packages = %v, want %v (dependencies must never enter the graph)", g.Packages(), want)
	}
}

func TestAffectedScopes(t *testing.T) {
	g := loadGraph(t)
	seeds := g.SeedPackages([]string{"base/base.go"})
	if !slices.Equal(seeds, []string{graphModule + "/base"}) {
		t.Fatalf("seeds = %v", seeds)
	}

	cases := []struct {
		name  string
		scope change.Scope
		want  []string
	}{
		{"changed only", change.ScopeChangedOnly, []string{graphModule + "/base"}},
		{"direct dependents", change.ScopeDirectDependents, []string{graphModule + "/base", graphModule + "/middle"}},
		{"full closure", change.ScopeFullClosure, []string{
			graphModule + "/base", graphModule + "/middle", graphModule + "/top",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.Affected(seeds, tc.scope); !slices.Equal(got, tc.want) {
				t.Fatalf("affected = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSeedPackagesResolveTestFiles(t *testing.T) {
	g := loadGraph(t)
	seeds := g.SeedPackages([]string{"base/base_test.go"})
	if !slices.Equal(seeds, []string{graphModule + "/base"}) {
		t.Fatalf("a _test.go file did not map to its package: %v", seeds)
	}
}

func TestFilesForIncludesTestFiles(t *testing.T) {
	g := loadGraph(t)
	files, err := g.FilesFor([]string{graphModule + "/base"})
	if err != nil {
		t.Fatalf("FilesFor: %v", err)
	}
	if !slices.Equal(files, []string{"base/base.go", "base/base_test.go"}) {
		t.Fatalf("files = %v", files)
	}
}

func TestHasMainPackage(t *testing.T) {
	g := loadGraph(t)
	if !g.HasMainPackage([]string{graphModule + "/cmd/app"}) {
		t.Fatal("the command package was not recognised as main")
	}
	if g.HasMainPackage([]string{graphModule + "/base"}) {
		t.Fatal("a library package was reported as main")
	}
}

func TestRelDirsFor(t *testing.T) {
	g := loadGraph(t)
	got := g.RelDirsFor([]string{graphModule + "/base", graphModule + "/cmd/app"})
	if !slices.Equal(got, []string{"./base", "./cmd/app"}) {
		t.Fatalf("relative dirs = %v", got)
	}
}

func TestChangeSetHelpers(t *testing.T) {
	cs := change.ChangeSet{Files: []string{"a.go", "README.md", "go.mod", "b/c.go"}}
	if got := cs.GoFiles(); !slices.Equal(got, []string{"a.go", "b/c.go"}) {
		t.Fatalf("GoFiles = %v", got)
	}
	if !cs.TouchesModuleFiles() {
		t.Fatal("go.mod change was not detected")
	}
	if (change.ChangeSet{Files: []string{"a.go"}}).TouchesModuleFiles() {
		t.Fatal("a source-only change was reported as touching the module files")
	}
}

func TestHasBase(t *testing.T) {
	if (change.ChangeSet{Base: "abc", BaseOrigin: change.BaseFromParent}).HasBase() != true {
		t.Fatal("a resolved base was reported as unavailable")
	}
	if (change.ChangeSet{BaseOrigin: change.BaseUnavailable}).HasBase() {
		t.Fatal("an unresolved base was reported as available")
	}
}

// TestUnexaminedSeparatesToolFaultsFromCodeFacts holds the line between a tool
// fault and a fact about the code.
//
// "N changed Go files were compiled by nothing in this run" is a claim about the
// repository. When the harness has merely failed to find a file, that claim is
// false, and an agent told its file is compiled by nothing goes hunting for a
// build-constraint problem that does not exist. A file the harness cannot
// resolve must leave through a different channel than a file the toolchain
// deliberately excluded, so that the report can attribute it to goharness.
func TestUnexaminedSeparatesToolFaultsFromCodeFacts(t *testing.T) {
	g, err := change.LoadGraph(t.Context(), buildModule(t))
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	unexamined, faults := g.Unexamined([]change.Entry{
		{Path: "nowhere/at/all/ghost.go", Status: change.StatusAdded},
	})
	if len(unexamined) != 0 {
		t.Fatalf("a file the harness could not resolve was reported as a fact about the code: %+v", unexamined)
	}
	if len(faults) != 1 || faults[0].Path != "nowhere/at/all/ghost.go" {
		t.Fatalf("an unresolvable file did not reach the fault channel: %+v", faults)
	}
	if faults[0].Err == nil {
		t.Fatal("a harness fault carried no error to attribute it with")
	}
}

// TestUnexaminedStillReportsRealExclusions is the false-positive guard: the
// taxonomy split must not turn a genuine coverage gap into silence.
func TestUnexaminedStillReportsRealExclusions(t *testing.T) {
	root := buildModule(t)
	writeSource(t, root, "hidden/hidden.go",
		"//go:build ignore\n\npackage hidden\n\n// Value is never compiled in this configuration.\nconst Value = 1\n")
	g, err := change.LoadGraph(t.Context(), root)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	unexamined, faults := g.Unexamined([]change.Entry{
		{Path: "hidden/hidden.go", Status: change.StatusAdded},
	})
	if len(faults) != 0 {
		t.Fatalf("a build-constraint exclusion was blamed on the harness: %+v", faults)
	}
	if len(unexamined) != 1 {
		t.Fatalf("a file outside the build was not reported as unexamined: %+v", unexamined)
	}
}

// writeSource adds one file to an already built fixture module.
func writeSource(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", rel, err)
	}
}

// TestRenamesAreCarriedThroughTheChangeSet pins the record git reports for a
// move.
//
// A rename used to arrive as an addition with the source discarded, which made
// every finding in a moved file absent at base and therefore introduced by the
// move. The source path is what lets the base snapshot be read in head's
// coordinates, so it has to survive the parse.
func TestRenamesAreCarriedThroughTheChangeSet(t *testing.T) {
	root := gitRepoWithAMove(t)
	git := repo.ExecGit{Runner: tool.ExecRunner{}}
	r, err := repo.Discover(t.Context(), git, root)
	if err != nil {
		t.Fatalf("discovering the fixture module: %v", err)
	}
	base, origin, err := change.ResolveBase(t.Context(), git, r, "")
	if err != nil {
		t.Fatalf("resolving the base revision: %v", err)
	}
	cs, err := change.Build(t.Context(), git, r, base, origin)
	if err != nil {
		t.Fatalf("building the change set: %v", err)
	}

	var moved change.Entry
	for _, e := range cs.Entries {
		if e.Path == "pkg/lib.go" {
			moved = e
		}
	}
	if moved.Status != change.StatusRenamed {
		t.Fatalf("entry for the moved file = %+v, want status %s", moved, change.StatusRenamed)
	}
	if moved.OldPath != "lib/lib.go" {
		t.Fatalf("OldPath = %q, want lib/lib.go", moved.OldPath)
	}
	if got := cs.Renames()["lib/lib.go"]; got != "pkg/lib.go" {
		t.Fatalf("Renames()[lib/lib.go] = %q, want pkg/lib.go", got)
	}
}

// gitRepoWithAMove builds a two-commit repository whose working tree has one
// package directory moved.
func gitRepoWithAMove(t *testing.T) string {
	t.Helper()
	root := newGitFixture(t, map[string]string{
		"go.mod":     "module " + graphModule + "\n\ngo 1.26\n",
		"lib/lib.go": "package lib\n\n// Value is a constant.\nconst Value = 1\n",
	})
	gitIn(t, root, "mv", "lib", "pkg")
	return root
}

// newGitFixture builds a repository holding the given files, committed, plus a
// second commit so that the first is a resolvable base revision.
func newGitFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	gitIn(t, root, "init", "--quiet", "--initial-branch=main")
	for rel, content := range files {
		writeIn(t, root, rel, content)
	}
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "commit", "--no-gpg-sign", "--quiet", "-m", "first")
	writeIn(t, root, "NOTES.md", "second commit so a parent revision exists\n")
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "commit", "--no-gpg-sign", "--quiet", "-m", "second")
	return root
}

func writeIn(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", rel, err)
	}
}

func appendTo(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	existing, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	writeIn(t, root, rel, string(existing)+content)
}

func gitIn(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=goharness fixture", "GIT_AUTHOR_EMAIL=harness@example.invalid",
		"GIT_COMMITTER_NAME=goharness fixture", "GIT_COMMITTER_EMAIL=harness@example.invalid",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestHunksReadTheLinesTheChangeWrote pins the parser behind added-line
// attribution. Only the head side of a zero-context diff matters: it names the
// lines that exist in the tree the checks examine.
func TestHunksReadTheLinesTheChangeWrote(t *testing.T) {
	root := gitRepoWithAnEdit(t)
	git := repo.ExecGit{Runner: tool.ExecRunner{}}
	r, err := repo.Discover(t.Context(), git, root)
	if err != nil {
		t.Fatalf("discovering the fixture module: %v", err)
	}
	base, _, err := change.ResolveBase(t.Context(), git, r, "")
	if err != nil {
		t.Fatalf("resolving the base revision: %v", err)
	}
	spans, err := change.Hunks(t.Context(), git, r, base)
	if err != nil {
		t.Fatalf("reading hunks: %v", err)
	}
	added := spans["lib/lib.go"]
	if len(added) == 0 {
		t.Fatalf("no span for the edited file: %v", spans)
	}
	inside, outside := false, false
	for _, span := range added {
		if span.Contains(6) {
			inside = true
		}
		if span.Contains(1) {
			outside = true
		}
	}
	if !inside {
		t.Fatalf("the appended line is outside every span: %v", added)
	}
	if outside {
		t.Fatalf("the package clause was reported as written by this change: %v", added)
	}
	if _, ok := spans["lib/untouched.go"]; ok {
		t.Fatalf("a file the change never opened carries spans: %v", spans)
	}
}

// gitRepoWithAnEdit builds a two-commit repository whose working tree appends
// one function to one of two files.
func gitRepoWithAnEdit(t *testing.T) string {
	t.Helper()
	root := newGitFixture(t, map[string]string{
		"go.mod":           "module " + graphModule + "\n\ngo 1.26\n",
		"lib/lib.go":       "package lib\n\n// Value is a constant.\nconst Value = 1\n",
		"lib/untouched.go": "package lib\n\n// Other is a constant.\nconst Other = 2\n",
	})
	appendTo(t, root, "lib/lib.go", "\n// Extra is a constant.\nconst Extra = 3\n")
	return root
}
