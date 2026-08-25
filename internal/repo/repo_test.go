package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeGit struct {
	responses map[string]string
	failures  map[string]bool
}

func (f fakeGit) Run(_ context.Context, _ string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	if f.failures[key] {
		return "", errors.New("git " + key + " failed")
	}
	out, ok := f.responses[key]
	if !ok {
		return "", errors.New("unexpected git invocation: " + key)
	}
	return out, nil
}

func (f fakeGit) Available(context.Context) bool { return true }

func TestParseGoMod(t *testing.T) {
	mod := parseGoMod("module example.com/x\n\ngo 1.26\n\nrequire foo v1.0.0\n")
	if mod.path != "example.com/x" || mod.goDirective != "1.26" {
		t.Fatalf("got module %q directive %q", mod.path, mod.goDirective)
	}
	if mod.toolchain != "" {
		t.Fatalf("a go.mod without a toolchain line reported %q", mod.toolchain)
	}
}

// TestParseGoModReadsTheToolchainFloor covers the directive that decides whether
// a vulnerability scan is judging the standard library the module accepts.
func TestParseGoModReadsTheToolchainFloor(t *testing.T) {
	mod := parseGoMod("module example.com/x\n\ngo 1.26.3\n\ntoolchain go1.26.6\n")
	if mod.goDirective != "1.26.3" || mod.toolchain != "go1.26.6" {
		t.Fatalf("got directive %q toolchain %q", mod.goDirective, mod.toolchain)
	}
}

func TestDiscoverFindsTheModuleFromASubdirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.26\n")
	sub := filepath.Join(root, "internal", "deep")
	mkdirAll(t, sub)

	git := fakeGit{responses: map[string]string{
		"rev-parse --show-toplevel": root,
		"rev-parse --verify HEAD":   "abc123",
	}}
	r, err := Discover(t.Context(), git, sub)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if r.ModulePath != "example.com/x" || r.GoDirective != "1.26" {
		t.Fatalf("repository = %+v", r)
	}
	if !r.HasGit || !r.HasCommits {
		t.Fatalf("git state = %+v", r)
	}
	if !strings.HasSuffix(r.Root, filepath.Base(root)) {
		t.Fatalf("root = %q, want the module directory %q", r.Root, root)
	}
}

func TestDiscoverWithoutAModuleFails(t *testing.T) {
	git := fakeGit{}
	_, err := Discover(t.Context(), git, t.TempDir())
	if !errors.Is(err, ErrNoModule) {
		t.Fatalf("error = %v, want ErrNoModule", err)
	}
}

func TestDiscoverOutsideGitIsNotAnError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.26\n")
	git := fakeGit{failures: map[string]bool{"rev-parse --show-toplevel": true}}

	r, err := Discover(t.Context(), git, root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if r.HasGit {
		t.Fatal("a directory outside git was reported as a git worktree")
	}
}

func TestDiscoverWithoutCommits(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.26\n")
	git := fakeGit{
		responses: map[string]string{"rev-parse --show-toplevel": root},
		failures:  map[string]bool{"rev-parse --verify HEAD": true},
	}
	r, err := Discover(t.Context(), git, root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !r.HasGit || r.HasCommits {
		t.Fatalf("repository = %+v, want a git worktree with no commits", r)
	}
}

func TestSnapshotEqualityIgnoresOrdering(t *testing.T) {
	a := Snapshot{Entries: []string{" M a.go", "?? b.go"}}
	b := Snapshot{Entries: []string{" M a.go", "?? b.go"}}
	if !a.Equal(b) {
		t.Fatal("identical snapshots compared unequal")
	}
	c := Snapshot{Entries: []string{" M a.go"}}
	if a.Equal(c) {
		t.Fatal("different snapshots compared equal")
	}
	diff := a.Diff(c)
	if !strings.Contains(diff, "disappeared: ?? b.go") {
		t.Fatalf("diff = %q", diff)
	}
}

func TestCaptureSnapshotSortsAndDropsBlanks(t *testing.T) {
	git := fakeGit{responses: map[string]string{
		"status --porcelain --untracked-files=all": "?? z.go\n\n M a.go\n",
	}}
	snap, err := CaptureSnapshot(t.Context(), git, ".")
	if err != nil {
		t.Fatalf("CaptureSnapshot: %v", err)
	}
	if len(snap.Entries) != 2 || snap.Entries[0] != " M a.go" {
		t.Fatalf("entries = %q", snap.Entries)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
}

// TestDiscoverRecordsTheModulePrefix pins the one value that translates between
// the two coordinate systems a monorepo run has to reconcile: git reports paths
// from the repository root and every check joins them onto the module root.
//
// The prefix comes from git rather than from filepath.Rel because GitRoot is
// symlink-resolved and Root is not, so a computed relative path disagrees with
// git on any machine whose temporary or home directory is a symlink.
func TestDiscoverRecordsTheModulePrefix(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "backend")
	if err := os.MkdirAll(module, 0o750); err != nil {
		t.Fatalf("creating the module directory: %v", err)
	}
	writeFile(t, filepath.Join(module, "go.mod"), "module example.com/x\n\ngo 1.26\n")
	git := fakeGit{responses: map[string]string{
		"rev-parse --show-toplevel": root,
		"rev-parse --show-prefix":   "backend/\n",
		"rev-parse --verify HEAD":   "abc123",
	}}

	r, err := Discover(t.Context(), git, module)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if r.ModulePrefix != "backend" {
		t.Fatalf("module prefix = %q, want %q", r.ModulePrefix, "backend")
	}
}

// TestDiscoverAtTheGitRootHasNoPrefix is the guard that keeps the translation
// inert where the two roots coincide, which is where every previous fixture
// lived and why the defect stayed hidden for so long.
func TestDiscoverAtTheGitRootHasNoPrefix(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.26\n")
	git := fakeGit{responses: map[string]string{
		"rev-parse --show-toplevel": root,
		"rev-parse --show-prefix":   "\n",
		"rev-parse --verify HEAD":   "abc123",
	}}

	r, err := Discover(t.Context(), git, root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if r.ModulePrefix != "" {
		t.Fatalf("module prefix at the git root = %q, want empty", r.ModulePrefix)
	}
}
