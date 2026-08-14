package repo_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatalf("writing fixture file: %v", err)
	}
	for _, args := range [][]string{
		{"init", "--initial-branch=main"},
		{"config", "user.email", "harness@example.invalid"},
		{"config", "user.name", "goharness fixture"},
		{"add", "-A"},
		{"commit", "--no-gpg-sign", "-m", "baseline"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
			"GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	return dir
}

func worktreeCount(t *testing.T, dir string) int {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "worktree", "list", "--porcelain")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git worktree list: %v", err)
	}
	return strings.Count(string(out), "worktree ")
}

// TestRemoveSucceedsAfterCancellation is the cleanup guarantee that makes
// Ctrl+C safe: the removal runs on a context detached from the caller's, so a
// cancelled run still deregisters its worktree instead of leaking one.
func TestRemoveSucceedsAfterCancellation(t *testing.T) {
	dir := gitRepo(t)
	git := repo.ExecGit{Runner: tool.ExecRunner{}}

	ctx, cancel := context.WithCancel(t.Context())
	wt, err := repo.AddBaseWorktree(ctx, git, dir, "HEAD")
	if err != nil {
		t.Fatalf("AddBaseWorktree: %v", err)
	}
	if worktreeCount(t, dir) != 2 {
		t.Fatalf("worktree was not registered: %d entries", worktreeCount(t, dir))
	}

	cancel()
	if ctx.Err() == nil {
		t.Fatal("the context did not cancel")
	}
	if err := wt.Remove(ctx); err != nil {
		t.Fatalf("Remove after cancellation: %v", err)
	}
	if got := worktreeCount(t, dir); got != 1 {
		t.Fatalf("worktree list has %d entries after removal, want 1", got)
	}
	if _, err := os.Stat(wt.Dir); !os.IsNotExist(err) {
		t.Fatalf("worktree directory still exists: %v", err)
	}
}

func TestRemoveIsSafeOnNilWorktree(t *testing.T) {
	var wt *repo.BaseWorktree
	if err := wt.Remove(t.Context()); err != nil {
		t.Fatalf("Remove on a nil worktree: %v", err)
	}
}
