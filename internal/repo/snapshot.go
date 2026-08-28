package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Snapshot is the porcelain view of the worktree at one instant. Comparing two
// snapshots is the last-line guard that verification wrote nothing.
type Snapshot struct {
	Entries []string
}

// CaptureSnapshot records `git status --porcelain` with untracked files
// included, sorted so ordering never causes a false guard trip.
func CaptureSnapshot(ctx context.Context, git Git, dir string) (Snapshot, error) {
	out, err := git.Run(ctx, dir, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return Snapshot{}, fmt.Errorf("capturing worktree snapshot: %w", err)
	}
	var entries []string
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) != "" {
			entries = append(entries, line)
		}
	}
	sort.Strings(entries)
	return Snapshot{Entries: entries}, nil
}

// Equal reports whether two snapshots describe the same worktree state.
func (s Snapshot) Equal(other Snapshot) bool {
	if len(s.Entries) != len(other.Entries) {
		return false
	}
	for i := range s.Entries {
		if s.Entries[i] != other.Entries[i] {
			return false
		}
	}
	return true
}

// Diff describes how two snapshots differ, for the INCONCLUSIVE message.
func (s Snapshot) Diff(other Snapshot) string {
	before := map[string]bool{}
	for _, e := range s.Entries {
		before[e] = true
	}
	after := map[string]bool{}
	for _, e := range other.Entries {
		after[e] = true
	}
	var lines []string
	for _, e := range other.Entries {
		if !before[e] {
			lines = append(lines, "appeared: "+e)
		}
	}
	for _, e := range s.Entries {
		if !after[e] {
			lines = append(lines, "disappeared: "+e)
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// BaseWorktree is a detached checkout of the base revision in a temporary
// directory. It is always removed, including after a failure.
type BaseWorktree struct {
	Dir      string
	Revision string
	git      Git
	repoDir  string
}

// AddBaseWorktree materializes revision in a temporary detached worktree.
//
// The temporary directory is symlink-resolved before anything is built on it,
// for the same reason Discover resolves the git root. On macOS os.MkdirTemp
// answers /var/folders/... while every tool the harness drives reports the same
// file as /private/var/folders/...; a base tree rooted at the unresolved form
// makes every path a tool reports escape it, and a path that escapes its tree
// becomes an absolute string in a fingerprint that the head side can never
// match. A whole producer's output then reads as introduced by the change.
func AddBaseWorktree(ctx context.Context, git Git, repoDir, revision string) (*BaseWorktree, error) {
	tmp, err := os.MkdirTemp("", "goharness-base-")
	if err != nil {
		return nil, fmt.Errorf("creating base worktree directory: %w", err)
	}
	tmp = resolveSymlinks(tmp)
	dir := filepath.Join(tmp, "tree")
	if _, addErr := git.Run(ctx, repoDir, "worktree", "add", "--detach", dir, revision); addErr != nil {
		return nil, errors.Join(
			fmt.Errorf("materializing base revision %s: %w", revision, addErr),
			os.RemoveAll(tmp),
		)
	}
	return &BaseWorktree{Dir: dir, Revision: revision, git: git, repoDir: repoDir}, nil
}

// CleanupTimeout bounds every cleanup command. Cleanup runs on a context
// detached from the caller's, so an interrupted verification still removes the
// temporary worktree instead of leaking a registered one.
const CleanupTimeout = 30 * time.Second

// Remove tears the temporary worktree down and deregisters it from git. It is
// safe to call after the caller's context has been cancelled: cleanup must
// outlive cancellation or a Ctrl+C would leave a registered worktree behind.
func (w *BaseWorktree) Remove(ctx context.Context) error {
	if w == nil {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), CleanupTimeout)
	defer cancel()

	_, gitErr := w.git.Run(cleanupCtx, w.repoDir, "worktree", "remove", "--force", w.Dir)
	rmErr := os.RemoveAll(filepath.Dir(w.Dir))
	if gitErr != nil {
		return fmt.Errorf("removing base worktree: %w", gitErr)
	}
	if rmErr != nil {
		return fmt.Errorf("cleaning base worktree directory: %w", rmErr)
	}
	return nil
}

// StaleWorktrees lists registered worktrees whose directory follows the
// harness's temporary naming and no longer exists on disk. A second interrupt
// can leave one behind, and doctor turns that into an exact removal command.
func StaleWorktrees(ctx context.Context, git Git, repoDir string) ([]string, error) {
	out, err := git.Run(ctx, repoDir, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("listing worktrees: %w", err)
	}
	var stale []string
	for line := range strings.SplitSeq(out, "\n") {
		path, found := strings.CutPrefix(strings.TrimSpace(line), "worktree ")
		if !found || !strings.Contains(path, "goharness-base-") {
			continue
		}
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			stale = append(stale, path)
		}
	}
	sort.Strings(stale)
	return stale, nil
}
