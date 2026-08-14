// Package change resolves the base revision, builds the set of changed files,
// and computes which packages a change can affect.
package change

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/repo"
)

// BaseOrigin records how the base revision was chosen, for the report.
type BaseOrigin string

// Base resolution outcomes, in the order they are attempted.
const (
	BaseFromFlag      BaseOrigin = "explicit --base"
	BaseFromMergeBase BaseOrigin = "merge-base with default branch"
	BaseFromParent    BaseOrigin = "parent commit"
	BaseUnavailable   BaseOrigin = "unavailable"
)

// Status is how a file was changed. It matters for rules that treat rewriting
// history differently from appending to it, such as migrations.
type Status string

// File change statuses.
const (
	StatusAdded    Status = "added"
	StatusModified Status = "modified"
	StatusDeleted  Status = "deleted"
)

// Describe renders a status for a report sentence.
func (s Status) Describe() string { return string(s) }

// Entry is one changed file with the strongest status observed for it. A file
// that is added and then edited is still an addition; one that existed before
// is a modification.
type Entry struct {
	Path   string
	Status Status
}

// ChangeSet is the set of files a verification run considers changed, together
// with the base it was computed against.
type ChangeSet struct {
	Base       string
	BaseOrigin BaseOrigin
	Files      []string
	Entries    []Entry
	FullScope  bool
}

// HasBase reports whether a base revision was resolved and base/head comparison
// is therefore possible.
func (c ChangeSet) HasBase() bool {
	return c.Base != "" && c.BaseOrigin != BaseUnavailable
}

// ResolveBase picks the base revision in the documented order: explicit flag,
// merge-base with the default branch, then the parent commit.
func ResolveBase(ctx context.Context, git repo.Git, r repo.Repository, explicit string) (string, BaseOrigin, error) {
	if !r.HasGit || !r.HasCommits {
		return "", BaseUnavailable, nil
	}
	if explicit != "" {
		rev, err := git.Run(ctx, r.Root, "rev-parse", "--verify", explicit+"^{commit}")
		if err != nil {
			return "", BaseUnavailable, fmt.Errorf("resolving --base %q: %w", explicit, err)
		}
		return strings.TrimSpace(rev), BaseFromFlag, nil
	}
	head, err := git.Run(ctx, r.Root, "rev-parse", "HEAD")
	if err != nil {
		return "", BaseUnavailable, fmt.Errorf("resolving HEAD: %w", err)
	}
	head = strings.TrimSpace(head)

	for _, branch := range defaultBranchCandidates(ctx, git, r) {
		merged, ok := tryRev(ctx, git, r, "merge-base", branch, "HEAD")
		if ok && merged != head {
			return merged, BaseFromMergeBase, nil
		}
	}
	if parent, ok := tryRev(ctx, git, r, "rev-parse", "--verify", "HEAD^{commit}~1"); ok {
		return parent, BaseFromParent, nil
	}
	return "", BaseUnavailable, nil
}

// tryRev resolves a revision whose absence is an expected answer: an unrelated
// default branch, or a root commit with no parent.
func tryRev(ctx context.Context, git repo.Git, r repo.Repository, args ...string) (string, bool) {
	out, err := git.Run(ctx, r.Root, args...)
	if err != nil {
		return "", false
	}
	trimmed := strings.TrimSpace(out)
	return trimmed, trimmed != ""
}

func defaultBranchCandidates(ctx context.Context, git repo.Git, r repo.Repository) []string {
	var out []string
	if name, ok := tryRev(ctx, git, r, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"); ok {
		out = append(out, name)
	}
	for _, name := range []string{"origin/main", "origin/master", "main", "master"} {
		if _, ok := tryRev(ctx, git, r, "rev-parse", "--verify", name+"^{commit}"); ok {
			out = append(out, name)
		}
	}
	return out
}

// Build assembles the change set: the committed diff from base to HEAD plus
// staged, unstaged, and untracked files. Without a base it degrades to full
// scope over tracked files.
func Build(ctx context.Context, git repo.Git, r repo.Repository, base string, origin BaseOrigin) (ChangeSet, error) {
	cs := ChangeSet{Base: base, BaseOrigin: origin}
	if !r.HasGit {
		cs.FullScope = true
		cs.BaseOrigin = BaseUnavailable
		return cs, nil
	}
	seen := map[string]Status{}
	record := func(path string, status Status) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if existing, ok := seen[path]; ok && existing == StatusAdded {
			return
		}
		seen[path] = status
	}

	statusCommands := [][]string{
		{"diff", "--name-status", "--diff-filter=ACMRTD", "HEAD"},
		{"diff", "--name-status", "--diff-filter=ACMRTD", "--cached", "HEAD"},
	}
	if cs.HasBase() {
		statusCommands = append(statusCommands,
			[]string{"diff", "--name-status", "--diff-filter=ACMRTD", base, "HEAD"})
	}
	plainCommands := [][]string{{"ls-files", "--others", "--exclude-standard"}}
	if !r.HasCommits {
		statusCommands = nil
		plainCommands = [][]string{{"ls-files"}, {"ls-files", "--others", "--exclude-standard"}}
		cs.FullScope = true
	}

	for _, args := range statusCommands {
		out, err := git.Run(ctx, r.Root, args...)
		if err != nil {
			return ChangeSet{}, fmt.Errorf("listing changed files (git %s): %w", strings.Join(args, " "), err)
		}
		for line := range strings.SplitSeq(out, "\n") {
			path, status, ok := parseNameStatus(line)
			if ok {
				record(path, status)
			}
		}
	}
	for _, args := range plainCommands {
		out, err := git.Run(ctx, r.Root, args...)
		if err != nil {
			return ChangeSet{}, fmt.Errorf("listing changed files (git %s): %w", strings.Join(args, " "), err)
		}
		for line := range strings.SplitSeq(out, "\n") {
			record(line, StatusAdded)
		}
	}

	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)
	cs.Files = files
	cs.Entries = make([]Entry, 0, len(files))
	for _, f := range files {
		cs.Entries = append(cs.Entries, Entry{Path: f, Status: seen[f]})
	}
	return cs, nil
}

// parseNameStatus reads one "M\tpath" or "R100\told\tnew" record.
func parseNameStatus(line string) (path string, status Status, ok bool) {
	fields := strings.Split(strings.TrimSpace(line), "\t")
	if len(fields) < 2 || fields[0] == "" {
		return "", "", false
	}
	path = fields[len(fields)-1]
	switch fields[0][0] {
	case 'A':
		return path, StatusAdded, true
	case 'D':
		return path, StatusDeleted, true
	case 'R':
		// A rename adds the destination; the source is reported separately by
		// the deletion filter when it matters.
		return path, StatusAdded, true
	default:
		return path, StatusModified, true
	}
}

// GoFiles returns the change set entries that are Go source files.
func (c ChangeSet) GoFiles() []string {
	var out []string
	for _, f := range c.Files {
		if strings.HasSuffix(f, ".go") {
			out = append(out, f)
		}
	}
	return out
}

// TouchesModuleFiles reports whether go.mod or go.sum changed.
func (c ChangeSet) TouchesModuleFiles() bool {
	for _, f := range c.Files {
		if f == "go.mod" || f == "go.sum" {
			return true
		}
	}
	return false
}
