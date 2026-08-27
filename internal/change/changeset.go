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
	// StatusRenamed is a file that moved. It is its own status rather than an
	// addition because the base revision holds the same code under another name,
	// and a comparison that does not know that reports every finding in the file
	// as introduced by the move.
	StatusRenamed Status = "renamed"
)

// Describe renders a status for a report sentence.
func (s Status) Describe() string { return string(s) }

// Entry is one changed file with the strongest status observed for it. A file
// that is added and then edited is still an addition; one that existed before
// is a modification.
type Entry struct {
	Path   string
	Status Status
	// OldPath is where a renamed file came from, module-relative, and empty for
	// every other status. It is what lets the base snapshot be read in head's
	// coordinate system.
	OldPath string
}

// ChangeSet is the set of files a verification run considers changed, together
// with the base it was computed against.
//
// Every path in Files and Entries is module-relative in slash form. That is the
// single coordinate system the rest of the harness joins against a module root,
// and mixing a repository-relative path into it silently disables every check
// that recognises a file by name.
type ChangeSet struct {
	Base       string
	BaseOrigin BaseOrigin
	Files      []string
	Entries    []Entry
	FullScope  bool
	// OutsideModule names the changed files the repository contains and this
	// module does not. They are neither evidence nor a gap in coverage, but a
	// reader of a monorepo report needs to see that they were seen and set aside.
	OutsideModule []string
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
	// Every query runs at the repository root. git diff reports the whole
	// repository wherever it is invoked, but ls-files reports only what lies
	// below the working directory, so asking from the module would make the
	// untracked half of the change set narrower than the tracked half.
	queryDir := r.Root
	if r.GitRoot != "" {
		queryDir = r.GitRoot
	}
	// Entries are keyed by repository-relative path here and translated into the
	// module's coordinates once, below.
	seen := map[string]Entry{}
	statuses, plain := listings(cs, r, base)
	cs.FullScope = !r.HasCommits
	if err := collect(ctx, git, queryDir, statuses, plain, seen); err != nil {
		return ChangeSet{}, err
	}

	repoPaths := make([]string, 0, len(seen))
	for f := range seen {
		repoPaths = append(repoPaths, f)
	}
	sort.Strings(repoPaths)

	cs.Entries = make([]Entry, 0, len(repoPaths))
	cs.Files = make([]string, 0, len(repoPaths))
	for _, repoPath := range repoPaths {
		rel, inModule := moduleRelative(repoPath, r.ModulePrefix)
		if !inModule {
			cs.OutsideModule = append(cs.OutsideModule, repoPath)
			continue
		}
		cs.Files = append(cs.Files, rel)
		cs.Entries = append(cs.Entries, moduleEntry(seen[repoPath], rel, r.ModulePrefix))
	}
	return cs, nil
}

// listings returns the git queries that between them name every changed file:
// the ones reporting a status per path, and the ones reporting bare paths.
//
// --full-name makes ls-files answer from the repository root, which is where git
// diff already answers from. Without it the two subcommands disagree by exactly
// the module prefix and the change set carries both coordinate systems at once.
func listings(cs ChangeSet, r repo.Repository, base string) (statuses, plain [][]string) {
	untracked := []string{"ls-files", "--others", "--exclude-standard", "--full-name"}
	if !r.HasCommits {
		return nil, [][]string{{"ls-files", "--full-name"}, untracked}
	}
	statuses = [][]string{
		{"diff", "--name-status", "--diff-filter=ACMRTD", "HEAD"},
		{"diff", "--name-status", "--diff-filter=ACMRTD", "--cached", "HEAD"},
	}
	if cs.HasBase() {
		statuses = append(statuses,
			[]string{"diff", "--name-status", "--diff-filter=ACMRTD", base, "HEAD"})
	}
	return statuses, [][]string{untracked}
}

// collect runs the listings and records what they name into seen.
//
// The first strong status for a path wins. An addition and a rename both say the
// base revision does not hold this path under this name, and a later plain diff
// reporting the same file as modified would erase that.
func collect(
	ctx context.Context, git repo.Git, dir string, statuses, plain [][]string, seen map[string]Entry,
) error {
	record := func(e Entry) {
		e.Path = strings.TrimSpace(e.Path)
		if e.Path == "" {
			return
		}
		if existing, ok := seen[e.Path]; ok && existing.Status != StatusModified {
			return
		}
		seen[e.Path] = e
	}
	for _, args := range statuses {
		out, err := git.Run(ctx, dir, args...)
		if err != nil {
			return fmt.Errorf("listing changed files (git %s): %w", strings.Join(args, " "), err)
		}
		for line := range strings.SplitSeq(out, "\n") {
			if e, ok := parseNameStatus(line); ok {
				record(e)
			}
		}
	}
	for _, args := range plain {
		out, err := git.Run(ctx, dir, args...)
		if err != nil {
			return fmt.Errorf("listing changed files (git %s): %w", strings.Join(args, " "), err)
		}
		for line := range strings.SplitSeq(out, "\n") {
			record(Entry{Path: line, Status: StatusAdded})
		}
	}
	return nil
}

// moduleEntry translates one recorded entry into the module's coordinates. A
// rename whose source lies outside the module is an addition as far as this
// module can tell, which is the honest reading: the base revision of this module
// holds nothing under that name.
func moduleEntry(e Entry, rel, modulePrefix string) Entry {
	e.Path = rel
	if e.Status != StatusRenamed {
		return e
	}
	oldRel, inModule := moduleRelative(e.OldPath, modulePrefix)
	if !inModule || oldRel == rel {
		return Entry{Path: rel, Status: StatusAdded}
	}
	e.OldPath = oldRel
	return e
}

// moduleRelative translates one repository-relative path into the module's
// coordinate system, reporting whether the module contains it at all.
//
// This is the single place the translation happens. Every git subcommand the
// change set reads is asked for repository-relative paths, so a caller never
// has to know which convention a particular subcommand prefers, and a path that
// reaches a check can only be module-relative.
func moduleRelative(repoPath, modulePrefix string) (string, bool) {
	if modulePrefix == "" {
		return repoPath, true
	}
	rest, ok := strings.CutPrefix(repoPath, modulePrefix+"/")
	if !ok || rest == "" {
		return "", false
	}
	return rest, true
}

// parseNameStatus reads one "M\tpath" or "R100\told\tnew" record.
//
// The source of a rename is kept. Discarding it and calling the destination an
// addition is what once made a branch that moved a file introduce every finding
// that file already carried.
func parseNameStatus(line string) (Entry, bool) {
	fields := strings.Split(strings.TrimSpace(line), "\t")
	if len(fields) < 2 || fields[0] == "" {
		return Entry{}, false
	}
	path := fields[len(fields)-1]
	switch fields[0][0] {
	case 'A':
		return Entry{Path: path, Status: StatusAdded}, true
	case 'D':
		return Entry{Path: path, Status: StatusDeleted}, true
	case 'R':
		if len(fields) < 3 {
			return Entry{Path: path, Status: StatusAdded}, true
		}
		return Entry{Path: path, Status: StatusRenamed, OldPath: fields[len(fields)-2]}, true
	default:
		return Entry{Path: path, Status: StatusModified}, true
	}
}

// Renames maps each moved file's path at head onto the path it had at base,
// module-relative. It is what a base evidence set is realigned through before
// the two revisions are compared.
func (c ChangeSet) Renames() map[string]string {
	var out map[string]string
	for _, e := range c.Entries {
		if e.Status != StatusRenamed || e.OldPath == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[e.OldPath] = e.Path
	}
	return out
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
