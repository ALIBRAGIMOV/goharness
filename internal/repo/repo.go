// Package repo discovers the module under verification, captures git state, and
// provides the worktree-modification guard that backs the read-only guarantee.
package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// Git is the git access test seam. Production code uses ExecGit.
type Git interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
	Available(ctx context.Context) bool
}

// ExecGit runs git through a process Runner.
type ExecGit struct {
	Runner tool.Runner
}

// Run executes a git subcommand and returns its trimmed standard output.
func (g ExecGit) Run(ctx context.Context, dir string, args ...string) (string, error) {
	res, err := g.Runner.Run(ctx, tool.Command{Dir: dir, Name: "git", Args: args})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("git %s exited %d: %s",
			strings.Join(args, " "), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return strings.TrimRight(res.Stdout, "\n"), nil
}

// Available reports whether a git executable can be invoked.
func (g ExecGit) Available(ctx context.Context) bool {
	res, err := g.Runner.Run(ctx, tool.Command{Name: "git", Args: []string{"--version"}})
	return err == nil && res.ExitCode == 0
}

// Repository is the module under verification.
type Repository struct {
	Root        string
	ModulePath  string
	GoDirective string
	// ToolchainDirective is the go.mod `toolchain` line, empty when absent. A
	// module that names one is declaring a floor, often a security floor, and a
	// scan performed below it is judging a configuration the module forbids.
	ToolchainDirective string
	GitRoot            string
	// ModulePrefix is Root's slash-form path below GitRoot, without a trailing
	// slash and empty when the two coincide. Git reports paths from the
	// repository root while every check joins them onto the module root, so this
	// is the one value that translates between the two coordinate systems.
	ModulePrefix string
	HasGit       bool
	HasCommits   bool
	// Head is the commit the working tree sits on, empty when there is none. A
	// document that records what a repository acknowledged has to name the
	// revision it was true of, and that revision is the only copy of such a
	// document the harness ever trusts.
	Head string
}

// ErrNoModule is returned when no go.mod is found at or above the start
// directory.
var ErrNoModule = errors.New("no go.mod found in this directory or any parent")

// Discover walks up from dir to find the module root and, if present, the git
// worktree root.
func Discover(ctx context.Context, git Git, dir string) (Repository, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Repository{}, fmt.Errorf("resolving %q: %w", dir, err)
	}
	mod, err := findModule(abs)
	if err != nil {
		return Repository{}, err
	}
	r := Repository{
		Root: mod.root, ModulePath: mod.path,
		GoDirective: mod.goDirective, ToolchainDirective: mod.toolchain,
	}

	gitRoot, inRepo := tryGit(ctx, git, mod.root, "rev-parse", "--show-toplevel")
	if !inRepo {
		return r, nil
	}
	r.GitRoot = resolveSymlinks(strings.TrimSpace(gitRoot))
	r.HasGit = true
	// git answers this itself rather than being asked to agree with a computed
	// relative path: GitRoot is symlink-resolved and Root is not, so deriving the
	// prefix with filepath.Rel would disagree with git on any machine whose
	// temporary or home directory is a symlink.
	prefix, _ := tryGit(ctx, git, mod.root, "rev-parse", "--show-prefix")
	r.ModulePrefix = strings.Trim(strings.TrimSpace(prefix), "/")
	head, hasCommits := tryGit(ctx, git, mod.root, "rev-parse", "--verify", "HEAD")
	r.HasCommits = hasCommits
	r.Head = strings.TrimSpace(head)
	return r, nil
}

// tryGit runs a git query whose failure is a legitimate answer rather than an
// error: not a repository, or no commits yet.
func tryGit(ctx context.Context, git Git, dir string, args ...string) (string, bool) {
	out, err := git.Run(ctx, dir, args...)
	if err != nil {
		return "", false
	}
	return out, true
}

func resolveSymlinks(p string) string {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return resolved
}

// moduleFile is the part of a go.mod the harness reads.
type moduleFile struct {
	root        string
	path        string
	goDirective string
	toolchain   string
}

func findModule(start string) (moduleFile, error) {
	dir := start
	for {
		candidate := filepath.Join(dir, "go.mod")
		data, readErr := os.ReadFile(candidate)
		if readErr == nil {
			mod := parseGoMod(string(data))
			if mod.path == "" {
				return moduleFile{}, fmt.Errorf("%s has no module directive", candidate)
			}
			mod.root = dir
			return mod, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return moduleFile{}, fmt.Errorf("%w (searched upward from %s)", ErrNoModule, start)
		}
		dir = parent
	}
}

func parseGoMod(src string) moduleFile {
	var mod moduleFile
	for line := range strings.SplitSeq(src, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "module":
			if mod.path == "" {
				mod.path = fields[1]
			}
		case "go":
			if mod.goDirective == "" {
				mod.goDirective = fields[1]
			}
		case "toolchain":
			if mod.toolchain == "" {
				mod.toolchain = fields[1]
			}
		}
	}
	return mod
}
