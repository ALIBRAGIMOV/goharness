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
	GitRoot     string
	HasGit      bool
	HasCommits  bool
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
	root, modPath, goDirective, err := findModule(abs)
	if err != nil {
		return Repository{}, err
	}
	r := Repository{Root: root, ModulePath: modPath, GoDirective: goDirective}

	gitRoot, inRepo := tryGit(ctx, git, root, "rev-parse", "--show-toplevel")
	if !inRepo {
		return r, nil
	}
	r.GitRoot = resolveSymlinks(strings.TrimSpace(gitRoot))
	r.HasGit = true
	_, r.HasCommits = tryGit(ctx, git, root, "rev-parse", "--verify", "HEAD")
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

func findModule(start string) (root, modulePath, goDirective string, err error) {
	dir := start
	for {
		candidate := filepath.Join(dir, "go.mod")
		data, readErr := os.ReadFile(candidate)
		if readErr == nil {
			mod, directive := parseGoMod(string(data))
			if mod == "" {
				return "", "", "", fmt.Errorf("%s has no module directive", candidate)
			}
			return dir, mod, directive, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", "", fmt.Errorf("%w (searched upward from %s)", ErrNoModule, start)
		}
		dir = parent
	}
}

func parseGoMod(src string) (modulePath, goDirective string) {
	for line := range strings.SplitSeq(src, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "module":
			if modulePath == "" {
				modulePath = fields[1]
			}
		case "go":
			if goDirective == "" {
				goDirective = fields[1]
			}
		}
	}
	return modulePath, goDirective
}
