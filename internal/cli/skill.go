package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/skill"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// runSkill serves the agent skill: prints it, or installs it where Claude
// Code and Codex read skills from.
func runSkill(ctx context.Context, args []string, streams Streams) int {
	if len(args) == 0 {
		p := newPrinter(streams.Err)
		p.printf("%s", commandUsage("skill"))
		return ExitInconclusive
	}
	switch args[0] {
	case "print":
		p := newPrinter(streams.Out)
		p.printf("%s", skill.Source())
		return exitFor(p, ExitAdmitted)
	case "install":
		return runSkillInstall(ctx, args[1:], streams)
	default:
		p := newPrinter(streams.Err)
		p.line("unknown skill subcommand %q", args[0])
		if suggestions := nearest(args[0], []string{"print", "install"}, 2); len(suggestions) > 0 {
			p.line("did you mean: %s", strings.Join(suggestions, ", "))
		}
		p.printf("\n%s", commandUsage("skill"))
		return ExitInconclusive
	}
}

func runSkillInstall(ctx context.Context, args []string, streams Streams) int {
	fs := flag.NewFlagSet("goharness skill install", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	project := fs.Bool("project", false, "install into the repository at --dir instead of the home directory")
	dir := fs.String("dir", ".", "any directory inside the repository, with --project")
	force := fs.Bool("force", false, "replace a skill file goharness did not write")
	if err := fs.Parse(args); err != nil {
		return ExitInconclusive
	}
	out := newPrinter(streams.Out)
	errOut := newPrinter(streams.Err)

	var targets []skill.Target
	if *project {
		root, err := projectRoot(ctx, *dir)
		if err != nil {
			errOut.line("goharness skill install: %v", err)
			return ExitInconclusive
		}
		targets = skill.ProjectTargets(root)
	} else {
		var err error
		if targets, err = userSkillTargets(); err != nil {
			errOut.line("goharness skill install: %v", err)
			return ExitInconclusive
		}
	}
	if !installSkill(out, errOut, targets, *force) {
		return ExitInconclusive
	}
	return exitFor(out, ExitAdmitted)
}

// projectRoot is where a repository-scoped skill goes: the git root when
// there is one, because that is the directory both agents treat as the
// project, and the module root otherwise.
func projectRoot(ctx context.Context, dir string) (string, error) {
	r, err := repo.Discover(ctx, repo.ExecGit{Runner: tool.ExecRunner{}}, dir)
	if err != nil {
		return "", err
	}
	if r.HasGit && r.GitRoot != "" {
		return r.GitRoot, nil
	}
	return r.Root, nil
}

func userSkillTargets() ([]skill.Target, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locating the home directory: %w", err)
	}
	return skill.UserTargets(home), nil
}

// installSkill writes every target and reports each on its own line. A file
// goharness did not write is named and left alone: replacing somebody's own
// skill is not a decision provisioning may take, and --force is the way to
// take it deliberately.
func installSkill(out, errOut *printer, targets []skill.Target, force bool) bool {
	ok := true
	for _, target := range targets {
		outcome, err := skill.Install(target, force)
		switch {
		case errors.Is(err, skill.ErrForeignFile):
			errOut.line("agent skill: %s: left alone, %s is a skill goharness did not write; "+
				"`goharness skill install --force` replaces it", target.Agent, target.Path)
			ok = false
		case err != nil:
			errOut.line("agent skill: %s: %v", target.Agent, err)
			ok = false
		default:
			out.line("agent skill: %s: %s at %s", target.Agent, outcome, target.Path)
		}
	}
	return ok
}

// reportSkill is the doctor's view of the skill copies: which agents on this
// machine carry this release's protocol. A missing copy is not a problem
// with the verdict, so it never makes the doctor unhealthy; it is a line with
// the command that installs it.
func reportSkill(out *printer) {
	targets, err := userSkillTargets()
	if err != nil {
		out.line("%s agent skill    %v", mark(false), err)
		return
	}
	for _, target := range targets {
		status, err := skill.Inspect(target)
		if err != nil {
			out.line("%s agent skill    %s: %v", mark(false), target.Agent, err)
			continue
		}
		out.line("%s agent skill    %s: %s (%s)", mark(status == skill.Current), target.Agent, status, target.Path)
		switch status {
		case skill.Missing, skill.Outdated:
			out.line("      fix: goharness skill install")
		case skill.Foreign:
			out.line("      note: goharness skill install --force replaces it")
		case skill.Current:
		}
	}
}
