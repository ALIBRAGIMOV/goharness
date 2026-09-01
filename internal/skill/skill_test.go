package skill_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/skill"
)

// TestSourceIsAnAgentSkill pins the shape both Claude Code and Codex parse:
// a frontmatter with name and description, the marker Install recognises,
// and a description short enough for the listing that decides when the
// skill loads.
func TestSourceIsAnAgentSkill(t *testing.T) {
	t.Parallel()
	src := skill.Source()
	if !strings.HasPrefix(src, "---\nname: goharness\ndescription: ") {
		t.Fatalf("the skill does not open with the name and description frontmatter:\n%.120s", src)
	}
	if !strings.Contains(src, "\n  source: goharness\n") {
		t.Fatalf("the skill carries no goharness marker, so Install could not tell its own copies apart")
	}
	description, _, _ := strings.Cut(strings.TrimPrefix(src, "---\nname: goharness\ndescription: "), "\n")
	if len(description) > 1024 {
		t.Fatalf("the description is %d bytes; the listing an agent reads truncates long ones", len(description))
	}
	for _, want := range []string{
		"goharness verify --agent", "sufficientForCompletion", "INCONCLUSIVE",
		"//nolint", "GH-POLICY-001", "goharness explain", "--base",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("the skill does not mention %q", want)
		}
	}
}

func TestInstallWritesReplacesAndLeavesOtherPeoplesFilesAlone(t *testing.T) {
	t.Parallel()
	target := skill.Target{Agent: "test", Path: filepath.Join(t.TempDir(), "skills", "goharness", "SKILL.md")}

	if status, err := skill.Inspect(target); err != nil || status != skill.Missing {
		t.Fatalf("Inspect before install = %q, %v; want %q", status, err, skill.Missing)
	}
	if outcome, err := skill.Install(target, false); err != nil || outcome != skill.Installed {
		t.Fatalf("first Install = %q, %v; want %q", outcome, err, skill.Installed)
	}
	if got, err := os.ReadFile(target.Path); err != nil || string(got) != skill.Source() {
		t.Fatalf("the installed copy differs from the shipped skill (err %v)", err)
	}
	if outcome, err := skill.Install(target, false); err != nil || outcome != skill.UpToDate {
		t.Fatalf("second Install = %q, %v; want %q", outcome, err, skill.UpToDate)
	}

	older := strings.Replace(skill.Source(), "# goharness", "# goharness (an earlier release)", 1)
	if err := os.WriteFile(target.Path, []byte(older), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, err := skill.Inspect(target); err != nil || status != skill.Outdated {
		t.Fatalf("Inspect of an older copy = %q, %v; want %q", status, err, skill.Outdated)
	}
	if outcome, err := skill.Install(target, false); err != nil || outcome != skill.Updated {
		t.Fatalf("Install over an older copy = %q, %v; want %q", outcome, err, skill.Updated)
	}

	foreign := "---\nname: goharness\ndescription: somebody's own notes\n---\n\nKeep these.\n"
	if err := os.WriteFile(target.Path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, err := skill.Inspect(target); err != nil || status != skill.Foreign {
		t.Fatalf("Inspect of a foreign file = %q, %v; want %q", status, err, skill.Foreign)
	}
	if _, err := skill.Install(target, false); !errors.Is(err, skill.ErrForeignFile) {
		t.Fatalf("Install over a foreign file = %v; want %v", err, skill.ErrForeignFile)
	}
	if got, err := os.ReadFile(target.Path); err != nil || string(got) != foreign {
		t.Fatalf("a refused install still changed the file (err %v)", err)
	}
	if outcome, err := skill.Install(target, true); err != nil || outcome != skill.Updated {
		t.Fatalf("forced Install over a foreign file = %q, %v; want %q", outcome, err, skill.Updated)
	}
	if got, err := os.ReadFile(target.Path); err != nil || string(got) != skill.Source() {
		t.Fatalf("the forced install did not write the shipped skill (err %v)", err)
	}
}

func TestTargetsNameBothAgents(t *testing.T) {
	t.Parallel()
	user := skill.UserTargets("/home/me")
	project := skill.ProjectTargets("/src/repo")
	if len(user) != 2 || len(project) != 2 {
		t.Fatalf("targets = %v / %v; want one per agent", user, project)
	}
	if user[0].Path != filepath.Join("/home/me", ".claude", "skills", "goharness", "SKILL.md") ||
		user[1].Path != filepath.Join("/home/me", ".agents", "skills", "goharness", "SKILL.md") {
		t.Fatalf("user targets = %v", user)
	}
	if project[0].Path != filepath.Join("/src/repo", ".claude", "skills", "goharness", "SKILL.md") ||
		project[1].Path != filepath.Join("/src/repo", ".agents", "skills", "goharness", "SKILL.md") {
		t.Fatalf("project targets = %v", project)
	}
}
