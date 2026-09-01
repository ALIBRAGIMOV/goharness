package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/cli"
	"github.com/ALIBRAGIMOV/goharness/internal/skill"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache/toolcachetest"
)

// useHome points every per-user skill location at a private directory, so
// no test writes into the developer's own agent configuration.
func useHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestSkillPrintWritesTheShippedSkill(t *testing.T) {
	code, out, errOut := invoke(t, "skill", "print")
	if code != cli.ExitAdmitted {
		t.Fatalf("skill print exit = %d\n%s", code, errOut)
	}
	if out != skill.Source() {
		t.Fatalf("skill print did not write the shipped skill byte for byte")
	}
}

func TestSkillInstallWritesBothAgentsUnderHome(t *testing.T) {
	home := useHome(t)
	code, out, errOut := invoke(t, "skill", "install")
	if code != cli.ExitAdmitted {
		t.Fatalf("skill install exit = %d\n%s%s", code, out, errOut)
	}
	for _, target := range skill.UserTargets(home) {
		got, err := os.ReadFile(target.Path)
		if err != nil || string(got) != skill.Source() {
			t.Fatalf("%s copy at %s: %v", target.Agent, target.Path, err)
		}
		if !strings.Contains(out, target.Agent+": installed at "+target.Path) {
			t.Fatalf("install did not report the %s copy:\n%s", target.Agent, out)
		}
	}

	code, out, _ = invoke(t, "skill", "install")
	if code != cli.ExitAdmitted || !strings.Contains(out, "up to date") {
		t.Fatalf("second install exit = %d, output:\n%s", code, out)
	}
}

func TestSkillInstallLeavesSomebodyElsesSkillAlone(t *testing.T) {
	home := useHome(t)
	foreign := skill.UserTargets(home)[0]
	writeFile(t, foreign.Path, "---\nname: goharness\ndescription: my own notes\n---\n")

	code, _, errOut := invoke(t, "skill", "install")
	if code != cli.ExitInconclusive {
		t.Fatalf("install over a foreign skill exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if !strings.Contains(errOut, "did not write") || !strings.Contains(errOut, "--force") {
		t.Fatalf("the refusal does not say what was found or how to replace it:\n%s", errOut)
	}
	if got, err := os.ReadFile(foreign.Path); err != nil || !strings.Contains(string(got), "my own notes") {
		t.Fatalf("the foreign skill was overwritten without --force (err %v)", err)
	}

	if code, _, errOut := invoke(t, "skill", "install", "--force"); code != cli.ExitAdmitted {
		t.Fatalf("forced install exit = %d\n%s", code, errOut)
	}
	if got, err := os.ReadFile(foreign.Path); err != nil || string(got) != skill.Source() {
		t.Fatalf("--force did not replace the foreign skill (err %v)", err)
	}
}

func TestSkillInstallProjectWritesUnderTheRepositoryRoot(t *testing.T) {
	useHome(t)
	dir := newFixtureRepo(t)
	code, out, errOut := invoke(t, "skill", "install", "--project", "--dir", filepath.Join(dir, "lib"))
	if code != cli.ExitAdmitted {
		t.Fatalf("skill install --project exit = %d\n%s%s", code, out, errOut)
	}
	for _, target := range skill.ProjectTargets(dir) {
		if got, err := os.ReadFile(target.Path); err != nil || string(got) != skill.Source() {
			t.Fatalf("%s project copy at %s: %v", target.Agent, target.Path, err)
		}
	}
}

func TestSetupInstallsTheSkillUnlessToldNotTo(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	serveVulnDB(t, toolcachetest.VulnerableSyncDB())
	home := useHome(t)

	code, out, errOut := invoke(t, "setup")
	if code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\n%s%s", code, out, errOut)
	}
	for _, target := range skill.UserTargets(home) {
		if _, err := os.Stat(target.Path); err != nil {
			t.Fatalf("setup did not install the %s skill: %v", target.Agent, err)
		}
	}
	if !strings.Contains(out, "agent skill: Claude Code: installed") {
		t.Fatalf("setup does not report the skill it installed:\n%s", out)
	}

	other := useHome(t)
	if code, _, errOut := invoke(t, "setup", "--no-skill"); code != cli.ExitAdmitted {
		t.Fatalf("setup --no-skill exit = %d\n%s", code, errOut)
	}
	for _, target := range skill.UserTargets(other) {
		if _, err := os.Stat(target.Path); err == nil {
			t.Fatalf("setup --no-skill still installed the %s skill", target.Agent)
		}
	}
}

func TestDoctorReportsTheSkillCopies(t *testing.T) {
	home := useHome(t)
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, out, _ := invoke(t, "doctor", "--dir", dir)
	if !strings.Contains(out, "agent skill    Claude Code: missing") ||
		!strings.Contains(out, "fix: goharness skill install") {
		t.Fatalf("doctor does not report a missing skill with its fix:\n%s", out)
	}
	if code, _, errOut := invoke(t, "skill", "install"); code != cli.ExitAdmitted {
		t.Fatalf("skill install exit = %d\n%s", code, errOut)
	}
	_, out, _ = invoke(t, "doctor", "--dir", dir)
	for _, target := range skill.UserTargets(home) {
		if !strings.Contains(out, target.Agent+": up to date ("+target.Path+")") {
			t.Fatalf("doctor does not report the installed %s copy:\n%s", target.Agent, out)
		}
	}
}

// TestCommittedSkillCopiesMatchTheShippedSkill keeps the repository's own
// project-scoped copies, which the agents working here read, identical to
// the text the binary ships. `goharness skill install --project` refreshes
// them.
func TestCommittedSkillCopiesMatchTheShippedSkill(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, target := range skill.ProjectTargets(root) {
		got, err := os.ReadFile(target.Path)
		if err != nil {
			t.Fatalf("reading the committed %s copy: %v", target.Agent, err)
		}
		if string(got) != skill.Source() {
			t.Fatalf("%s differs from the shipped skill; run `goharness skill install --project`", target.Path)
		}
	}
}
