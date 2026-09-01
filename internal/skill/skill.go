// Package skill ships the agent skill: the completion protocol, the reading
// order of the report and the routes an agent must not take, in the Agent
// Skills format that Claude Code and Codex both read from disk. The binary
// carries the text so that provisioning goharness provisions the protocol
// with it, and every installed copy is byte-identical to the release.
package skill

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed SKILL.md
var source []byte

// Name is the skill directory name, which is also the command an agent
// types to invoke it.
const Name = "goharness"

// marker is the frontmatter line that identifies a copy goharness wrote.
// Install replaces a file that carries it and refuses one that does not,
// because the other file is somebody's own skill under the same name.
const marker = "\n  source: goharness\n"

// Source returns the skill text as shipped.
func Source() string {
	return string(source)
}

// Target is one place a copy of the skill lives.
type Target struct {
	// Agent names the tool that reads this location.
	Agent string
	// Path is the SKILL.md location.
	Path string
}

// UserTargets lists the per-user skill locations of the agents goharness
// supports, under home: Claude Code reads ~/.claude/skills, Codex reads
// ~/.agents/skills.
func UserTargets(home string) []Target {
	return []Target{
		{Agent: "Claude Code", Path: filepath.Join(home, ".claude", "skills", Name, "SKILL.md")},
		{Agent: "Codex", Path: filepath.Join(home, ".agents", "skills", Name, "SKILL.md")},
	}
}

// ProjectTargets lists the repository-scoped locations under root, which
// both agents read for a project and which a cloud session or a teammate's
// checkout gets from the commit rather than from a machine.
func ProjectTargets(root string) []Target {
	return []Target{
		{Agent: "Claude Code", Path: filepath.Join(root, ".claude", "skills", Name, "SKILL.md")},
		{Agent: "Codex", Path: filepath.Join(root, ".agents", "skills", Name, "SKILL.md")},
	}
}

// Outcome says what Install found at the target and what it did.
type Outcome string

// Outcomes of Install.
const (
	// Installed means nothing was there and the skill was written.
	Installed Outcome = "installed"
	// Updated means an older goharness copy was replaced.
	Updated Outcome = "updated"
	// UpToDate means the copy there is already this release's text.
	UpToDate Outcome = "up to date"
)

// ErrForeignFile reports a file at the target that goharness did not write.
var ErrForeignFile = errors.New("a skill goharness did not write is already there")

// Status is what Inspect found at a target.
type Status string

// Statuses of Inspect.
const (
	// Current means the copy is this release's text.
	Current Status = "up to date"
	// Outdated means a goharness copy from another release is there.
	Outdated Status = "outdated"
	// Missing means nothing is there.
	Missing Status = "missing"
	// Foreign means a file goharness did not write is there.
	Foreign Status = "not goharness's"
)

// Inspect reports the state of one target without writing anything.
func Inspect(target Target) (Status, error) {
	existing, err := os.ReadFile(target.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Missing, nil
	case err != nil:
		return "", err
	case bytes.Equal(existing, source):
		return Current, nil
	case bytes.Contains(existing, []byte(marker)):
		return Outdated, nil
	default:
		return Foreign, nil
	}
}

// Install writes the skill at target, creating the directories above it. A
// copy goharness wrote is replaced; a file it did not write is left alone
// and reported as ErrForeignFile unless force is set. The write is a rename,
// so a reader never sees a partial file.
func Install(target Target, force bool) (Outcome, error) {
	status, err := Inspect(target)
	if err != nil {
		return "", fmt.Errorf("inspecting %s: %w", target.Path, err)
	}
	switch status {
	case Current:
		return UpToDate, nil
	case Foreign:
		if !force {
			return "", fmt.Errorf("%s: %w", target.Path, ErrForeignFile)
		}
	case Outdated, Missing:
	}
	dir := filepath.Dir(target.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	staged, err := os.CreateTemp(dir, "SKILL.md.*.tmp")
	if err != nil {
		return "", fmt.Errorf("staging the skill in %s: %w", dir, err)
	}
	staging := staged.Name()
	if _, err := staged.Write(source); err != nil {
		return "", errors.Join(fmt.Errorf("writing %s: %w", staging, err), staged.Close(), os.Remove(staging))
	}
	if err := staged.Close(); err != nil {
		return "", errors.Join(fmt.Errorf("closing %s: %w", staging, err), os.Remove(staging))
	}
	if err := os.Chmod(staging, 0o600); err != nil {
		return "", errors.Join(fmt.Errorf("setting the mode of %s: %w", staging, err), os.Remove(staging))
	}
	if err := os.Rename(staging, target.Path); err != nil {
		return "", errors.Join(fmt.Errorf("installing %s: %w", target.Path, err), os.Remove(staging))
	}
	if status == Missing {
		return Installed, nil
	}
	return Updated, nil
}
