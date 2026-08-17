package tool

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// GolangciLintPin is the exact golangci-lint version the harness trusts. Any
// other version yields INCONCLUSIVE rather than a silently different verdict.
const GolangciLintPin = "2.12.2"

// GolangciLintEnvVar overrides binary discovery.
const GolangciLintEnvVar = "GOHARNESS_GOLANGCI_LINT"

// GolangciLintLocalPath is the repository-local location searched after the
// environment override and before PATH.
const GolangciLintLocalPath = ".tools/golangci-lint"

//go:embed golangci_strict.yaml
var strictConfig []byte

// StrictConfig returns the embedded strict golangci-lint configuration.
func StrictConfig() []byte {
	out := make([]byte, len(strictConfig))
	copy(out, strictConfig)
	return out
}

// Golangci is a discovered golangci-lint executable.
type Golangci struct {
	Path    string
	Version string
	Source  string
	// SHA256 is the hash the executable was accepted on, recorded in the report
	// so a verdict is attributable to the exact binary that produced it.
	SHA256 string
	// Note records why earlier discovery sources were passed over, so a rejected
	// candidate is visible rather than silently skipped.
	Note string
}

// DiscoverGolangci locates a golangci-lint executable the harness can trust.
//
// It searches the documented order (environment override, repository-local
// .tools, the provisioned cache, then PATH) and accepts a candidate only when
// the file hashes to the sum pinned for this platform. Identity comes from the
// bytes, never from the binary's own account of itself: printing the pinned
// version takes three lines of shell, and .tools sits inside the repository
// that the change under verification can write to. A candidate that does not
// match is passed over with the reason recorded, and a run that finds nothing
// trustworthy reports the linter's evidence as unproducible instead of
// believing an unknown program.
func DiscoverGolangci(repoRoot string) (Golangci, error) {
	var d discovery
	if p := strings.TrimSpace(os.Getenv(GolangciLintEnvVar)); p != "" {
		if g, ok := d.accept(p, "env "+GolangciLintEnvVar); ok {
			return g, nil
		}
	}
	local := filepath.Join(repoRoot, GolangciLintLocalPath)
	if info, err := os.Stat(local); err == nil && !info.IsDir() {
		if g, ok := d.accept(local, GolangciLintLocalPath); ok {
			return g, nil
		}
	}
	if path, ok := d.fromCache(); ok {
		if g, ok := d.accept(path, "goharness cache"); ok {
			return g, nil
		}
	}
	if path, err := exec.LookPath("golangci-lint"); err == nil {
		if g, ok := d.accept(path, "PATH"); ok {
			return g, nil
		}
	}
	return Golangci{Note: d.note()}, fmt.Errorf(
		"no golangci-lint matching the pinned %s release was found via %s, %s, the goharness cache, or PATH%s",
		GolangciLintPin, GolangciLintEnvVar, GolangciLintLocalPath, noteSuffix(d.note()))
}

// discovery accumulates why candidates were passed over, so a failed search can
// say what it found rather than only that it found nothing.
type discovery struct {
	rejected []string
}

func (d *discovery) reject(origin, reason string) {
	d.rejected = append(d.rejected, origin+" "+reason)
}

func (d *discovery) note() string {
	return strings.Join(d.rejected, "; ")
}

// accept verifies one candidate against the pinned sum for this platform.
func (d *discovery) accept(path, origin string) (Golangci, bool) {
	pinned, known := toolcache.GolangciBinarySum(toolcache.CurrentPlatform())
	if !known {
		d.reject(origin, "cannot be verified: no golangci-lint binary checksum is pinned for "+
			toolcache.CurrentPlatform())
		return Golangci{}, false
	}
	sum, err := toolcache.SumFile(path)
	if err != nil {
		d.reject(origin, "could not be read: "+err.Error())
		return Golangci{}, false
	}
	if sum != pinned {
		d.reject(origin, "is not the pinned release: "+path+" hashes to "+sum)
		return Golangci{}, false
	}
	return Golangci{Path: path, Source: origin, SHA256: sum}, true
}

// fromCache returns the provisioned binary if the cache holds one that still
// matches its own manifest. A missing entry is not worth reporting; a corrupt
// one is.
func (d *discovery) fromCache() (string, bool) {
	cache, err := toolcache.Open()
	if err != nil {
		return "", false
	}
	binary, err := cache.VerifiedToolBinary(toolcache.ToolGolangci, GolangciLintPin)
	switch {
	case err == nil:
		return binary, true
	case errors.Is(err, toolcache.ErrNotProvisioned):
		return "", false
	default:
		d.reject("the goharness cache", "was rejected: "+err.Error())
		return "", false
	}
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return " (" + note + ")"
}

// ResolveVersion runs the binary's version command and records the parsed
// version on the returned value.
func (g Golangci) ResolveVersion(ctx context.Context, runner Runner) (Golangci, error) {
	res, err := runner.Run(ctx, Command{Name: g.Path, Args: []string{"--version"}})
	if err != nil {
		return g, fmt.Errorf("querying golangci-lint version: %w", err)
	}
	if res.ExitCode != 0 {
		return g, fmt.Errorf("golangci-lint --version exited %d: %s",
			res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout))
	}
	g.Version = parseGolangciVersion(res.Stdout + res.Stderr)
	if g.Version == "" {
		return g, fmt.Errorf("could not parse golangci-lint version from %q", strings.TrimSpace(res.Stdout))
	}
	return g, nil
}

// MatchesPin reports whether the discovered version equals the pin.
func (g Golangci) MatchesPin() bool {
	return g.Version == GolangciLintPin
}

func parseGolangciVersion(out string) string {
	for field := range strings.FieldsSeq(out) {
		trimmed := strings.TrimPrefix(field, "v")
		if trimmed == "" || (trimmed[0] < '0' || trimmed[0] > '9') {
			continue
		}
		if strings.Count(trimmed, ".") >= 2 {
			return trimmed
		}
	}
	return ""
}

// GolangciIssue is one finding from the JSON report.
type GolangciIssue struct {
	FromLinter string `json:"FromLinter"`
	Text       string `json:"Text"`
	Severity   string `json:"Severity"`
	Pos        struct {
		Filename string `json:"Filename"`
		Line     int    `json:"Line"`
		Column   int    `json:"Column"`
	} `json:"Pos"`
}

type golangciReport struct {
	Issues []GolangciIssue `json:"Issues"`
}

// WriteStrictConfig materializes the embedded configuration inside dir and
// returns its path. The target repository's own configuration is never read.
func WriteStrictConfig(dir string) (string, error) {
	path := filepath.Join(dir, ".golangci.yaml")
	if err := os.WriteFile(path, StrictConfig(), 0o600); err != nil {
		return "", fmt.Errorf("writing embedded golangci config: %w", err)
	}
	return path, nil
}

// RunGolangci lints the given package patterns with the embedded configuration.
// Exit status 0 (clean) and 1 (issues found) are both normal; any other status
// is a tool failure and is returned as an error.
func RunGolangci(ctx context.Context, runner Runner, g Golangci, dir, configPath string, patterns []string) ([]GolangciIssue, error) {
	args := []string{
		"run",
		"--config", configPath,
		"--output.json.path", "stdout",
		"--output.text.path", "stderr",
		"--show-stats=false",
		"--allow-parallel-runners",
	}
	args = append(args, patterns...)

	res, err := runner.Run(ctx, Command{Dir: dir, Name: g.Path, Args: args})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 && res.ExitCode != 1 {
		return nil, fmt.Errorf("golangci-lint exited %d: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr+res.Stdout, 20)))
	}
	payload := strings.TrimSpace(res.Stdout)
	if payload == "" {
		return nil, fmt.Errorf("golangci-lint produced no JSON report (exit %d): %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
	}
	var report golangciReport
	if err := json.Unmarshal([]byte(payload), &report); err != nil {
		return nil, fmt.Errorf("decoding golangci-lint JSON report: %w", err)
	}
	return report.Issues, nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
