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
	// Note records why an earlier discovery source was passed over, so a
	// rejected cache entry is visible rather than silently skipped.
	Note string
}

// DiscoverGolangci locates the executable in the documented order: environment
// override, repository-local .tools, the provisioned cache, then PATH.
//
// A cached binary is re-hashed against its manifest before use. A cache entry
// that fails that check is passed over rather than executed, and the reason is
// carried on the result: corruption is an environment problem, and falling
// through still applies the exact version pin to whatever is found next, so no
// unverified binary can ever be trusted.
func DiscoverGolangci(repoRoot string) (Golangci, error) {
	if p := strings.TrimSpace(os.Getenv(GolangciLintEnvVar)); p != "" {
		return Golangci{Path: p, Source: "env " + GolangciLintEnvVar}, nil
	}
	local := filepath.Join(repoRoot, GolangciLintLocalPath)
	if info, err := os.Stat(local); err == nil && !info.IsDir() {
		return Golangci{Path: local, Source: GolangciLintLocalPath}, nil
	}

	path, note := discoverFromCache()
	if path != "" {
		return Golangci{Path: path, Source: "goharness cache"}, nil
	}

	p, err := exec.LookPath("golangci-lint")
	if err != nil {
		return Golangci{Note: note}, fmt.Errorf(
			"golangci-lint not found via %s, %s, the goharness cache, or PATH%s: %w",
			GolangciLintEnvVar, GolangciLintLocalPath, noteSuffix(note), err)
	}
	return Golangci{Path: p, Source: "PATH", Note: note}, nil
}

// discoverFromCache returns a verified cached binary, or the reason there is
// none. A missing entry is not worth reporting; a rejected one is.
func discoverFromCache() (path, note string) {
	cache, err := toolcache.Open()
	if err != nil {
		return "", ""
	}
	binary, err := cache.VerifiedToolBinary(toolcache.ToolGolangci, GolangciLintPin)
	switch {
	case err == nil:
		return binary, ""
	case errors.Is(err, toolcache.ErrNotProvisioned):
		return "", ""
	default:
		return "", "the cached binary was rejected: " + err.Error()
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
