package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

func runDoctor(ctx context.Context, args []string, streams Streams) int {
	fs := flag.NewFlagSet("goharness doctor", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	dir := fs.String("dir", ".", "directory inside the module to inspect")
	if err := fs.Parse(args); err != nil {
		return ExitInconclusive
	}

	runner := tool.ExecRunner{}
	git := repo.ExecGit{Runner: runner}
	out := newPrinter(streams.Out)
	healthy := true

	out.line("goharness %s", Version)
	out.line("%s go toolchain   %s", mark(true), tool.GoVersion())

	gitOK := git.Available(ctx)
	out.line("%s git            %s", mark(gitOK), gitLabel(gitOK))
	if !gitOK {
		out.line("      fix: install git and make sure it is on PATH")
	}
	healthy = healthy && gitOK

	r, err := repo.Discover(ctx, git, *dir)
	if err != nil {
		out.line("%s module         %v", mark(false), err)
		out.line("      fix: run goharness from inside a Go module, or pass --dir")
		healthy = false
	} else {
		out.line("%s module         %s (go %s) at %s", mark(true), r.ModulePath, r.GoDirective, r.Root)
		out.line("%s git repository %s", mark(true), gitStateLabel(r))
		healthy = reportToolchainFloor(ctx, out, runner, r) && healthy
	}

	healthy = reportGolangci(ctx, out, runner, r) && healthy
	healthy = reportGoFix(ctx, out, runner, *dir) && healthy
	healthy = reportStaleWorktrees(ctx, out, git, r) && healthy
	reportPath(out)
	reportSubprocessEnv(out)

	reportScanner(out)
	cache, cacheHealthy := reportCache(out)
	healthy = cacheHealthy && healthy
	healthy = reportVulnDB(out, cache, time.Now()) && healthy
	reportSkill(out)

	out.line("")
	out.line("uber guide pin: %s", policy.UberGuideCommit)
	out.line("report schema:  %s", report.SchemaID)
	out.line("policy packs:   %s", strings.Join([]string{
		policy.PackGoCore, policy.PackGoFix, policy.PackGolangciStrict, policy.PackUberGuide,
		policy.PackAgentHygiene, policy.PackTestEffectiveness,
		policy.PackArchitecture, policy.PackMaintainability, policy.PackDiffEvidence,
	}, ", "))
	out.line("strict linters: %s", strings.Join(policy.EnabledLinters(), ", "))

	if healthy {
		out.line("\nhealthy: goharness can produce a trustworthy verdict here.")
		return exitFor(out, ExitAdmitted)
	}
	out.line("\nproblems found: apply the fix lines above before trusting a verdict.")
	return ExitInconclusive
}

// reportSubprocessEnv names the settings the harness takes away from the
// commands it runs, so a developer whose local GOFLAGS stop applying can see
// why here rather than guessing at a verdict that disagrees with their shell.
func reportSubprocessEnv(out *printer) {
	var present []string
	for _, name := range []string{"GOFLAGS", "GOTOOLCHAIN"} {
		if value := os.Getenv(name); value != "" {
			present = append(present, name+"="+value)
		}
	}
	out.line("%s subprocess env GOFLAGS and GOTOOLCHAIN are not inherited; %s",
		mark(true), tool.ForcedToolchain)
	if len(present) > 0 {
		out.line("      your shell sets %s; verification runs without it", strings.Join(present, ", "))
	}
}

// reportScanner shows the embedded scanner. There is no PATH probe: the
// scanner is a library dependency of this binary, so it is present exactly when
// the binary is.
// reportGoFix compares the analyzer set the policy declares with the one the
// installed toolchain registers.
//
// An enabled analyzer the toolchain does not have breaks the run, so it is a
// problem here. One the toolchain added and the policy never classified is not:
// the verdict stays trustworthy on the analyzers that did run. It is reported
// because nothing else would ever say so, and an analyzer silently not running
// is how a gate loses coverage between toolchain releases.
func reportGoFix(ctx context.Context, out *printer, runner tool.Runner, dir string) bool {
	enabled := policy.GoFixAnalyzers()
	support, err := tool.InspectFixAnalyzers(ctx, runner, dir, enabled, policy.GoFixKnownAnalyzers())
	if err != nil {
		out.line("%s go fix         %v", mark(false), err)
		out.line("      fix: run `go tool fix help` to see what this toolchain provides")
		return false
	}
	if len(support.Missing) > 0 {
		out.line("%s go fix         %s does not register %s", mark(false),
			tool.GoVersion(), strings.Join(support.Missing, ", "))
		out.line("      fix: install the pinned Go toolchain, or reclassify those analyzers in the registry")
		return false
	}
	out.line("%s go fix         %d analyzers enabled, read-only (-json)", mark(true), len(enabled))
	if len(support.Unregistered) > 0 {
		out.line("      note: this toolchain also offers %s, which the policy has not classified",
			strings.Join(support.Unregistered, ", "))
	}
	return true
}

func reportScanner(out *printer) {
	out.line("%s vuln scanner   embedded golang.org/x/vuln %s", mark(true),
		orUnknown(tool.XVulnVersion()))
	out.line("%s leak check     %s profile, read by a TestMain injected into race runs (needs %s or later on PATH)",
		mark(true), leakcheck.Method, leakcheck.MinimumGoVersion)
}

// reportCache inspects the provisioned cache. Doctor only reads: it reports
// what is missing and the command that fixes it, and never provisions.
func reportCache(out *printer) (*toolcache.Cache, bool) {
	cache, err := toolcache.Open()
	if err != nil {
		out.line("%s cache          %v", mark(false), err)
		return nil, false
	}
	size, sizeErr := cache.Size()
	if sizeErr != nil {
		out.line("%s cache          %s (size unknown: %v)", mark(true), cache.Root(), sizeErr)
	} else {
		out.line("%s cache          %s (%s)", mark(true), cache.Root(), humanBytes(size))
	}
	return cache, reportToolManifest(out, cache)
}

// reportToolManifest reports the cached linter. A missing entry is only a
// warning, because the linter may legitimately come from the environment
// override, the repository .tools directory, or PATH. A cached entry that no
// longer matches its manifest is a failure: something rewrote a payload the
// cache promised was immutable.
func reportToolManifest(out *printer, cache *toolcache.Cache) bool {
	manifest, err := cache.ReadToolManifest(toolcache.ToolGolangci, tool.GolangciLintPin)
	if err != nil {
		if errors.Is(err, toolcache.ErrNotProvisioned) {
			out.line("[warn] cached linter  golangci-lint %s is not in the cache", tool.GolangciLintPin)
			out.line("      fix: goharness setup")
			return true
		}
		out.line("%s cached linter  %v", mark(false), err)
		return false
	}
	if _, err := cache.VerifiedToolBinary(toolcache.ToolGolangci, tool.GolangciLintPin); err != nil {
		out.line("%s cached linter  %v", mark(false), err)
		out.line("      fix: goharness setup")
		return false
	}
	out.line("%s cached linter  golangci-lint %s for %s (binary sha256 %s)",
		mark(true), manifest.Version, manifest.Platform, manifest.BinarySHA256[:12])
	return true
}

// reportVulnDB verifies the snapshot's tree checksum and its freshness. A stale
// snapshot is a warning, never a failure: an old database still finds every
// vulnerability it knows about.
func reportVulnDB(out *printer, cache *toolcache.Cache, now time.Time) bool {
	if cache == nil {
		return false
	}
	if !cache.HasVulnDB() {
		out.line("[warn] vuln database  no snapshot; `goharness audit` reports its security claim INCONCLUSIVE")
		out.line("      fix: goharness setup")
		return true
	}
	manifest, err := cache.VerifyVulnDB()
	if err != nil {
		out.line("%s vuln database  %v", mark(false), err)
		out.line("      fix: goharness tools update")
		return false
	}
	days := int(manifest.Age(now).Hours() / 24)
	if manifest.Stale(now) {
		out.line("[warn] vuln database  %d entries, modified %s (%d days ago, over the %d day budget)",
			manifest.EntryCount, manifest.Modified.UTC().Format("2006-01-02"),
			days, int(toolcache.StaleAfter.Hours()/24))
		out.line("      fix: goharness tools update")
		return true
	}
	out.line("%s vuln database  %d entries, modified %s (%d day(s) ago, tree sha256 %s)",
		mark(true), manifest.EntryCount, manifest.Modified.UTC().Format("2006-01-02"),
		days, manifest.TreeChecksum[:12])
	return true
}

func orUnknown(v string) string {
	if v == "" {
		return "(version unavailable)"
	}
	return v
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for rest := n / unit; rest >= unit; rest /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func mark(ok bool) string {
	if ok {
		return "[ok]  "
	}
	return "[FAIL]"
}

func gitLabel(ok bool) string {
	if ok {
		return "available"
	}
	return "not found on PATH"
}

// reportStaleWorktrees finds base worktrees a previous run could not remove,
// which is what a second interrupt leaves behind, and prints the exact removal
// command.
func reportStaleWorktrees(ctx context.Context, out *printer, git repo.Git, r repo.Repository) bool {
	if !r.HasGit {
		return true
	}
	stale, err := repo.StaleWorktrees(ctx, git, r.Root)
	if err != nil {
		out.line("%s worktrees      could not be listed: %v", mark(false), err)
		return false
	}
	if len(stale) == 0 {
		out.line("%s worktrees      no stale goharness worktrees", mark(true))
		return true
	}
	out.line("%s worktrees      %d stale goharness worktree(s) from an interrupted run", mark(false), len(stale))
	for _, path := range stale {
		out.line("      fix: git worktree remove --force %s", path)
	}
	return false
}

func reportPath(out *printer) {
	entries := filepath.SplitList(os.Getenv("PATH"))
	out.line("%s PATH           %d entries", mark(len(entries) > 0), len(entries))
}

// golangciInstall is the only route that ends in a trusted binary. A locally
// built one reports the pinned version and hashes to something else, so the
// harness will not use it; provisioning downloads the pinned release and
// verifies it against the checksum shipped in this binary.
const golangciInstall = "goharness setup"

func reportGolangci(ctx context.Context, out *printer, runner tool.Runner, r repo.Repository) bool {
	g, err := tool.DiscoverGolangci(r.Root)
	if err != nil {
		out.line("%s golangci-lint  %v", mark(false), err)
		out.line("      fix: %s", golangciInstall)
		return false
	}
	g, err = g.ResolveVersion(ctx, runner)
	if err != nil {
		out.line("%s golangci-lint  %s: %v", mark(false), g.Path, err)
		out.line("      fix: %s", golangciInstall)
		return false
	}
	if !g.MatchesPin() {
		out.line("%s golangci-lint  %s reports %s, pinned %s", mark(false), g.Path, g.Version, tool.GolangciLintPin)
		out.line("      fix: %s", golangciInstall)
		return false
	}
	out.line("%s golangci-lint  %s (%s, sha256 %s, via %s)",
		mark(true), g.Version, g.Path, g.SHA256[:12], g.Source)
	if g.Note != "" {
		out.line("      passed over: %s", g.Note)
	}
	return true
}

func gitStateLabel(r repo.Repository) string {
	switch {
	case !r.HasGit:
		return "none (diff modes degrade to full scope)"
	case !r.HasCommits:
		return r.GitRoot + " (no commits yet; no base comparison)"
	default:
		return r.GitRoot
	}
}

// reportToolchainFloor compares the toolchain that will run the checks with the
// one the module's go.mod requires.
//
// Verification pins GOTOOLCHAIN=local, and under that setting the go command
// ignores a module's toolchain directive. A module below its own floor still
// builds, so nothing else in the run would mention it, yet the vulnerability
// scan would be judging a standard library the module has declared it does not
// accept. Six minutes into an audit is the wrong moment to learn that.
func reportToolchainFloor(ctx context.Context, out *printer, runner tool.Runner, r repo.Repository) bool {
	resolved, err := tool.ResolveGoVersion(ctx, runner, r.Root)
	if err != nil {
		out.line("%s checks run on  could not be resolved: %v", mark(false), err)
		out.line("      fix: make sure the go command runs inside %s", r.Root)
		return false
	}
	if r.ToolchainDirective == "" {
		out.line("%s checks run on  %s, module declares no floor", mark(true), resolved)
		return true
	}
	if tool.CompareGoVersions(resolved, r.ToolchainDirective) >= 0 {
		out.line("%s checks run on  %s, at or above the module floor %s",
			mark(true), resolved, r.ToolchainDirective)
		return true
	}
	// A warning, not a failure, for the same reason a missing vulnerability
	// database is one: the condition degrades evidence rather than breaking the
	// harness, and the consequence is already carried where it cannot be argued
	// away, by the security claim going INCONCLUSIVE. Everything still compiles;
	// what is no longer true is that the scan judged the standard library this
	// module accepts.
	out.line("[warn] checks run on  %s is below the module floor %s; "+
		"`goharness audit` reports its security claim INCONCLUSIVE", resolved, r.ToolchainDirective)
	out.line("      fix: install %s; verification pins GOTOOLCHAIN=local and will not download it",
		r.ToolchainDirective)
	return true
}
