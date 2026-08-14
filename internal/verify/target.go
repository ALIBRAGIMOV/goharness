package verify

import (
	"context"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/imports"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// target is one tree to verify: the head worktree, or the temporary base
// worktree during comparison.
type target struct {
	engine       *Engine
	root         string
	modulePath   string
	graph        change.PackageGraph
	packages     []string
	testPackages []string
	files        []string
	changed      []string
	raceTests    bool
	leakCheck    bool
	isBase       bool
	contract     admission.TaskContract
	analyzeOpts  analyze.Options

	// vulnDB records the snapshot the scan actually used, so the report can
	// state which database produced the security evidence.
	vulnDB *toolcache.VulnDBManifest
}

// checksFor builds the runnable DAG for the planned checks that belong to this
// tree. Producers that need both snapshots are handled by the comparison phase
// and are skipped here.
func (t *target) checksFor(planned []admission.PlannedCheck) []Check {
	runners := map[string]runFunc{
		admission.ProducerCompile:     t.runCompile,
		admission.ProducerGofmt:       t.runGofmt,
		admission.ProducerGoimports:   t.runGoimports,
		admission.ProducerModTidy:     t.runModTidy,
		admission.ProducerNative:      t.runNative,
		admission.ProducerMetrics:     t.runMetrics,
		admission.ProducerClone:       t.runClone,
		admission.ProducerScope:       t.runScope,
		admission.ProducerPolicyGuard: t.runPolicyGuard,
		admission.ProducerMigration:   t.runMigration,
		admission.ProducerVet:         t.runVet,
		admission.ProducerGolangci:    t.runGolangci,
		admission.ProducerTest:        t.runTests,
		admission.ProducerRaceTest:    t.runRaceTests,
		admission.ProducerVulnScan:    t.runVulnScan,
	}
	checks := make([]Check, 0, len(planned))
	for _, p := range planned {
		run, ok := runners[p.ID]
		if !ok {
			continue
		}
		checks = append(checks, Check{
			ID: p.ID, Tool: p.Tool, DependsOn: p.DependsOn, Produces: p.Produces, run: run,
		})
	}
	sortChecks(checks)
	return checks
}

func (t *target) newEvidence(ruleID, toolName, version string, sev evidence.Severity, file string, line, col int, pkg, msg string) evidence.Evidence {
	return evidence.Evidence{
		RuleID:      ruleID,
		Tool:        toolName,
		ToolVersion: version,
		Severity:    sev,
		File:        t.rel(file),
		Line:        line,
		Column:      col,
		Package:     pkg,
		Message:     evidence.NormalizeMessage(msg),
	}
}

func (t *target) rel(p string) string {
	if p == "" {
		return ""
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(t.root, p)
	}
	rel, err := filepath.Rel(t.root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

// fromFindings converts native scanner findings into decorated evidence. The
// advisory flag a scanner sets is honoured after policy decoration, because a
// graded rule (one budget advisory, a higher one required) carries the grade on
// the finding rather than on the rule.
func (t *target) fromFindings(findings []analyze.Finding, producer string) []evidence.Evidence {
	out := make([]evidence.Evidence, 0, len(findings))
	for _, f := range findings {
		pkg, _ := t.graph.PackageForFile(f.File)
		e := t.newEvidence(f.RuleID, producer, t.engine.Version,
			f.Severity, f.File, f.Line, f.Column, pkg, f.Message)
		e = t.engine.Policy.Decorate(e)
		if f.Advisory {
			e.Classification = evidence.ClassificationAdvisory
		}
		out = append(out, e)
	}
	return out
}

func (t *target) runCompile(ctx context.Context) (checkResult, error) {
	var out []evidence.Evidence
	seen := map[string]bool{}
	addFailure := func(file string, line, col int, msg string) {
		key := fmt.Sprintf("%s:%d:%d:%s", file, line, col, msg)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t.newEvidence(policy.RuleCompile, "go build", tool.GoVersion(),
			evidence.SeverityError, file, line, col, "", msg))
	}
	for _, e := range t.graph.Errors() {
		addFailure(e.File, e.Line, e.Column, e.Message)
	}
	patterns := t.graph.PatternsFor(t.packages)
	if len(patterns) == 0 {
		return checkResult{evidence: out}, nil
	}
	failures, err := tool.RunBuild(ctx, t.engine.Runner, t.root, patterns, t.graph.HasMainPackage(t.packages))
	if err != nil {
		if len(out) > 0 {
			return checkResult{evidence: out}, nil
		}
		return checkResult{}, err
	}
	for _, f := range failures {
		addFailure(f.File, f.Line, f.Column, f.Message)
	}
	return checkResult{evidence: out}, nil
}

func (t *target) runGofmt(ctx context.Context) (checkResult, error) {
	var out []evidence.Evidence
	for _, rel := range t.files {
		if err := ctx.Err(); err != nil {
			return checkResult{}, err
		}
		src, err := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(rel)))
		if err != nil {
			return checkResult{}, fmt.Errorf("reading %s: %w", rel, err)
		}
		formatted, err := format.Source(src)
		if err != nil {
			continue
		}
		if string(formatted) != string(src) {
			out = append(out, t.newEvidence(policy.RuleFormatGofmt, "gofmt", tool.GoVersion(),
				evidence.SeverityError, rel, 0, 0, "",
				"file is not gofmt-formatted; run gofmt to see the canonical form"))
		}
	}
	return checkResult{evidence: out}, nil
}

func (t *target) runGoimports(ctx context.Context) (checkResult, error) {
	options := &imports.Options{Comments: true, TabIndent: true, TabWidth: 8}
	var out []evidence.Evidence
	for _, rel := range t.files {
		if err := ctx.Err(); err != nil {
			return checkResult{}, err
		}
		full := filepath.Join(t.root, filepath.FromSlash(rel))
		src, err := os.ReadFile(full)
		if err != nil {
			return checkResult{}, fmt.Errorf("reading %s: %w", rel, err)
		}
		processed, err := imports.Process(full, src, options)
		if err != nil {
			continue
		}
		if string(processed) != string(src) {
			out = append(out, t.newEvidence(policy.RuleFormatGoimports, "goimports", tool.GoVersion(),
				evidence.SeverityError, rel, 0, 0, "",
				"import block is not goimports-normalized"))
		}
	}
	return checkResult{evidence: out}, nil
}

func (t *target) runNative(ctx context.Context) (checkResult, error) {
	findings, err := analyze.Scan(ctx, t.root, t.files, t.analyzeOpts)
	if err != nil {
		return checkResult{}, err
	}
	return checkResult{evidence: t.fromFindings(findings, "goharness")}, nil
}

func (t *target) runMetrics(ctx context.Context) (checkResult, error) {
	metrics, err := analyze.ComputeMetrics(ctx, t.root, t.files)
	if err != nil {
		return checkResult{}, err
	}
	return checkResult{evidence: t.fromFindings(analyze.SimplicityFindings(metrics), "goharness")}, nil
}

func (t *target) runClone(ctx context.Context) (checkResult, error) {
	findings, err := analyze.CloneFindings(ctx, t.root, t.files)
	if err != nil {
		return checkResult{}, err
	}
	return checkResult{evidence: t.fromFindings(findings, "goharness")}, nil
}

func (t *target) runScope(_ context.Context) (checkResult, error) {
	var out []evidence.Evidence
	for _, rel := range t.changed {
		if t.contract.InScope(rel) {
			continue
		}
		out = append(out, t.engine.Policy.Decorate(t.newEvidence(
			policy.RuleScopeViolation, "goharness", t.engine.Version,
			evidence.SeverityError, rel, 0, 0, "",
			"file is outside the scope declared by the task contract")))
	}
	return checkResult{evidence: out}, nil
}

// runPolicyGuard rejects a change that edits its own admission gate and flags
// hand-edited generated files. It reads the diff, so it runs at head only: the
// same entries re-scanned at base would cancel themselves out as pre-existing.
func (t *target) runPolicyGuard(ctx context.Context) (checkResult, error) {
	if t.isBase {
		return checkResult{}, nil
	}
	var out []evidence.Evidence
	for _, entry := range t.engine.ChangedEntries {
		if err := ctx.Err(); err != nil {
			return checkResult{}, err
		}
		switch {
		case isPolicyFile(entry.Path) && !t.contract.AllowPolicyEdit:
			out = append(out, t.engine.Policy.Decorate(t.newEvidence(
				policy.RulePolicyEdit, "goharness", t.engine.Version,
				evidence.SeverityError, entry.Path, 0, 0, "",
				"the change "+entry.Status.Describe()+" the quality policy file "+entry.Path+
					"; altering the admission gate needs a human decision, recorded as allowPolicyEdit: true in the task contract")))
		case entry.Status == change.StatusModified && strings.HasSuffix(entry.Path, ".go") &&
			isGeneratedFile(filepath.Join(t.root, filepath.FromSlash(entry.Path))):
			out = append(out, t.engine.Policy.Decorate(t.newEvidence(
				policy.RuleGeneratedEdit, "goharness", t.engine.Version,
				evidence.SeverityWarning, entry.Path, 0, 0, "",
				"file carries a Code generated header but was modified directly; re-run the generator so the next run does not erase this edit")))
		}
	}
	return checkResult{evidence: out}, nil
}

// isPolicyFile covers the durable policy only. The task contract is a per-run
// input the gate cannot authenticate anyway (a --contract flag would bypass a
// file check), so guarding it would add friction without adding protection;
// what matters is that using allowPolicyEdit leaves an explicit, reportable
// record of the decision.
func isPolicyFile(rel string) bool {
	return rel == "goharness.yaml"
}

// isGeneratedFile applies the Go convention: a `// Code generated ... DO NOT
// EDIT.` line before the package clause.
func isGeneratedFile(abs string) bool {
	src, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			return false
		}
		if strings.HasPrefix(trimmed, "// Code generated ") && strings.HasSuffix(trimmed, " DO NOT EDIT.") {
			return true
		}
	}
	return false
}

// runMigration reports migrations that the change rewrote rather than added.
// Only modification and deletion are reported: appending a migration is the
// intended way to evolve a schema. Like every diff-reading check it runs at
// head only.
func (t *target) runMigration(_ context.Context) (checkResult, error) {
	if t.isBase {
		return checkResult{}, nil
	}
	var out []evidence.Evidence
	for _, entry := range t.engine.ChangedEntries {
		if !isMigrationFile(entry.Path) || entry.Status == change.StatusAdded {
			continue
		}
		out = append(out, t.engine.Policy.Decorate(t.newEvidence(
			policy.RuleMigrationRewrite, "goharness", t.engine.Version,
			evidence.SeverityError, entry.Path, 0, 0, "",
			"migration was "+entry.Status.Describe()+" rather than added, so deployed databases cannot reproduce this schema")))
	}
	return checkResult{evidence: out}, nil
}

func isMigrationFile(rel string) bool {
	for part := range strings.SplitSeq(rel, "/") {
		if part == "migrations" || part == "migration" {
			return true
		}
	}
	return false
}

func (t *target) runVet(ctx context.Context) (checkResult, error) {
	patterns := t.graph.PatternsFor(t.packages)
	if len(patterns) == 0 {
		return checkResult{}, nil
	}
	diags, err := tool.RunVet(ctx, t.engine.Runner, t.root, patterns)
	if err != nil {
		return checkResult{}, err
	}
	out := make([]evidence.Evidence, 0, len(diags))
	for _, d := range diags {
		out = append(out, t.newEvidence(policy.RuleVet, "go vet", tool.GoVersion(),
			evidence.SeverityError, d.File, d.Line, d.Column, d.Package,
			d.Analyzer+": "+d.Message))
	}
	return checkResult{evidence: out}, nil
}

func (t *target) runGolangci(ctx context.Context) (checkResult, error) {
	g := t.engine.Golangci
	if !g.MatchesPin() {
		return checkResult{}, fmt.Errorf(
			"golangci-lint version %q does not match the pinned %s (found at %s); run `goharness doctor`",
			g.Version, tool.GolangciLintPin, g.Path)
	}
	patterns := t.graph.RelDirsFor(t.packages)
	if len(patterns) == 0 {
		return checkResult{}, nil
	}
	issues, err := tool.RunGolangci(ctx, t.engine.Runner, g, t.root, t.engine.GolangciConfig, patterns)
	if err != nil {
		return checkResult{}, err
	}
	out := make([]evidence.Evidence, 0, len(issues))
	for _, issue := range issues {
		file := t.normalizeLintPath(issue.Pos.Filename)
		pkg, _ := t.graph.PackageForFile(file)
		out = append(out, t.newEvidence("GCL-"+issue.FromLinter, "golangci-lint", g.Version,
			severityFor(issue.Severity), file, issue.Pos.Line, issue.Pos.Column,
			pkg, issue.Text))
	}
	return checkResult{evidence: out}, nil
}

// normalizeLintPath maps a reported path back into this worktree. golangci-lint
// caches analysis results by content, so when the same file exists in two trees
// (head and the temporary base worktree) it can report the path recorded the
// first time. Matching by longest path suffix against the in-scope file list
// restores a module-relative path, which the fingerprint depends on.
func (t *target) normalizeLintPath(reported string) string {
	rel := t.rel(reported)
	if !strings.HasPrefix(rel, "../") {
		return rel
	}
	slashed := filepath.ToSlash(reported)
	best := ""
	for _, candidate := range t.files {
		if len(candidate) <= len(best) {
			continue
		}
		if slashed == candidate || strings.HasSuffix(slashed, "/"+candidate) {
			best = candidate
		}
	}
	if best != "" {
		return best
	}
	return rel
}

func severityFor(s string) evidence.Severity {
	switch strings.ToLower(s) {
	case "warning", "medium", "low":
		return evidence.SeverityWarning
	case "info":
		return evidence.SeverityInfo
	default:
		return evidence.SeverityError
	}
}

func (t *target) runTests(ctx context.Context) (checkResult, error) {
	return t.runTestsWith(ctx, nil)
}

func (t *target) runRaceTests(ctx context.Context) (checkResult, error) {
	if !t.leakCheck || t.isBase {
		return t.runTestsWith(ctx, []string{"-race"})
	}
	return t.runLeakRaceTests(ctx)
}

// runLeakRaceTests runs the race suite with goroutine-leak verification
// injected through a build overlay. One run discharges tests-pass, race-clean,
// and goroutine-leak-clean. Packages that already declare a TestMain cannot be
// injected; they still run plainly, and the leak obligation is reported
// unproducible for them rather than silently passed.
func (t *target) runLeakRaceTests(ctx context.Context) (checkResult, error) {
	patterns := t.graph.PatternsFor(t.testPackages)
	if len(patterns) == 0 {
		return checkResult{}, nil
	}
	injectable, injectablePkgs, blocked, err := t.classifyLeakPackages()
	if err != nil {
		return checkResult{}, err
	}

	var res checkResult
	if len(blocked) > 0 {
		res.unproducible = append(res.unproducible, admission.Unproducible{
			Kind: admission.KindLeakClean,
			Reason: "a TestMain already exists in " + strings.Join(blocked, ", ") +
				", so goroutine-leak verification cannot be injected there",
			Remedy: "call goleak.VerifyTestMain from those TestMain functions, or remove them",
		})
	}

	var failures []tool.TestFailure
	if len(injectable) > 0 {
		scratch, mkErr := os.MkdirTemp("", "goharness-leak-")
		if mkErr != nil {
			return checkResult{}, fmt.Errorf("creating leak-check scratch directory: %w", mkErr)
		}
		defer func() {
			if rmErr := os.RemoveAll(scratch); rmErr != nil && err == nil {
				err = fmt.Errorf("removing leak-check scratch directory: %w", rmErr)
			}
		}()
		overlay, ovErr := leakcheck.Overlay(scratch, t.root, t.modulePath, injectablePkgs)
		if ovErr != nil {
			return checkResult{}, ovErr
		}
		injected, runErr := tool.RunTests(ctx, t.engine.Runner, t.root, injectable,
			[]string{"-race", "-overlay", overlay})
		if runErr != nil {
			return checkResult{}, runErr
		}
		failures = append(failures, injected...)
	}
	if rest := exceptPatterns(patterns, injectable); len(rest) > 0 {
		plain, runErr := tool.RunTests(ctx, t.engine.Runner, t.root, rest, []string{"-race"})
		if runErr != nil {
			return checkResult{}, runErr
		}
		failures = append(failures, plain...)
	}

	testFailures := 0
	for _, f := range failures {
		if leakcheck.IsLeakFailure(f.Output) {
			msg, ok := leakcheck.LeakMessage(f.Output)
			if !ok {
				msg = "tests leave goroutines running after completion"
			}
			res.evidence = append(res.evidence, t.newEvidence(policy.RuleGoroutineLeak,
				"goleak "+leakcheck.Version, tool.GoVersion(),
				evidence.SeverityError, "", 0, 0, f.Package, msg))
			continue
		}
		testFailures++
		res.evidence = append(res.evidence, t.testFailureEvidence(f))
	}
	if testFailures > 0 {
		res.unproducible = append(res.unproducible, admission.Unproducible{
			Kind:   admission.KindLeakClean,
			Reason: "failing tests stop the suite before goroutine-leak verification can conclude",
			Remedy: "fix the failing tests first",
		})
	}
	return res, nil
}

// classifyLeakPackages splits the test scope into injectable package patterns,
// their overlay descriptors, and packages blocked by an existing TestMain.
func (t *target) classifyLeakPackages() (injectable []string, pkgs []leakcheck.Package, blocked []string, err error) {
	for _, pkgPath := range t.testPackages {
		dir, name, ok := t.graph.DirAndName(pkgPath)
		if !ok {
			continue
		}
		hasTests, listErr := leakcheck.HasTestFiles(dir)
		if listErr != nil {
			return nil, nil, nil, listErr
		}
		if !hasTests {
			continue
		}
		hasMain, mainErr := leakcheck.HasTestMain(dir)
		if mainErr != nil {
			return nil, nil, nil, mainErr
		}
		if hasMain {
			blocked = append(blocked, pkgPath)
			continue
		}
		injectable = append(injectable, pkgPath)
		pkgs = append(pkgs, leakcheck.Package{Dir: t.rel(dir), Name: name})
	}
	slices.Sort(blocked)
	return injectable, pkgs, blocked, nil
}

func exceptPatterns(all, remove []string) []string {
	out := make([]string, 0, len(all))
	for _, p := range all {
		if !slices.Contains(remove, p) {
			out = append(out, p)
		}
	}
	return out
}

func (t *target) runTestsWith(ctx context.Context, extra []string) (checkResult, error) {
	patterns := t.graph.PatternsFor(t.testPackages)
	if len(patterns) == 0 {
		return checkResult{}, nil
	}
	if t.raceTests && !slices.Contains(extra, "-race") {
		extra = append(extra, "-race")
	}
	failures, err := tool.RunTests(ctx, t.engine.Runner, t.root, patterns, extra)
	if err != nil {
		return checkResult{}, err
	}
	out := make([]evidence.Evidence, 0, len(failures))
	for _, f := range failures {
		out = append(out, t.testFailureEvidence(f))
	}
	return checkResult{evidence: out}, nil
}

func (t *target) testFailureEvidence(f tool.TestFailure) evidence.Evidence {
	name := f.Test
	if name == "" {
		name = "package"
	}
	return t.newEvidence(policy.RuleTestFailure, "go test", tool.GoVersion(),
		evidence.SeverityError, "", 0, 0, f.Package,
		"test "+name+" failed: "+firstMeaningfulLine(f.Output))
}

func firstMeaningfulLine(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "---") {
			continue
		}
		return trimmed
	}
	return "no output captured"
}

func (t *target) runModTidy(ctx context.Context) (checkResult, error) {
	diff, err := tool.RunModTidy(ctx, t.engine.Runner, t.root)
	if err != nil {
		return checkResult{}, err
	}
	if diff == "" {
		return checkResult{}, nil
	}
	return checkResult{evidence: []evidence.Evidence{t.newEvidence(
		policy.RuleModTidy, "go mod tidy", tool.GoVersion(),
		evidence.SeverityError, "go.mod", 0, 0, "",
		"module requirements are not tidy; `go mod tidy` would change go.mod or go.sum")}}, nil
}

// runVulnScan scans in process against the provisioned database snapshot.
//
// Without a snapshot the obligation is unproducible, never a pass: the harness
// will not report a change free of known vulnerabilities on the strength of
// having no database to check against. A stale snapshot still scans; its age is
// surfaced in the report and by doctor.
func (t *target) runVulnScan(ctx context.Context) (checkResult, error) {
	cache, err := toolcache.Open()
	if err != nil {
		return checkResult{unproducible: vulnUnproducible(err.Error())}, nil
	}
	if !cache.HasVulnDB() {
		return checkResult{unproducible: vulnUnproducible(
			"no vulnerability database snapshot in " + cache.Root())}, nil
	}
	manifest, readable := readVulnManifest(cache)
	if !readable.ok {
		return checkResult{unproducible: vulnUnproducible(readable.reason)}, nil
	}

	findings, err := tool.RunVulnScan(ctx, t.root, cache.VulnDBURL(), []string{"./..."})
	if err != nil {
		return checkResult{}, err
	}
	t.vulnDB = &manifest

	out := make([]evidence.Evidence, 0, len(findings))
	for _, f := range findings {
		out = append(out, t.newEvidence(policy.RuleGovulncheck, "golang.org/x/vuln",
			tool.XVulnVersion(), evidence.SeverityError, f.File, f.Line, 0, f.Package, f.Message))
	}
	return checkResult{evidence: out}, nil
}

// manifestStatus separates "the snapshot is unusable" from "the check failed",
// so an unreadable manifest becomes an unproducible obligation rather than a
// tool failure or, worse, a silent pass.
type manifestStatus struct {
	ok     bool
	reason string
}

func readVulnManifest(cache *toolcache.Cache) (toolcache.VulnDBManifest, manifestStatus) {
	manifest, err := cache.ReadVulnDBManifest()
	if err != nil {
		return toolcache.VulnDBManifest{}, manifestStatus{
			reason: "the snapshot manifest could not be read: " + err.Error(),
		}
	}
	return manifest, manifestStatus{ok: true}
}

func vulnUnproducible(reason string) []admission.Unproducible {
	return []admission.Unproducible{{
		Kind:   admission.KindVulnerabilityScan,
		Reason: reason,
		Remedy: "run goharness setup",
	}}
}
