package verify

import (
	"context"
	"errors"
	"fmt"
	"go/format"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
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
	// files is every Go file in the scope packages. It is what a linter path is
	// mapped back against, so it must stay complete even where nothing is judged.
	files []string
	// judged is the subset of files this run examines: files less the generated
	// ones the change leaves alone.
	judged []string
	// exemptFiles are the generated files this change does not touch. Their
	// linter issues are dropped rather than reported against the change.
	exemptFiles map[string]bool
	// generatedFiles is every in-scope file a tool wrote, the regenerated ones
	// included. Base/head deltas are not computed across it: see
	// generatedPartition.
	generatedFiles map[string]bool
	changed        []string
	raceTests      bool
	leakCheck      bool
	isBase         bool
	contract       admission.TaskContract
	analyzeOpts    analyze.Options
	// parsed is the one parse of judged that every syntax-driven check reads.
	// The coordinator builds it before scheduling and never writes to it again,
	// which is what lets three checks share it without sharing mutable state.
	parsed *analyze.ParsedScope
	// packageScopes groups judged by package directory, with the content digest
	// each package's cached answers are addressed by. Built with parsed, and read
	// only afterwards, for the same reason.
	packageScopes []packageScope
	// module is the digest of the module requirements, which decide which imports
	// resolve and therefore what goimports concludes.
	module string
	// localScope names the package directories the directory-local checks
	// examine. It is nil where they examine every directory in scope, which is
	// every mode but a verify that has a base to compare against.
	localScope []string
	// moduleChanged records that the change edits go.mod or go.sum, which can
	// move goimports's answer for a file whose own bytes did not.
	moduleChanged bool

	// vulnDB records the snapshot the scan actually used, so the report can
	// state which database produced the security evidence.
	vulnDB *toolcache.VulnDBManifest
	// leakBlocked names the test packages whose existing TestMain kept the leak
	// detector out. Written by the race check and read once the schedule has
	// returned, exactly as vulnDB is.
	leakBlocked []string
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
		admission.ProducerVisibility:  t.runVisibility,
		admission.ProducerMigration:   t.runMigration,
		admission.ProducerVet:         t.runVet,
		admission.ProducerGoFix:       t.runGoFix,
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

// nativeRemediation is the command that closes a native finding, for the rules
// whose fix the harness performs itself. It follows the gofmt precedent: when a
// tool can state the fix exactly, arguing about the rule becomes moot.
func nativeRemediation(ruleID string) (evidence.Remediation, bool) {
	fixer, ok := analyze.FixerFor(ruleID)
	if !ok {
		return evidence.Remediation{}, false
	}
	return evidence.Remediation{
		Command: "goharness fix --rule " + fixer.RuleID,
		Summary: fixer.Summary,
	}, true
}

// dirSet turns a directory list into a membership test, keeping nil as "every
// directory" rather than as the empty set.
func dirSet(dirs []string) map[string]bool {
	if dirs == nil {
		return nil
	}
	out := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		out[dir] = true
	}
	return out
}

// rel maps a path a tool reported into this tree's module-relative coordinates.
//
// Two trees are what make the repair necessary. The base revision is verified in
// a temporary worktree, and a tool that reports a file there by an absolute path
// hands back a string the head side can never equal, so the same finding at both
// revisions gets two fingerprints and a whole producer's output reads as
// introduced by the change. This is exactly what happened to go vet and go fix
// on a production monorepo, while golangci-lint escaped only because it happened
// to report relative paths.
//
// The in-scope file list is the authority of last resort: a reported path that
// ends with one of its entries names that file whatever prefix it arrived with.
// A path that cannot be placed at all is returned as it came, and the coordinator
// refuses to fingerprint it.
func (t *target) rel(p string) string {
	if p == "" {
		return ""
	}
	if placed, ok := t.relUnderRoot(p); ok {
		return placed
	}
	return t.matchInScope(p)
}

// relUnderRoot places a path below this tree's root, reporting whether it lies
// there at all.
func (t *target) relUnderRoot(p string) (string, bool) {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(t.root, p)
	}
	rel, err := filepath.Rel(t.root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// matchInScope repairs a path by its longest suffix that names an in-scope file.
func (t *target) matchInScope(p string) string {
	slashed := filepath.ToSlash(p)
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
	return slashed
}

// fromFindings converts native scanner findings into decorated evidence. The
// advisory flag a scanner sets is honoured after policy decoration, because a
// graded rule (one budget advisory, a higher one required) carries the grade on
// the finding rather than on the rule.
func (t *target) fromFindings(findings []analyze.Finding, producer string) []evidence.Evidence {
	out := make([]evidence.Evidence, 0, len(findings))
	for _, f := range findings {
		pkg := f.Package
		if pkg == "" {
			pkg, _ = t.graph.PackageForFile(f.File)
		}
		e := t.newEvidence(f.RuleID, producer, t.engine.Version,
			f.Severity, f.File, f.Line, f.Column, pkg, f.Message)
		e.Identity = f.Identity
		e = t.engine.Policy.Decorate(e)
		if f.Advisory {
			e.Classification = evidence.ClassificationAdvisory
		}
		if fix, ok := nativeRemediation(f.RuleID); ok {
			e.Fix = &fix
		}
		out = append(out, e)
	}
	return out
}

// runCompile reports the defects the compiler found. A package the go command
// could not resolve at all is not one of them: an unobtainable module says
// nothing about the change, so it ends the check as a failure and leaves the
// claim inconclusive rather than blaming the code in front of it.
func (t *target) runCompile(ctx context.Context) (checkResult, error) {
	if unresolved := t.graph.ResolutionErrors(); len(unresolved) > 0 {
		return checkResult{}, fmt.Errorf(
			"the module graph could not be resolved, so nothing was compiled: %s",
			unresolved[0].Message)
	}
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

// formatCheck describes one formatting question: what its answers are stored
// under, how a package is judged, and how a finding reads once policy has been
// applied to it.
type formatCheck struct {
	kind    string
	ruleID  string
	tool    string
	message string
	fix     string
	// dependsOnModule marks a check whose answer can move when go.mod does, which
	// decides whether it may skip the directories the change did not touch.
	dependsOnModule bool
	judge           func(context.Context, packageScope) ([]formatFinding, error)
}

func (t *target) runGofmt(ctx context.Context) (checkResult, error) {
	return t.runFormatCheck(ctx, formatCheck{
		kind:    gofmtEvidenceKind,
		ruleID:  policy.RuleFormatGofmt,
		tool:    "gofmt",
		message: "file is not gofmt-formatted; run gofmt to see the canonical form",
		fix:     "gofmt -w ",
		judge:   t.gofmtPackage,
	})
}

func (t *target) runGoimports(ctx context.Context) (checkResult, error) {
	return t.runFormatCheck(ctx, formatCheck{
		kind:            goimportsEvidenceKind,
		ruleID:          policy.RuleFormatGoimports,
		tool:            "goimports",
		message:         "import block is not goimports-normalized",
		fix:             "goimports -w ",
		dependsOnModule: true,
		judge:           t.goimportsPackage,
	})
}

// runFormatCheck answers one formatting question package by package, reusing
// what a previous run concluded about a package whose files have not moved
// since.
//
// The formatting checks are where this pays. Both are pure functions of a
// file's bytes and the toolchain, and goimports in particular resolves imports
// from scratch for every file it is handed, which on a repository of any size
// is the largest thing the harness owns. In an agent's repair loop, where two
// files of hundreds changed, everything else was already answered.
//
// The cached answer is the raw per-file finding, not evidence: classification
// and fingerprints are rebuilt here on every run, so a policy edit is picked up
// even where a package's files did not change.
func (t *target) runFormatCheck(ctx context.Context, check formatCheck) (checkResult, error) {
	// A nil scope list would make this check report no findings at all, which is
	// a silent pass rather than an error. It is a harness fault, phrased as one.
	if t.packageScopes == nil {
		return checkResult{}, harnessError{err: errors.New(
			"a formatting check was scheduled before the scope was grouped by package")}
	}
	cacheable := t.headCacheable()
	local := dirSet(t.localFor(check.dependsOnModule))
	var out []evidence.Evidence
	for _, pkg := range t.packageScopes {
		if err := ctx.Err(); err != nil {
			return checkResult{}, err
		}
		if local != nil && !local[pkg.dir] {
			continue
		}
		var findings []formatFinding
		key, hit := "", false
		if cacheable {
			key = t.engine.headKey(check.kind, pkg, t.module)
			findings, hit = readHeadEntry[[]formatFinding](t.engine, check.kind, key)
		}
		if !hit {
			computed, err := check.judge(ctx, pkg)
			if err != nil {
				return checkResult{}, err
			}
			findings = computed
			if cacheable {
				writeHeadEntry(t.engine, check.kind, key, findings)
			}
		}
		for _, f := range findings {
			e := t.newEvidence(check.ruleID, check.tool, tool.GoVersion(),
				evidence.SeverityError, f.File, 0, 0, "", check.message)
			e.Fix = &evidence.Remediation{Command: check.fix + f.File}
			out = append(out, e)
		}
	}
	return checkResult{evidence: out}, nil
}

// gofmtPackage reports the files in one package that gofmt would rewrite. A
// file that does not parse is the compile check's finding, so it is passed over
// here rather than reported twice.
func (t *target) gofmtPackage(ctx context.Context, pkg packageScope) ([]formatFinding, error) {
	var out []formatFinding
	for _, rel := range pkg.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src, err := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", rel, err)
		}
		formatted, err := format.Source(src)
		if err != nil {
			continue
		}
		if string(formatted) != string(src) {
			out = append(out, formatFinding{File: rel})
		}
	}
	return out, nil
}

// goimportsPackage reports the files in one package whose import block
// goimports would rewrite.
func (t *target) goimportsPackage(ctx context.Context, pkg packageScope) ([]formatFinding, error) {
	options := &imports.Options{Comments: true, TabIndent: true, TabWidth: 8}
	var out []formatFinding
	for _, rel := range pkg.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		full := filepath.Join(t.root, filepath.FromSlash(rel))
		src, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", rel, err)
		}
		processed, err := imports.Process(full, src, options)
		if err != nil {
			continue
		}
		if string(processed) != string(src) {
			out = append(out, formatFinding{File: rel})
		}
	}
	return out, nil
}

// prepare builds everything the checks share before any of them starts.
//
// It is the coordinator's job because the alternative is several checks racing
// to derive the same thing from the same files, which is either repeated work
// or shared mutable state, and the architecture rules out the second.
func (t *target) prepare(ctx context.Context) error {
	if err := t.parseScope(ctx); err != nil {
		return err
	}
	return t.scopePackages(ctx)
}

// parseScope gives the syntax-driven checks the single parse they share.
func (t *target) parseScope(ctx context.Context) error {
	if t.parsed != nil {
		return nil
	}
	scope, err := analyze.Parse(ctx, t.root, t.judged)
	if err != nil {
		return err
	}
	t.parsed = scope
	return nil
}

// syntax returns the parsed scope, or the fault of having scheduled a
// syntax-driven check before anything parsed for it. Phrasing that as a harness
// fault keeps it out of the evidence channel, where it would read as a defect
// in the repository.
func (t *target) syntax() (*analyze.ParsedScope, error) {
	if t.parsed == nil {
		return nil, harnessError{err: errors.New(
			"a syntax-driven check was scheduled before the scope was parsed")}
	}
	return t.parsed, nil
}

// localFor returns the package directories one directory-local check examines,
// and nil when it has to see every directory in scope.
//
// Two conditions, both necessary. The check's answer must depend on one
// directory's bytes alone, so that a directory identical at base and head yields
// findings that pair on fingerprint. And none of its rules may be
// ungrandfatherable, since such a rule blocks on a pre-existing finding too:
// skipping it would not decline to recompute a row that cancels, it would
// decline to enforce a rule. The native scan fails the second test and is never
// narrowed; it owns every suppression rule and the em dash.
//
// dependsOnModule separates goimports from gofmt: goimports resolves identifiers
// against what the module can reach, so an edit to go.mod can move its answer
// for a file whose own bytes did not.
func (t *target) localFor(dependsOnModule bool) []string {
	if dependsOnModule && t.moduleChanged {
		return nil
	}
	return t.localScope
}

// runNative reads the whole scope on purpose. See localFor: this check produces
// the rules that block whether or not the base revision already carried them.
func (t *target) runNative(ctx context.Context) (checkResult, error) {
	scope, err := t.syntax()
	if err != nil {
		return checkResult{}, err
	}
	findings, err := scope.Scan(ctx, t.analyzeOpts)
	if err != nil {
		return checkResult{}, err
	}
	return checkResult{evidence: t.fromFindings(findings, "goharness")}, nil
}

func (t *target) runMetrics(ctx context.Context) (checkResult, error) {
	scope, err := t.syntax()
	if err != nil {
		return checkResult{}, err
	}
	metrics, err := scope.Restrict(t.localFor(false)).Metrics(ctx)
	if err != nil {
		return checkResult{}, err
	}
	return checkResult{evidence: t.fromFindings(analyze.SimplicityFindings(metrics), "goharness")}, nil
}

func (t *target) runClone(ctx context.Context) (checkResult, error) {
	scope, err := t.syntax()
	if err != nil {
		return checkResult{}, err
	}
	findings, err := scope.Clones(ctx, t.generatedFiles)
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
	if grants := t.contract.IgnoredGrants; len(grants) > 0 {
		out = append(out, t.engine.Policy.Decorate(t.newEvidence(
			policy.RulePolicyGrant, "goharness", t.engine.Version,
			evidence.SeverityError, admission.ContractFileName, 0, 0, "",
			"the working tree asks for "+strings.Join(grants, ", ")+
				" but the base revision grants none of it; commit the contract before the change it authorises")))
	}
	for _, entry := range t.engine.ChangedEntries {
		if err := ctx.Err(); err != nil {
			return checkResult{}, err
		}
		if isPolicyFile(entry.Path) && !t.contract.AllowPolicyEdit {
			out = append(out, t.engine.Policy.Decorate(t.newEvidence(
				policy.RulePolicyEdit, "goharness", t.engine.Version,
				evidence.SeverityError, entry.Path, 0, 0, "",
				"the change "+entry.Status.Describe()+" the quality policy file "+entry.Path+
					"; altering the admission gate needs a human decision, recorded as allowPolicyEdit: true in a task contract committed at the base revision")))
			continue
		}
		edited, err := t.editedGeneratedFile(entry)
		if err != nil {
			return checkResult{}, err
		}
		if edited {
			out = append(out, t.engine.Policy.Decorate(t.newEvidence(
				policy.RuleGeneratedEdit, "goharness", t.engine.Version,
				evidence.SeverityWarning, entry.Path, 0, 0, "",
				"changed file carries a Code generated header; confirm it was regenerated rather than "+
					"hand-edited, because the next generator run erases a hand edit")))
		}
	}
	return checkResult{evidence: out}, nil
}

// maxNamedFiles keeps an unproducible reason readable when a change moved a
// whole directory out of the build.
const maxNamedFiles = 5

// runVisibility reports the changed Go files this run's build configuration
// excludes from every package.
//
// Compiling, vetting, linting and testing all work through the package graph,
// so a file outside it is a part of the change that nothing examined. That is
// missing evidence rather than a defect: the file may build perfectly on
// another platform or under another tag. The claim it supports goes
// INCONCLUSIVE and names the files, which is the honest answer and still stops
// an agent from calling the task finished.
func (t *target) runVisibility(_ context.Context) (checkResult, error) {
	if t.isBase {
		return checkResult{}, nil
	}
	unexamined, faults := t.graph.Unexamined(t.engine.ChangedEntries)
	// A file the harness could not read is a fault in the harness, and saying so
	// in the vocabulary of build constraints would send the reader hunting for a
	// defect the repository does not have. It ends the check as a failure, which
	// is the channel that carries harness faults and is attributed to goharness.
	if len(faults) > 0 {
		named := make([]string, 0, min(len(faults), maxNamedFiles))
		for _, fault := range faults[:min(len(faults), maxNamedFiles)] {
			named = append(named, fault.Path+" ("+fault.Err.Error()+")")
		}
		return checkResult{}, harnessError{err: fmt.Errorf(
			"goharness could not resolve %d changed file(s) and so cannot report what examined them: %s",
			len(faults), strings.Join(named, "; "))}
	}
	if len(unexamined) == 0 {
		return checkResult{}, nil
	}
	named := make([]string, 0, len(unexamined))
	for _, file := range unexamined[:min(len(unexamined), maxNamedFiles)] {
		named = append(named, file.Path+" ("+file.Reason+")")
	}
	reason := fmt.Sprintf("%d changed Go file(s) were compiled by nothing in this run: %s",
		len(unexamined), strings.Join(named, "; "))
	if len(unexamined) > len(named) {
		reason += fmt.Sprintf(" and %d more", len(unexamined)-len(named))
	}
	return checkResult{unproducible: []admission.Unproducible{{
		Kind:   admission.KindChangeVisible,
		Reason: reason,
		Remedy: "build the file in this configuration, drop it from the change, " +
			"or run verify where its constraints are satisfied",
	}}}, nil
}

// editedGeneratedFile reports a generated file the change rewrote in place.
// Adding one is not reported: introducing a generator produces its output for
// the first time, and that output is judged like any other code the change
// brings in.
func (t *target) editedGeneratedFile(entry change.Entry) (bool, error) {
	if entry.Status != change.StatusModified || !strings.HasSuffix(entry.Path, ".go") {
		return false, nil
	}
	return analyze.IsGenerated(filepath.Join(t.root, filepath.FromSlash(entry.Path)))
}

// isPolicyFile covers the durable policy only. The task contract is a per-run
// input the gate cannot authenticate anyway (a --contract flag would bypass a
// file check), so guarding it would add friction without adding protection;
// what matters is that using allowPolicyEdit leaves an explicit, reportable
// record of the decision.
//
// The acknowledged-debt ledger belongs here for the same reason the policy file
// does: it decides what stops blocking, so writing to it is altering the gate.
// Only the committed copy has any effect, and this is what makes the edit that
// produced it visible instead of silent.
func isPolicyFile(rel string) bool {
	return rel == policy.ConfigFileName || rel == policy.DebtFileName
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

// runGoFix reports what the go fix analyzer suite would rewrite. Every finding
// carries the command that applies it: the toolchain computed the edit, so the
// remediation is a command rather than an exercise.
//
// Only diagnostics that carry an edit become evidence. What makes this suite
// precise enough to report at all is that it proves each finding by producing
// the replacement; a diagnostic with no edit is the analyzer saying it cannot
// help here, which is a statement about the analyzer rather than about the
// code. The clearest instance is a call inside a generated file, where the
// inliner reports that it will not rewrite the file at all.
//
// The analyzer set is checked against the toolchain before the run. An analyzer
// the policy enables and the toolchain does not have would otherwise fail as an
// undefined flag, which reads as a broken harness rather than as a pin that
// moved.
func (t *target) runGoFix(ctx context.Context) (checkResult, error) {
	patterns := t.graph.PatternsFor(t.packages)
	if len(patterns) == 0 {
		return checkResult{}, nil
	}
	analyzers := policy.GoFixAnalyzers()
	support, err := tool.InspectFixAnalyzers(ctx, t.engine.Runner, t.root, analyzers, policy.GoFixKnownAnalyzers())
	if err != nil {
		return checkResult{}, err
	}
	if len(support.Missing) > 0 {
		return checkResult{}, fmt.Errorf(
			"%s does not register the go fix analyzer(s) %s that the policy enables",
			tool.GoVersion(), strings.Join(support.Missing, ", "))
	}
	diags, err := tool.RunGoFix(ctx, t.engine.Runner, t.root, patterns, analyzers)
	if err != nil {
		return checkResult{}, err
	}
	out := make([]evidence.Evidence, 0, len(diags))
	for _, d := range diags {
		file := t.rel(d.File)
		if t.exemptFiles[file] || d.Edits == 0 {
			continue
		}
		e := t.newEvidence(policy.GoFixRuleID(d.Analyzer), "go fix", tool.GoVersion(),
			evidence.SeverityWarning, file, d.Line, d.Column, d.Package, d.Message)
		e.Fix = &evidence.Remediation{
			Command: goFixCommand(d.Analyzer, file),
			Summary: d.FixSummary,
		}
		out = append(out, e)
	}
	return checkResult{evidence: out}, nil
}

// goFixCommand names the narrowest invocation that closes one finding: the one
// analyzer that reported it, over the directory it is in. A reader who runs it
// gets that fix and no other, which is what makes it safe to run without
// reading the whole diff first.
func goFixCommand(analyzer, file string) string {
	dir := path.Dir(file)
	if dir == "." || dir == "" || file == "" {
		return "go fix -" + analyzer + " ./..."
	}
	return "go fix -" + analyzer + " ./" + dir
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
		file := t.rel(issue.Pos.Filename)
		if t.exemptFiles[file] {
			continue
		}
		pkg, _ := t.graph.PackageForFile(file)
		out = append(out, t.newEvidence(policy.GolangciRuleID(issue.FromLinter), "golangci-lint", g.Version,
			severityFor(issue.Severity), file, issue.Pos.Line, issue.Pos.Column,
			pkg, issue.Text))
	}
	return checkResult{evidence: out}, nil
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
func (t *target) runLeakRaceTests(ctx context.Context) (_ checkResult, err error) {
	patterns := t.graph.PatternsFor(t.testPackages)
	if len(patterns) == 0 {
		return checkResult{}, nil
	}
	injectable, injectablePkgs, blocked, classifyErr := t.classifyLeakPackages()
	if classifyErr != nil {
		return checkResult{}, classifyErr
	}

	var res checkResult
	t.leakBlocked = blocked
	// Only a package the change touched leaves an obligation this change can
	// discharge. A TestMain anywhere else in the reverse-dependency closure is a
	// gap in the repository's coverage, and telling the author of a merge request
	// to go and edit three packages they never opened is an instruction nobody
	// will follow: it is reported in coverage instead.
	if inChange := t.changedAmong(blocked); len(inChange) > 0 {
		res.unproducible = append(res.unproducible, admission.Unproducible{
			Kind: admission.KindLeakClean,
			Reason: "a TestMain already exists in " + strings.Join(inChange, ", ") +
				", which this change touches, so goroutine-leak verification cannot be injected there",
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

	interpreted, err := t.interpretLeakRun(ctx, failures)
	if err != nil {
		return checkResult{}, err
	}
	res.evidence = append(res.evidence, interpreted.evidence...)
	res.unproducible = append(res.unproducible, interpreted.unproducible...)
	return res, nil
}

// interpretLeakRun splits a race run's failures into leaked goroutines, tests
// that failed twice, and tests that did not reproduce.
func (t *target) interpretLeakRun(ctx context.Context, failures []tool.TestFailure) (checkResult, error) {
	var res checkResult
	var failed []tool.TestFailure
	leaks := map[string]*leakSite{}
	for _, f := range failures {
		if !leakcheck.IsLeakFailure(f.Output) {
			failed = append(failed, f)
			continue
		}
		t.recordLeak(leaks, f)
	}
	res.evidence = append(res.evidence, t.leakEvidence(leaks)...)
	confirmed, flaky, err := t.confirmFailures(ctx, failed, []string{"-race"})
	if err != nil {
		return checkResult{}, err
	}
	res.unproducible = append(res.unproducible, flakyUnproducible(flaky, true)...)
	for _, f := range confirmed {
		res.evidence = append(res.evidence, t.testFailureEvidence(f))
	}
	if len(confirmed) > 0 {
		res.unproducible = append(res.unproducible, admission.Unproducible{
			Kind:   admission.KindLeakClean,
			Reason: "failing tests stop the suite before goroutine-leak verification can conclude",
			Remedy: "fix the failing tests first",
		})
	}
	return res, nil
}

// leakSite is one place goroutines were left running, and everything the run
// observed about it.
//
// The site is the unit because it is the unit of repair. One leaking helper
// reached from thirty test packages is one defect and thirty rows: a production
// run produced forty rows for four sites and told its reader to "fix every
// GH-LEAK-001 finding above" forty times.
type leakSite struct {
	file     string
	line     int
	pkg      string
	funcs    map[string]bool
	packages map[string]bool
}

// recordLeak folds one leaking test package into the site it leaked at.
//
// A leak belongs to a place rather than to a line, but "nowhere" is not a
// location: with an empty file a reader has nothing to open and a scoped
// exception can never match. The package directory is the most precise anchor
// that is true, and goleak's own stack head names the origin when it falls
// inside this tree.
func (t *target) recordLeak(sites map[string]*leakSite, f tool.TestFailure) {
	file, line := t.leakAnchor(f)
	key := file
	if key == "" {
		key = f.Package
	}
	site, known := sites[key]
	if !known {
		site = &leakSite{
			file: file, line: line, pkg: f.Package,
			funcs: map[string]bool{}, packages: map[string]bool{},
		}
		sites[key] = site
	}
	site.packages[f.Package] = true
	for _, fn := range leakcheck.LeakFunctions(f.Output) {
		site.funcs[fn] = true
	}
}

// leakEvidence renders one finding per leaking site.
//
// The identity is the site and nothing else. goleak lists the goroutines it
// found in whatever order the runtime produced them, and the list's membership
// varies between runs of the same code, so a finding named by that list is a new
// finding every run: eleven leaks were reported as introduced between two runs
// of one commit. The list is what the message is for.
func (t *target) leakEvidence(sites map[string]*leakSite) []evidence.Evidence {
	out := make([]evidence.Evidence, 0, len(sites))
	for _, key := range slices.Sorted(maps.Keys(sites)) {
		site := sites[key]
		e := t.newEvidence(policy.RuleGoroutineLeak,
			"goleak "+leakcheck.Version, tool.GoVersion(),
			evidence.SeverityError, site.file, site.line, 0, site.pkg, site.message())
		e.Identity = policy.RuleGoroutineLeak + " at " + key
		out = append(out, e)
	}
	return out
}

// message describes a site: what leaked there, and how widely it was observed.
func (s *leakSite) message() string {
	funcs := slices.Sorted(maps.Keys(s.funcs))
	if len(funcs) == 0 {
		funcs = []string{"an unnamed goroutine"}
	}
	msg := "tests leave goroutines running after completion: " + strings.Join(funcs, ", ")
	if len(s.packages) > 1 {
		msg += fmt.Sprintf(" (observed in %d test packages)", len(s.packages))
	}
	return msg
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

// changedAmong keeps the packages the change touched, in the order given.
func (t *target) changedAmong(pkgPaths []string) []string {
	dirs := make(map[string]bool, len(t.changed))
	for _, rel := range t.changed {
		dirs[path.Dir(rel)] = true
	}
	out := make([]string, 0, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		if dirs[t.packageDir(pkgPath)] {
			out = append(out, pkgPath)
		}
	}
	return out
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
	confirmed, flaky, err := t.confirmFailures(ctx, failures, extra)
	if err != nil {
		return checkResult{}, err
	}
	out := make([]evidence.Evidence, 0, len(confirmed))
	for _, f := range confirmed {
		out = append(out, t.testFailureEvidence(f))
	}
	return checkResult{evidence: out, unproducible: flakyUnproducible(flaky, slices.Contains(extra, "-race"))}, nil
}

// raceReport marks output the race detector wrote. A race it saw once is a real
// race whether or not a second run schedules the goroutines the same way, so
// such a failure is never dismissed as a flake.
const raceReport = "DATA RACE"

// confirmFailures re-runs the tests that failed, once each, and splits them
// into failures that reproduce and tests that did not.
//
// A suite with a flake rate above zero would otherwise blame whichever change
// happens to be in front of it, which is the fastest way for a gate to lose the
// authority it needs. A test that fails twice is evidence. One that passes on
// the second run has proved nothing either way, so the obligation it was
// carrying goes unproducible and names the test, rather than quietly passing or
// rejecting a change that did not cause it.
func (t *target) confirmFailures(
	ctx context.Context, failures []tool.TestFailure, extra []string,
) (confirmed []tool.TestFailure, flaky []string, err error) {
	if t.isBase || len(failures) == 0 {
		return failures, nil, nil
	}
	retryable := map[string][]string{}
	for _, f := range failures {
		if name := topLevelTest(f); name != "" && !strings.Contains(f.Output, raceReport) {
			retryable[f.Package] = appendUnique(retryable[f.Package], name)
		}
	}
	stillFailing := map[string]bool{}
	for _, pkg := range slices.Sorted(maps.Keys(retryable)) {
		names := retryable[pkg]
		repeat, runErr := tool.RunTests(ctx, t.engine.Runner, t.root, []string{pkg},
			append(slices.Clone(extra), "-run", testNamePattern(names)))
		if runErr != nil {
			// A re-run the toolchain refuses is a tool failure like any other, and
			// the harness never turns one of those into a judgement about the code.
			return nil, nil, fmt.Errorf("re-running the failing tests in %s: %w", pkg, runErr)
		}
		for _, f := range repeat {
			stillFailing[f.Package+"\x00"+topLevelTest(f)] = true
		}
	}
	for _, f := range failures {
		name := topLevelTest(f)
		switch {
		case name == "" || strings.Contains(f.Output, raceReport):
			confirmed = append(confirmed, f)
		case stillFailing[f.Package+"\x00"+name]:
			confirmed = append(confirmed, f)
		default:
			flaky = appendUnique(flaky, f.Package+"."+name)
		}
	}
	return confirmed, flaky, nil
}

// flakyUnproducible turns a non-reproducing failure into missing evidence for
// the obligations that run was carrying.
func flakyUnproducible(flaky []string, raced bool) []admission.Unproducible {
	if len(flaky) == 0 {
		return nil
	}
	kinds := []admission.EvidenceKind{admission.KindTestsPass}
	if raced {
		kinds = append(kinds, admission.KindRaceClean)
	}
	out := make([]admission.Unproducible, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, admission.Unproducible{
			Kind:   kind,
			Reason: "these tests failed and then passed unchanged: " + strings.Join(flaky, ", "),
			Remedy: "make the named tests deterministic; a suite that answers differently each run cannot support a verdict",
		})
	}
	return out
}

// topLevelTest is the name a -run pattern has to name to reach a failure,
// which for a failing subtest is the parent it lives in.
func topLevelTest(f tool.TestFailure) string {
	name, _, _ := strings.Cut(f.Test, "/")
	return name
}

func testNamePattern(names []string) string {
	return "^(" + strings.Join(names, "|") + ")$"
}

func appendUnique(items []string, value string) []string {
	if slices.Contains(items, value) {
		return items
	}
	return append(items, value)
}

// testFailureEvidence names a failing test by the test, and describes it with
// whatever the run printed.
//
// The two have to be separate. A suite that logs a timestamp, a generated key,
// or any other line that moves puts that line in the description, and a finding
// named by its description is a different finding every run: ten failures were
// reported as introduced between two runs of one commit, and one flaky race
// arrived as new, fixed and pre-existing inside a single report.
func (t *target) testFailureEvidence(f tool.TestFailure) evidence.Evidence {
	name := f.Test
	if name == "" {
		name = "package"
	}
	e := t.newEvidence(policy.RuleTestFailure, "go test", tool.GoVersion(),
		evidence.SeverityError, "", 0, 0, f.Package,
		"test "+name+" failed: "+firstMeaningfulLine(f.Output))
	e.Identity = policy.RuleTestFailure + " " + f.Package + " " + topLevelTest(f)
	return e
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
	e := t.newEvidence(policy.RuleModTidy, "go mod tidy", tool.GoVersion(),
		evidence.SeverityError, "go.mod", 0, 0, "",
		"module requirements are not tidy; `go mod tidy` would change go.mod or go.sum")
	e.Fix = &evidence.Remediation{Command: "go mod tidy"}
	return checkResult{evidence: []evidence.Evidence{e}}, nil
}

// runVulnScan scans in process against the provisioned database snapshot.
//
// Without a snapshot the obligation is unproducible, never a pass: the harness
// will not report a change free of known vulnerabilities on the strength of
// having no database to check against. A stale snapshot still scans; its age is
// surfaced in the report and by doctor.
func (t *target) runVulnScan(ctx context.Context) (checkResult, error) {
	if t.engine.GoVersion == "" {
		reason := "the Go toolchain version could not be resolved, so the standard " +
			"library this scan would judge is unknown"
		if t.engine.GoVersionErr != nil {
			reason += ": " + t.engine.GoVersionErr.Error()
		}
		return checkResult{unproducible: []admission.Unproducible{{
			Kind:   admission.KindVulnerabilityScan,
			Reason: reason,
			Remedy: "make sure the go command runs inside this module; `goharness doctor` reports the same probe",
		}}}, nil
	}
	if reason, below := t.belowToolchainFloor(); below {
		return checkResult{unproducible: []admission.Unproducible{{
			Kind:   admission.KindVulnerabilityScan,
			Reason: reason,
			Remedy: "install the toolchain the module requires, or lower the go.mod toolchain directive if it no longer reflects a floor",
		}}}, nil
	}
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

	findings, err := tool.RunVulnScan(ctx, t.root, cache.VulnDBURL(), t.engine.GoVersion, []string{"./..."})
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

// belowToolchainFloor reports whether the toolchain performing this scan is
// older than the one the module's go.mod requires.
//
// Verification pins GOTOOLCHAIN=local so that it downloads nothing, and under
// that setting the go command ignores the module's toolchain directive
// entirely. A module that names a newer toolchain has usually named it for a
// reason, and the reason is often that the newer standard library is the one
// without the vulnerabilities. Scanning below the floor and reporting the
// module clean would be answering a question nobody asked: the honest answer is
// that this run cannot settle the claim.
func (t *target) belowToolchainFloor() (string, bool) {
	required := t.engine.ToolchainFloor
	if required == "" || t.engine.GoVersion == "" {
		return "", false
	}
	if tool.CompareGoVersions(t.engine.GoVersion, required) >= 0 {
		return "", false
	}
	return "the installed toolchain is " + t.engine.GoVersion + ", below the " + required +
		" floor go.mod declares, so a scan here would judge a standard library this module " +
		"does not accept and no scan was performed", true
}

// leakAnchor locates a leak as precisely as the tools allow.
//
// goleak's stack head is used only when it points inside this tree: a goroutine
// parked in the standard library or a dependency is real, but naming a file the
// reader cannot edit is worse than naming the package they can. The line is
// reported for navigation only; fingerprints exclude it, so a leak keeps its
// identity when the file above it moves.
func (t *target) leakAnchor(f tool.TestFailure) (file string, line int) {
	if origin, ok := leakcheck.LeakOrigin(f.Output); ok {
		path, lineText, _ := strings.Cut(origin, ":")
		rel := t.rel(path)
		if !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			return rel, parseLine(lineText)
		}
	}
	if dir, _, ok := t.graph.DirAndName(f.Package); ok {
		return t.rel(dir), 0
	}
	return "", 0
}

func parseLine(text string) int {
	n, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0
	}
	return n
}
