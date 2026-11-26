package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// comparison runs the producers that need both snapshots at once. They cannot
// live in the per-tree DAG because a single tree carries no delta.
type comparison struct {
	engine *Engine
	head   *target
	base   *target
}

func (c *comparison) checksFor(planned []admission.PlannedCheck) []Check {
	runners := map[string]runFunc{
		admission.ProducerAPICompat:    c.runAPICompat,
		admission.ProducerMaintainable: c.runMaintainability,
		admission.ProducerAntiWeaken:   c.runAntiWeakening,
		admission.ProducerMutation:     c.runMutation,
		admission.ProducerBenchmark:    c.runBenchmarks,
		admission.ProducerDependency:   c.runDependencies,
	}
	checks := make([]Check, 0, len(planned))
	for _, p := range planned {
		run, ok := runners[p.ID]
		if !ok {
			continue
		}
		checks = append(checks, Check{ID: p.ID, Tool: p.Tool, Produces: p.Produces, run: run})
	}
	sortChecks(checks)
	return checks
}

// changedPackagePatterns returns the head packages that contain a changed file,
// which is the smallest set the comparison producers need to look at.
func (c *comparison) changedPackagePatterns() []string {
	dirs := map[string]bool{}
	for _, rel := range c.head.changed {
		if strings.HasSuffix(rel, ".go") {
			dirs[filepath.ToSlash(filepath.Dir(rel))] = true
		}
	}
	var out []string
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		out = append(out, "./"+dir)
	}
	return out
}

func (c *comparison) runAPICompat(ctx context.Context) (checkResult, error) {
	patterns := c.changedPackagePatterns()
	if len(patterns) == 0 {
		return checkResult{unproducible: []admission.Unproducible{{
			Kind:   admission.KindAPICompat,
			Reason: "no Go package in the change could be located for comparison",
			Remedy: "run verify from a worktree where the changed packages build",
		}}}, nil
	}
	headSurface, err := analyze.ExportSurface(ctx, c.head.root, patterns)
	if err != nil {
		return checkResult{}, err
	}
	baseSurface, err := analyze.ExportSurface(ctx, c.base.root, patterns)
	if err != nil {
		// A package that does not exist at base cannot have broken; its symbols
		// are additions.
		baseSurface = map[string]analyze.Exported{}
	}
	findings := analyze.APIBreakFindings(baseSurface, headSurface)
	if c.head.contract.AllowAPIBreak {
		for i := range findings {
			findings[i].Advisory = true
			findings[i].Message += " (permitted: the task contract sets allowApiBreak)"
		}
	}
	return checkResult{evidence: c.head.fromFindings(findings, "goharness")}, nil
}

func (c *comparison) runMaintainability(ctx context.Context) (checkResult, error) {
	headMetrics, err := analyze.ComputeMetrics(ctx, c.head.tree.FS(), c.head.files)
	if err != nil {
		return checkResult{}, err
	}
	baseMetrics, err := analyze.ComputeMetrics(ctx, c.base.tree.FS(), c.base.files)
	if err != nil {
		return checkResult{}, err
	}
	findings := analyze.MaintainabilityFindings(baseMetrics, headMetrics, c.head.generatedFiles)
	return checkResult{evidence: c.head.fromFindings(findings, "goharness")}, nil
}

func (c *comparison) runAntiWeakening(ctx context.Context) (checkResult, error) {
	headShapes, err := analyze.TestShapes(ctx, c.head.tree.FS(), c.head.files)
	if err != nil {
		return checkResult{}, err
	}
	baseShapes, err := analyze.TestShapes(ctx, c.base.tree.FS(), c.base.files)
	if err != nil {
		return checkResult{}, err
	}
	survives := func(dir string) bool {
		_, err := fs.Stat(c.head.tree.FS(), dir)
		return err == nil
	}
	findings := analyze.WeakeningFindings(baseShapes, headShapes, survives)
	return checkResult{evidence: c.head.fromFindings(findings, "goharness")}, nil
}

// runBenchmarks measures the packages the change edited, at both revisions.
//
// The scope is the changed packages and not the reverse-dependency closure,
// because the closure is what made this the most expensive check in the harness
// while measuring almost nothing: on a large module most of a run can go to
// benchmarks in a package whose measured functions call nothing the change
// touched. The obligation was activated by "a benchmark in a
// changed directory" in the first place, so answering it over exactly those
// directories is what was asked.
func (c *comparison) runBenchmarks(ctx context.Context) (checkResult, error) {
	changed := c.head.graph.SeedPackages(c.head.changed)
	patterns := c.head.graph.PatternsFor(changed)
	if len(patterns) == 0 {
		return checkResult{unproducible: unmeasurableBench(
			"no package the change edited could be benchmarked", benchRemedy)}, nil
	}
	// Named from the head scope so that both revisions measure the same packages
	// whatever the base tree happens to hold.
	basePatterns := c.base.graph.PatternsFor(changed)
	baseRun, headRun, err := c.sampleBenchmarks(ctx, basePatterns, patterns)
	if err != nil {
		return checkResult{}, err
	}

	var result checkResult
	// A benchmark that fails at both revisions measured nothing about the
	// change and is reported as the debt it is; one that fails only at head
	// ran at base, so the change is what broke it, and the claim it feeds
	// cannot be discharged around it.
	for _, name := range slices.Sorted(maps.Keys(headRun.Broken)) {
		broken := headRun.Broken[name]
		if _, atBase := baseRun.Broken[name]; !atBase {
			result.unproducible = append(result.unproducible, unmeasurableBench(
				name+" fails at head and ran at the base revision: "+broken.Output,
				"fix the benchmark; it ran before this change")...)
			continue
		}
		e := c.head.newEvidence(policy.RuleBenchBroken, "go test -bench", tool.GoVersion(),
			evidence.SeverityWarning, "", 0, 0, broken.Package,
			name+" fails at the base revision and at head, so it measures nothing: "+broken.Output)
		e.Identity = policy.RuleBenchBroken + " " + broken.Package + " " + name
		result.evidence = append(result.evidence, c.head.engine.Policy.Decorate(e))
	}

	common := tool.BenchmarkNames(baseRun.Results, headRun.Results)
	if len(common) == 0 && len(result.unproducible) == 0 {
		reason := "no benchmark ran at both base and head"
		if broken := slices.Sorted(maps.Keys(headRun.Broken)); len(broken) > 0 {
			reason += "; failing: " + strings.Join(broken, ", ")
		}
		result.unproducible = unmeasurableBench(reason, benchRemedy)
	}
	for _, name := range common {
		result.evidence = append(result.evidence,
			c.compareBenchmark(name, baseRun.Results[name], headRun.Results[name])...)
	}
	return result, nil
}

// sampleBenchmarks measures both revisions, alternating between them.
//
// Interleaving is the whole point. A machine's load drifts over the minutes a
// comparison takes, and measuring one revision to completion and then the other
// turns that drift into a regression report for every benchmark at once.
// Alternating gives both sides the same conditions, so what survives the
// comparison is the change rather than the weather.
func (c *comparison) sampleBenchmarks(
	ctx context.Context, basePatterns, headPatterns []string,
) (base, head tool.BenchRun, err error) {
	base = tool.BenchRun{Results: map[string]tool.BenchResult{}, Broken: map[string]tool.BrokenBenchmark{}}
	head = tool.BenchRun{Results: map[string]tool.BenchResult{}, Broken: map[string]tool.BrokenBenchmark{}}
	for range tool.BenchSamples {
		baseSample, err := tool.RunBenchmarks(ctx, c.engine.Runner, c.base.root,
			basePatterns, slices.Sorted(maps.Keys(base.Broken)))
		if err != nil {
			return tool.BenchRun{}, tool.BenchRun{}, err
		}
		headSample, err := tool.RunBenchmarks(ctx, c.engine.Runner, c.head.root,
			headPatterns, slices.Sorted(maps.Keys(head.Broken)))
		if err != nil {
			return tool.BenchRun{}, tool.BenchRun{}, err
		}
		tool.MergeBenchResults(base.Results, baseSample.Results)
		tool.MergeBenchResults(head.Results, headSample.Results)
		maps.Copy(base.Broken, baseSample.Broken)
		maps.Copy(head.Broken, headSample.Broken)
	}
	return base, head, nil
}

const benchRemedy = "add a Benchmark function to the changed package, or remove hot-path from the contract's declared risks"

func unmeasurableBench(reason, remedy string) []admission.Unproducible {
	return []admission.Unproducible{
		{Kind: admission.KindBenchDelta, Reason: reason, Remedy: remedy},
		{Kind: admission.KindAllocDelta, Reason: reason, Remedy: remedy},
	}
}

func (c *comparison) compareBenchmark(name string, base, head tool.BenchResult) []evidence.Evidence {
	budget := c.head.contract.BudgetFor(name)
	var out []evidence.Evidence

	if timeRise, regressed := timeRegression(base, head, budget.MaxTimeIncreasePercent); regressed {
		baseFastest, baseSlowest := base.RangeNs()
		headFastest, headSlowest := head.RangeNs()
		out = append(out, c.head.engine.Policy.Decorate(c.head.newEvidence(
			policy.RuleBenchTimeDelta, "go test -bench", tool.GoVersion(),
			evidence.SeverityError, "", 0, 0, "",
			fmt.Sprintf("%s slowed by %.1f%% past the %.0f%% budget: every head sample (%.0f to %.0f ns/op) is slower than every base sample (%.0f to %.0f ns/op)",
				name, timeRise, budget.MaxTimeIncreasePercent,
				headFastest, headSlowest, baseFastest, baseSlowest))))
	}
	if allocRise, regressed := regression(base.MedianAllocs(), head.MedianAllocs(),
		budget.MaxAllocIncreasePercent); regressed {
		out = append(out, c.head.engine.Policy.Decorate(c.head.newEvidence(
			policy.RuleBenchAllocDelta, "go test -bench", tool.GoVersion(),
			evidence.SeverityError, "", 0, 0, "",
			fmt.Sprintf("%s allocations rose by %.1f%% (%.0f to %.0f allocs/op), past the %.0f%% budget",
				name, allocRise, base.MedianAllocs(), head.MedianAllocs(),
				budget.MaxAllocIncreasePercent))))
	}
	return out
}

// timeRegression reports a benchmark that got slower by more than its budget
// and did so beyond any doubt the samples leave.
//
// Beyond doubt is two tests, and the second one is the load test. The medians
// have to differ by more than the budget, and then the most optimistic reading of
// head, its fastest sample, has to exceed the budget against the most pessimistic
// reading of base, its slowest. Merely separating the ranges is not enough: a
// machine that is also running the other revision's test suite stretches head's
// samples upward by a few percent, which separates two ranges that describe
// identical code. This harness rejected its own change that way, over a
// difference measured at under one percent on an idle machine, and a gate that
// cries wolf spends the authority it needs.
func timeRegression(base, head tool.BenchResult, budgetPercent float64) (float64, bool) {
	rise, over := regression(base.MedianNs(), head.MedianNs(), budgetPercent)
	if !over {
		return rise, false
	}
	_, baseSlowest := base.RangeNs()
	headFastest, _ := head.RangeNs()
	_, beyondDoubt := regression(baseSlowest, headFastest, budgetPercent)
	return rise, beyondDoubt
}

// regression reports the percentage rise and whether it exceeds the budget.
func regression(base, head, budgetPercent float64) (float64, bool) {
	if base <= 0 {
		return 0, false
	}
	rise := (head - base) / base * 100
	return rise, rise > budgetPercent
}

// runDependencies reports the direct requirements head's go.mod carries that
// base's did not. The rule is advisory: a new dependency is a decision rather
// than a defect, and the finding exists so that the decision is seen as one
// instead of passing as a line in a lockfile.
func (c *comparison) runDependencies(_ context.Context) (checkResult, error) {
	headSrc, err := c.head.tree.ReadFile("go.mod")
	if err != nil {
		return checkResult{}, fmt.Errorf("reading go.mod at head: %w", err)
	}
	// A base without a go.mod required nothing, so every head requirement is
	// an addition; the module itself being new is the change's business.
	baseSrc, err := c.base.tree.ReadFile("go.mod")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return checkResult{}, fmt.Errorf("reading go.mod at base: %w", err)
	}
	direct := map[string]bool{}
	for _, req := range repo.ParseRequirements(string(baseSrc)) {
		if !req.Indirect {
			direct[req.Path] = true
		}
	}
	var out []evidence.Evidence
	for _, req := range repo.ParseRequirements(string(headSrc)) {
		if req.Indirect || direct[req.Path] {
			continue
		}
		e := c.head.newEvidence(policy.RuleNewDependency, "goharness", c.engine.Version,
			evidence.SeverityWarning, "go.mod", req.Line, 0, "",
			"change adds a direct requirement on "+req.Path+" "+req.Version)
		// The requirement is the identity: the version it was added at and the
		// line it landed on both move while the decision stays the same.
		e.Identity = policy.RuleNewDependency + " " + req.Path
		out = append(out, c.engine.Policy.Decorate(e))
	}
	return checkResult{evidence: out}, nil
}
