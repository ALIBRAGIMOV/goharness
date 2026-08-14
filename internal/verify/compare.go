package verify

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
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
		baseSurface = map[string]string{}
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
	headMetrics, err := analyze.ComputeMetrics(ctx, c.head.root, c.head.files)
	if err != nil {
		return checkResult{}, err
	}
	baseMetrics, err := analyze.ComputeMetrics(ctx, c.base.root, c.base.files)
	if err != nil {
		return checkResult{}, err
	}
	findings := analyze.MaintainabilityFindings(baseMetrics, headMetrics)
	return checkResult{evidence: c.head.fromFindings(findings, "goharness")}, nil
}

func (c *comparison) runAntiWeakening(ctx context.Context) (checkResult, error) {
	headShapes, err := analyze.TestShapes(ctx, c.head.root, c.head.files)
	if err != nil {
		return checkResult{}, err
	}
	baseShapes, err := analyze.TestShapes(ctx, c.base.root, c.base.files)
	if err != nil {
		return checkResult{}, err
	}
	survives := func(dir string) bool {
		_, err := os.Stat(filepath.Join(c.head.root, filepath.FromSlash(dir)))
		return err == nil
	}
	findings := analyze.WeakeningFindings(baseShapes, headShapes, survives)
	return checkResult{evidence: c.head.fromFindings(findings, "goharness")}, nil
}

func (c *comparison) runBenchmarks(ctx context.Context) (checkResult, error) {
	patterns := c.head.graph.PatternsFor(c.head.testPackages)
	if len(patterns) == 0 {
		return checkResult{unproducible: unmeasurableBench("no package in scope could be benchmarked")}, nil
	}
	headResults, err := tool.RunBenchmarks(ctx, c.engine.Runner, c.head.root, patterns)
	if err != nil {
		return checkResult{}, err
	}
	basePatterns := c.base.graph.PatternsFor(c.base.testPackages)
	baseResults, err := tool.RunBenchmarks(ctx, c.engine.Runner, c.base.root, basePatterns)
	if err != nil {
		return checkResult{}, err
	}
	common := tool.BenchmarkNames(baseResults, headResults)
	if len(common) == 0 {
		return checkResult{unproducible: unmeasurableBench(
			"no benchmark ran at both base and head")}, nil
	}

	var out []evidence.Evidence
	for _, name := range common {
		out = append(out, c.compareBenchmark(name, baseResults[name], headResults[name])...)
	}
	return checkResult{evidence: out}, nil
}

func unmeasurableBench(reason string) []admission.Unproducible {
	return []admission.Unproducible{
		{
			Kind: admission.KindBenchDelta, Reason: reason,
			Remedy: "add a Benchmark function to the changed package, or remove hot-path from the contract's declared risks",
		},
		{
			Kind: admission.KindAllocDelta, Reason: reason,
			Remedy: "add a Benchmark function to the changed package, or remove hot-path from the contract's declared risks",
		},
	}
}

func (c *comparison) compareBenchmark(name string, base, head tool.BenchResult) []evidence.Evidence {
	budget := c.head.contract.BudgetFor(name)
	var out []evidence.Evidence

	if timeRise, regressed := regression(base.MedianNs(), head.MedianNs(),
		budget.MaxTimeIncreasePercent, head.SpreadNs()); regressed {
		out = append(out, c.head.engine.Policy.Decorate(c.head.newEvidence(
			policy.RuleBenchTimeDelta, "go test -bench", tool.GoVersion(),
			evidence.SeverityError, "", 0, 0, "",
			fmt.Sprintf("%s slowed by %.1f%% (%.0f to %.0f ns/op), past the %.0f%% budget and the %.1f%% sample spread",
				name, timeRise, base.MedianNs(), head.MedianNs(),
				budget.MaxTimeIncreasePercent, head.SpreadNs()))))
	}
	if allocRise, regressed := regression(base.MedianAllocs(), head.MedianAllocs(),
		budget.MaxAllocIncreasePercent, 0); regressed {
		out = append(out, c.head.engine.Policy.Decorate(c.head.newEvidence(
			policy.RuleBenchAllocDelta, "go test -bench", tool.GoVersion(),
			evidence.SeverityError, "", 0, 0, "",
			fmt.Sprintf("%s allocations rose by %.1f%% (%.0f to %.0f allocs/op), past the %.0f%% budget",
				name, allocRise, base.MedianAllocs(), head.MedianAllocs(),
				budget.MaxAllocIncreasePercent))))
	}
	return out
}

// regression reports the percentage rise and whether it exceeds both the budget
// and the observed sample spread, so measurement noise never fails a claim.
func regression(base, head, budgetPercent, spreadPercent float64) (float64, bool) {
	if base <= 0 {
		return 0, false
	}
	rise := (head - base) / base * 100
	return rise, rise > budgetPercent && rise > spreadPercent
}
