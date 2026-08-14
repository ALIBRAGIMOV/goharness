package verify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"go.uber.org/zap"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// Mutation budgets. They bound the cost of the evidence, not its meaning: the
// engine reports INCONCLUSIVE rather than PASS when a budget runs out before
// any signal arrives.
const (
	MaxMutants       = 16
	MutantTimeout    = 60 * time.Second
	MutationBudget   = 5 * time.Minute
	mutationOverlays = "goharness-mutation-"

	// maxReportedSurvivors keeps a badly tested change readable: the first few
	// survivors already prove the tests do not observe the change.
	maxReportedSurvivors = 8
)

// runMutation injects deliberate defects into the functions the change touched
// and reports whether any test noticed. The worktree is never written: each
// mutant is a temporary file applied through a go build overlay.
func (c *comparison) runMutation(ctx context.Context) (checkResult, error) {
	targets, err := analyze.ChangedFunctions(ctx, c.base.root, c.head.root, c.head.changed)
	if err != nil {
		return checkResult{}, err
	}
	if len(targets) == 0 {
		return checkResult{unproducible: mutationUnproducible(
			"the change edits no function body that could be mutated",
			"change production code, or drop tests from the contract's declared risks")}, nil
	}
	mutants, err := analyze.GenerateMutants(ctx, c.head.root, targets, MaxMutants)
	if err != nil {
		return checkResult{}, err
	}
	if len(mutants) == 0 {
		return checkResult{unproducible: mutationUnproducible(
			"no mutable construct was found in the changed functions",
			"the changed code has no branch, comparison, or error return to mutate")}, nil
	}

	budget, cancel := context.WithTimeout(ctx, MutationBudget)
	defer cancel()

	outcome, err := c.runMutants(budget, mutants)
	if err != nil {
		return checkResult{}, err
	}
	return outcome, nil
}

type mutationOutcome struct {
	killed   int
	survived []analyze.Mutant
	ran      int
}

func (c *comparison) runMutants(ctx context.Context, mutants []analyze.Mutant) (result checkResult, err error) {
	dir, err := os.MkdirTemp("", mutationOverlays)
	if err != nil {
		return checkResult{}, fmt.Errorf("creating mutation workspace: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil && err == nil {
			err = fmt.Errorf("removing mutation workspace: %w", rmErr)
		}
	}()

	var outcome mutationOutcome
	for i, mutant := range mutants {
		if ctx.Err() != nil {
			break
		}
		patterns := c.mutationTestPatterns(mutant)
		if len(patterns) == 0 {
			continue
		}
		killed, ran, err := c.runOneMutant(ctx, dir, i, mutant, patterns)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			return checkResult{}, err
		}
		if !ran {
			continue
		}
		outcome.ran++
		if killed {
			outcome.killed++
			continue
		}
		outcome.survived = append(outcome.survived, mutant)
	}
	return c.mutationResult(outcome), nil
}

func (c *comparison) runOneMutant(
	ctx context.Context, dir string, index int, mutant analyze.Mutant, patterns []string,
) (killed, ran bool, err error) {
	mutantPath := filepath.Join(dir, fmt.Sprintf("mutant-%02d.go", index))
	if err := os.WriteFile(mutantPath, mutant.Source, 0o600); err != nil {
		return false, false, fmt.Errorf("writing mutant source: %w", err)
	}
	original := filepath.Join(c.head.root, filepath.FromSlash(mutant.File))
	overlay, err := tool.OverlayPath(dir, map[string]string{original: mutantPath})
	if err != nil {
		return false, false, err
	}

	attempt, cancel := context.WithTimeout(ctx, MutantTimeout)
	defer cancel()

	c.engine.Logger.Debug("running mutant",
		zap.String("file", mutant.File),
		zap.Int("line", mutant.Line),
		zap.String("operator", mutant.Operator))

	failed, err := tool.RunTestsWithOverlay(attempt, c.engine.Runner, c.head.root, overlay, patterns)
	if err != nil {
		// A mutant that times out is not evidence either way; it simply did not
		// run, and the budget accounting treats it as such.
		if errors.Is(err, context.DeadlineExceeded) || attempt.Err() != nil {
			return false, false, nil
		}
		return false, false, err
	}
	return failed, true, nil
}

// mutationTestPatterns returns the mutated package and its direct importers,
// which is where a test able to observe the mutation can live.
func (c *comparison) mutationTestPatterns(mutant analyze.Mutant) []string {
	pkgPath, ok := c.head.graph.PackageForFile(mutant.File)
	if !ok {
		return nil
	}
	scope := c.head.graph.Affected([]string{pkgPath}, change.ScopeDirectDependents)
	return c.head.graph.PatternsFor(scope)
}

func (c *comparison) mutationResult(outcome mutationOutcome) checkResult {
	switch {
	case outcome.ran == 0:
		return checkResult{unproducible: mutationUnproducible(
			"no test covered the mutated packages within the mutation budget",
			"add a test that exercises the changed functions, then run verify again")}
	case outcome.killed > 0:
		return checkResult{}
	default:
		reported := survivorsWithin(outcome.survived, maxReportedSurvivors)
		out := make([]evidence.Evidence, 0, len(reported))
		for _, mutant := range reported {
			out = append(out, c.head.engine.Policy.Decorate(c.head.newEvidence(
				policy.RuleMutantsSurvived, "go test -overlay", tool.GoVersion(),
				evidence.SeverityError, mutant.File, mutant.Line, 0, "",
				"tests still pass with "+mutant.Description+", so they execute this code without observing it")))
		}
		return checkResult{evidence: out}
	}
}

func mutationUnproducible(reason, remedy string) []admission.Unproducible {
	return []admission.Unproducible{{
		Kind: admission.KindMutationSignal, Reason: reason, Remedy: remedy,
	}}
}

// survivorsWithin caps how many surviving mutants are reported, so a badly
// tested change produces a readable report rather than a wall of findings.
func survivorsWithin(mutants []analyze.Mutant, limit int) []analyze.Mutant {
	if len(mutants) <= limit {
		return mutants
	}
	return slices.Clone(mutants[:limit])
}
