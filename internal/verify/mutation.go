package verify

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
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
	targets, err := analyze.ChangedFunctions(ctx, c.base.tree.FS(), c.head.tree.FS(), c.head.changed)
	if err != nil {
		return checkResult{}, err
	}
	// A change that edits no function body, or whose functions offer the
	// operators nothing to damage, has nothing a test could fail to notice.
	// The obligation is discharged with the count that says so. Reporting it
	// unproducible made a test-only change and a one-line accessor changes
	// nobody could finish, with a remedy that asked for branches to exist.
	if len(targets) == 0 {
		return checkResult{mutation: &MutationCoverage{}}, nil
	}
	mutants, err := analyze.GenerateMutants(ctx, c.head.tree.FS(), targets, MaxMutants)
	if err != nil {
		return checkResult{}, err
	}
	if len(mutants) == 0 {
		return checkResult{mutation: &MutationCoverage{Targets: len(targets)}}, nil
	}

	budget, cancel := context.WithTimeout(ctx, MutationBudget)
	defer cancel()

	outcome, err := c.runMutants(budget, mutants)
	if err != nil {
		return checkResult{}, err
	}
	outcome.mutation.Targets = len(targets)
	outcome.mutation.Mutants = len(mutants)
	return outcome, nil
}

type mutationOutcome struct {
	killed   int
	survived []analyze.Mutant
	ran      int
	timedOut int
	unbuilt  int
	// unconfirmed counts mutants that survived the tests nearest them and whose
	// wider search did not finish, so neither answer was established.
	unconfirmed int
}

// runMutants offers every mutant to the tests written for the code it damaged,
// and only then, if none of them noticed, to the tests further away.
//
// The two passes exist because the two questions have very different prices. A
// mutant killed by its own package's tests answers the whole obligation in
// seconds, and one kill is all the evidence this claim asks for. Widening to the
// importers is what keeps a survivor honest, since a test one package away can
// still be the one watching, but in a repository with a slow suite that search
// costs minutes per mutant. Paying it only when the near tests noticed nothing
// is what makes mutation evidence affordable on a real codebase.
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

	outcome, survivors, err := c.runNearPass(ctx, dir, mutants)
	if err != nil {
		return checkResult{}, err
	}
	if outcome.killed == 0 {
		if err := c.runWidePass(ctx, dir, survivors, &outcome); err != nil {
			return checkResult{}, err
		}
	} else {
		outcome.survived = nil
	}
	return c.mutationResult(outcome), nil
}

// candidate is a mutant that survived the tests closest to it, kept with the
// index that names its overlay file.
type candidate struct {
	index  int
	mutant analyze.Mutant
}

// runNearPass offers each mutant to the tests of the package it damaged, and
// stops at the first kill. One kill is the whole of what this claim asks for, so
// every further near run would spend another pass of a package's tests to
// establish something already established. On a healthy change that is the
// difference between one run of one package and sixteen.
func (c *comparison) runNearPass(
	ctx context.Context, dir string, mutants []analyze.Mutant,
) (mutationOutcome, []candidate, error) {
	var outcome mutationOutcome
	var survivors []candidate
	for i, mutant := range mutants {
		if budgetExhausted(ctx) {
			break
		}
		scope := c.nearScope(mutant)
		if len(scope) == 0 {
			continue
		}
		attempt, err := c.runOneMutant(ctx, dir, i, mutant, scope)
		if err != nil {
			return outcome, nil, err
		}
		switch {
		case attempt.timedOut:
			outcome.timedOut++
		case attempt.unbuilt:
			outcome.unbuilt++
		case attempt.killed:
			outcome.ran++
			outcome.killed++
			return outcome, nil, nil
		case attempt.ran:
			outcome.ran++
			outcome.survived = append(outcome.survived, mutant)
			survivors = append(survivors, candidate{index: i, mutant: mutant})
		}
	}
	return outcome, survivors, nil
}

// runWidePass gives each survivor the tests of the packages that import it. A
// kill there is still a kill; a survivor whose wider search ran out of time is
// dropped from the survivor list, because reporting weak tests on the strength
// of a search that did not finish would be an accusation the run cannot support.
func (c *comparison) runWidePass(
	ctx context.Context, dir string, survivors []candidate, outcome *mutationOutcome,
) error {
	var confirmed []analyze.Mutant
	for _, s := range survivors {
		if budgetExhausted(ctx) {
			break
		}
		scope := c.wideScope(s.mutant)
		if len(scope) == 0 {
			confirmed = append(confirmed, s.mutant)
			continue
		}
		attempt, err := c.runOneMutant(ctx, dir, s.index, s.mutant, scope)
		if err != nil {
			return err
		}
		switch {
		case attempt.killed:
			outcome.killed++
		case attempt.ran:
			confirmed = append(confirmed, s.mutant)
		default:
			outcome.unconfirmed++
		}
	}
	outcome.survived = confirmed
	return nil
}

// budgetExhausted reports whether the mutation budget has run out. A spent
// budget ends the search with whatever it has established by then; that is an
// expected outcome of a bounded search, not a failure, so it never travels as
// an error.
func budgetExhausted(ctx context.Context) bool {
	return ctx.Err() != nil
}

// mutantResult is what one mutant's run established, if anything.
type mutantResult struct {
	killed   bool
	ran      bool
	timedOut bool
	// unbuilt means the mutant did not compile, so no test saw it. It is not
	// a kill: go test exits 1 either way, and a compiler error standing in
	// for a test once discharged the whole test-effectiveness claim.
	unbuilt bool
}

// runOneMutant applies one mutant through a build overlay and runs one scope of
// tests against it.
func (c *comparison) runOneMutant(
	ctx context.Context, dir string, index int, mutant analyze.Mutant, patterns []string,
) (mutantResult, error) {
	mutantPath := filepath.Join(dir, fmt.Sprintf("mutant-%02d.go", index))
	if err := os.WriteFile(mutantPath, mutant.Source, 0o600); err != nil {
		return mutantResult{}, fmt.Errorf("writing mutant source: %w", err)
	}
	original := filepath.Join(c.head.root, filepath.FromSlash(mutant.File))
	overlay, err := tool.OverlayPath(dir, map[string]string{original: mutantPath})
	if err != nil {
		return mutantResult{}, err
	}

	c.engine.Logger.Debug("running mutant",
		slog.String("file", mutant.File),
		slog.Int("line", mutant.Line),
		slog.String("operator", mutant.Operator),
		slog.Any("scope", patterns))

	attempt, cancel := context.WithTimeout(ctx, MutantTimeout)
	defer cancel()

	outcome, err := tool.RunTestsWithOverlay(attempt, c.engine.Runner, c.head.root, overlay, patterns)
	if err != nil {
		// A mutant that runs out of time is not evidence either way; it simply
		// did not run, and the budget accounting treats it as such. The mutation
		// budget expiring cancels this attempt too, so it arrives here as well
		// and no deadline ever escapes as a failure.
		if attempt.Err() != nil {
			return mutantResult{timedOut: true}, nil
		}
		return mutantResult{}, err
	}
	switch outcome {
	case tool.OverlayNotBuilt:
		return mutantResult{unbuilt: true}, nil
	case tool.OverlayFailed:
		return mutantResult{killed: true, ran: true}, nil
	default:
		return mutantResult{ran: true}, nil
	}
}

// nearScope is the mutated package itself, or its importers when it carries no
// tests of its own and so has nothing near enough to notice.
func (c *comparison) nearScope(mutant analyze.Mutant) []string {
	pkgPath, ok := c.head.graph.PackageForFile(mutant.File)
	if !ok {
		return nil
	}
	if !c.headPackageHasTests(pkgPath) {
		return c.wideScope(mutant)
	}
	return c.head.graph.PatternsFor([]string{pkgPath})
}

// wideScope is the mutated package together with everything that imports it.
func (c *comparison) wideScope(mutant analyze.Mutant) []string {
	pkgPath, ok := c.head.graph.PackageForFile(mutant.File)
	if !ok {
		return nil
	}
	return c.head.graph.PatternsFor(
		c.head.graph.Affected([]string{pkgPath}, change.ScopeDirectDependents))
}

// headPackageHasTests reports whether a package carries test files of its own.
// A listing error means the same thing to this decision as no tests: use the
// wider scope, which can only find more.
func (c *comparison) headPackageHasTests(pkgPath string) bool {
	dir, _, ok := c.head.graph.DirAndName(pkgPath)
	if !ok {
		return false
	}
	hasTests, err := leakcheck.HasTestFiles(c.head.tree.FS(), c.head.rel(dir))
	return err == nil && hasTests
}

func (c *comparison) mutationResult(outcome mutationOutcome) checkResult {
	result := c.mutationVerdict(outcome)
	result.mutation = &MutationCoverage{
		Ran: outcome.ran, Killed: outcome.killed, Survived: len(outcome.survived),
		Unbuilt: outcome.unbuilt, TimedOut: outcome.timedOut,
	}
	return result
}

func (c *comparison) mutationVerdict(outcome mutationOutcome) checkResult {
	switch {
	case outcome.ran == 0 && outcome.timedOut > 0:
		return checkResult{unproducible: mutationUnproducible(
			fmt.Sprintf("%d mutant run(s) exceeded the %s budget before any test could report",
				outcome.timedOut, MutantTimeout),
			"shorten the tests covering the changed functions, or make the change smaller")}
	case outcome.ran == 0 && outcome.unbuilt > 0:
		return checkResult{unproducible: mutationUnproducible(
			fmt.Sprintf("%d mutant(s) did not compile, so no test could observe them", outcome.unbuilt),
			"give the changed functions a comparison, boolean or error return that a test observes; "+
				"a mutant that does not build is not evidence either way")}
	case outcome.ran == 0:
		return checkResult{unproducible: mutationUnproducible(
			"no test covered the mutated packages within the mutation budget",
			"add a test that exercises the changed functions, then run verify again")}
	case outcome.killed > 0:
		return checkResult{}
	case len(outcome.survived) == 0:
		return checkResult{unproducible: mutationUnproducible(
			fmt.Sprintf("%d mutant(s) survived the tests nearest them and the wider search did not finish in time",
				outcome.unconfirmed),
			"add a test in the changed package that observes the change, so the answer arrives before the budget does")}
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
