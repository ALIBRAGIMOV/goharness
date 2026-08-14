package verify

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// Engine holds everything a run needs that is not specific to one worktree.
type Engine struct {
	Runner         tool.Runner
	Git            repo.Git
	Logger         *zap.Logger
	Policy         policy.ResolvedPolicy
	Golangci       tool.Golangci
	GolangciConfig string
	Version        string
	Concurrency    int64
	ChangedEntries []change.Entry
	Progress       func(ProgressEvent)
	phase          string
}

func (e *Engine) notify(event ProgressEvent) {
	if e.Progress == nil {
		return
	}
	event.Phase = e.phase
	e.Progress(event)
}

type checkOutcome struct {
	id           string
	tool         string
	evidence     []evidence.Evidence
	unproducible []admission.Unproducible
	failure      error
	skipped      bool
	blocking     bool
	elapsed      time.Duration
}

// runOutput is what one scheduled plan produced.
type runOutput struct {
	Evidence     []evidence.Evidence
	Failures     []CheckFailure
	Skipped      []string
	VulnDB       *toolcache.VulnDBManifest
	Produced     []admission.EvidenceKind
	Unproducible []admission.Unproducible
	Timings      map[string]time.Duration
}

func (o *runOutput) merge(other runOutput) {
	o.Evidence = append(o.Evidence, other.Evidence...)
	o.Failures = append(o.Failures, other.Failures...)
	o.Skipped = append(o.Skipped, other.Skipped...)
	o.Produced = append(o.Produced, other.Produced...)
	o.Unproducible = append(o.Unproducible, other.Unproducible...)
	if o.Timings == nil {
		o.Timings = map[string]time.Duration{}
	}
	maps.Copy(o.Timings, other.Timings)
}

// schedule runs the checks respecting their dependencies, with independent
// checks running concurrently under a semaphore bounded by GOMAXPROCS. Each
// goroutine writes only its own slot and returns before Wait completes, so its
// lifetime is visible here; the coordinator owns all aggregation.
func (e *Engine) schedule(ctx context.Context, checks []Check) (runOutput, error) {
	limit := e.Concurrency
	if limit <= 0 {
		limit = int64(runtime.GOMAXPROCS(0))
	}
	sem := semaphore.NewWeighted(limit)

	outcomes := make([]checkOutcome, len(checks))
	index := map[string]int{}
	for i, c := range checks {
		index[c.ID] = i
	}
	completed := map[string]bool{}
	usable := map[string]bool{}

	remaining := len(checks)
	for remaining > 0 {
		wave, blocked := readyWave(checks, index, completed, usable)
		for _, i := range blocked {
			outcomes[i] = checkOutcome{id: checks[i].ID, tool: checks[i].Tool, skipped: true}
			completed[checks[i].ID] = true
			usable[checks[i].ID] = false
			remaining--
		}
		if len(wave) == 0 {
			if remaining > 0 && len(blocked) == 0 {
				return runOutput{}, fmt.Errorf(
					"execution plan has an unsatisfiable dependency among %d remaining checks", remaining)
			}
			continue
		}

		group, gctx := errgroup.WithContext(ctx)
		for _, i := range wave {
			group.Go(func() error {
				if err := sem.Acquire(gctx, 1); err != nil {
					return err
				}
				defer sem.Release(1)
				outcomes[i] = e.runOne(gctx, checks[i], len(checks))
				return nil
			})
		}
		if err := group.Wait(); err != nil {
			return runOutput{}, err
		}
		for _, i := range wave {
			completed[checks[i].ID] = true
			usable[checks[i].ID] = outcomes[i].failure == nil && !outcomes[i].blocking
			remaining--
		}
	}
	return collect(checks, outcomes), nil
}

func readyWave(checks []Check, index map[string]int, completed, usable map[string]bool) (wave, blocked []int) {
	for i, c := range checks {
		if completed[c.ID] {
			continue
		}
		ready, isBlocked := true, false
		for _, dep := range c.DependsOn {
			if _, known := index[dep]; !known {
				continue
			}
			if !completed[dep] {
				ready = false
				break
			}
			if !usable[dep] {
				isBlocked = true
			}
		}
		switch {
		case !ready:
		case isBlocked:
			blocked = append(blocked, i)
		default:
			wave = append(wave, i)
		}
	}
	return wave, blocked
}

// runOne executes one check under a recover guard: a panicking check becomes a
// CheckFailure, and therefore an INCONCLUSIVE claim, never a harness crash.
func (e *Engine) runOne(ctx context.Context, check Check, total int) (outcome checkOutcome) {
	started := time.Now()
	outcome = checkOutcome{id: check.ID, tool: check.Tool}
	e.notify(ProgressEvent{Check: check.ID, Total: total})
	defer func() {
		outcome.elapsed = time.Since(started)
		e.notify(ProgressEvent{Check: check.ID, Total: total, Done: true, Elapsed: outcome.elapsed})
		if recovered := recover(); recovered != nil {
			outcome.failure = fmt.Errorf("check %s panicked: %v\n%s",
				check.ID, recovered, debug.Stack())
		}
		e.Logger.Info("check finished",
			zap.String("check", check.ID),
			zap.Duration("elapsed", outcome.elapsed),
			zap.Bool("failed", outcome.failure != nil))
	}()

	e.Logger.Info("check started", zap.String("check", check.ID))
	result, err := check.run(ctx)
	outcome.evidence = result.evidence
	outcome.unproducible = result.unproducible
	outcome.failure = err
	outcome.blocking = check.ID == admission.ProducerCompile && len(result.evidence) > 0
	return outcome
}

func collect(checks []Check, outcomes []checkOutcome) runOutput {
	out := runOutput{Timings: map[string]time.Duration{}}
	unproduced := map[admission.EvidenceKind]bool{}

	for i, o := range outcomes {
		out.Timings[o.id] = o.elapsed
		switch {
		case o.failure != nil:
			out.Failures = append(out.Failures, CheckFailure{
				CheckID: o.id, Tool: o.tool,
				Reason: o.failure.Error(), Hint: hintFor(o.id),
			})
			for _, kind := range checks[i].Produces {
				unproduced[kind] = true
				out.Unproducible = append(out.Unproducible, admission.Unproducible{
					Kind: kind, Reason: o.id + " failed: " + firstLine(o.failure.Error()),
					Remedy: hintFor(o.id),
				})
			}
		case o.skipped:
			out.Skipped = append(out.Skipped, o.id)
			for _, kind := range checks[i].Produces {
				unproduced[kind] = true
				out.Unproducible = append(out.Unproducible, admission.Unproducible{
					Kind: kind, Reason: "the " + o.id + " check was skipped because a prerequisite failed",
					Remedy: "fix the failing prerequisite check first",
				})
			}
		default:
			out.Evidence = append(out.Evidence, o.evidence...)
			out.Unproducible = append(out.Unproducible, o.unproducible...)
			for _, u := range o.unproducible {
				unproduced[u.Kind] = true
			}
		}
	}
	for i, o := range outcomes {
		if o.failure != nil || o.skipped {
			continue
		}
		for _, kind := range checks[i].Produces {
			if !unproduced[kind] {
				out.Produced = append(out.Produced, kind)
			}
		}
	}
	slices.SortFunc(out.Failures, func(a, b CheckFailure) int { return strings.Compare(a.CheckID, b.CheckID) })
	slices.Sort(out.Skipped)
	slices.Sort(out.Produced)
	return out
}

func firstLine(s string) string {
	first, _, _ := strings.Cut(s, "\n")
	return first
}

func hintFor(checkID string) string {
	switch checkID {
	case admission.ProducerGolangci:
		return "run `goharness doctor` to inspect golangci-lint discovery and the pinned version"
	case admission.ProducerVulnScan:
		return "run `goharness setup` to provision the vulnerability database snapshot"
	case admission.ProducerMutation:
		return "add a test that exercises the changed functions"
	case admission.ProducerBenchmark:
		return "add a Benchmark function to the changed package"
	default:
		return ""
	}
}

// Blocking reports whether one piece of evidence can fail its claim.
func Blocking(e evidence.Evidence) bool {
	if e.Classification != evidence.ClassificationRequired {
		return false
	}
	switch e.State {
	case evidence.StateFixed:
		return false
	case evidence.StatePreexisting:
		return policy.IsUngrandfatherable(e.RuleID)
	default:
		return true
	}
}

// Options configures one verification run.
type Options struct {
	Mode         Mode
	Dir          string
	Base         string
	ContractPath string
	Now          time.Time
	Limit        int64
	Timeout      time.Duration
	Logger       *zap.Logger
	Progress     func(ProgressEvent)
	// PlanOnly stops the run once the obligation set is known, which is what
	// --explain-plan needs: the plan without paying for the evidence.
	PlanOnly bool
}

// Result is everything a report renderer needs.
type Result struct {
	Decision     admission.AdmissionDecision
	Mode         Mode
	Repository   repo.Repository
	Change       change.ChangeSet
	Contract     admission.TaskContract
	Risks        admission.RiskProfile
	Plan         admission.VerificationPlan
	Execution    ExecutionPlan
	Evidence     []evidence.Evidence
	Failures     []CheckFailure
	Skipped      []string
	Unproducible []admission.Unproducible
	Golangci     tool.Golangci
	VulnDB       *toolcache.VulnDBManifest
	PolicyPacks  []string
	BaseCompared bool
	Interrupted  bool
	TimedOut     bool
	Duration     time.Duration
	CheckTimings map[string]time.Duration
}

// ErrNotAModule is returned when verification is started outside a Go module.
var ErrNotAModule = repo.ErrNoModule

// Run executes the full pipeline for one mode and returns the admission
// decision.
func Run(ctx context.Context, version string, opts Options) (result Result, err error) {
	started := time.Now()
	runCtx, cancelTimeout := applyTimeout(ctx, opts)
	defer cancelTimeout()

	setup, err := prepare(runCtx, version, opts)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if rmErr := os.RemoveAll(setup.configDir); rmErr != nil && err == nil {
			err = fmt.Errorf("removing temporary config directory: %w", rmErr)
		}
	}()
	result = setup.result

	run, err := setup.engine.execute(runCtx, executeInput{
		repository: setup.repository, change: setup.change, contract: setup.contract,
		mode: opts.Mode, config: setup.config, result: &result, planOnly: opts.PlanOnly,
	})
	if err != nil {
		if interrupted(ctx, runCtx, err) {
			return interruptedResult(result, ctx, runCtx, started), nil
		}
		return Result{}, err
	}
	if setup.discoveryFailure != nil {
		run.Failures = append([]CheckFailure{*setup.discoveryFailure},
			filterOut(run.Failures, admission.ProducerGolangci)...)
		run.Unproducible = append(run.Unproducible,
			golangciUnproducible(setup.discoveryFailure.Reason)...)
	}

	result.Evidence = run.Evidence
	result.Failures = run.Failures
	result.Skipped = run.Skipped
	result.Unproducible = run.Unproducible
	result.CheckTimings = run.Timings
	result.Golangci = setup.engine.Golangci
	result.VulnDB = run.VulnDB

	setup.engine.applyWorktreeGuard(runCtx, setup.repository, setup.before, &run, &result)
	result.Decision = decideRun(result, run, opts.Mode)
	result.Duration = time.Since(started)
	return result, nil
}

func decideRun(result Result, run runOutput, mode Mode) admission.AdmissionDecision {
	claims := admission.EvaluateClaims(admission.ClaimInput{
		Plan:         result.Plan,
		Evidence:     result.Evidence,
		Produced:     run.Produced,
		Unproducible: run.Unproducible,
		Blocking:     Blocking,
	})
	verdict := admission.Decide(claims)
	return admission.AdmissionDecision{
		Verdict:                 verdict,
		Claims:                  claims,
		UnmetObligations:        admission.UnmetObligations(result.Plan, claims),
		SufficientForCompletion: mode.IsAdmissionGate() && verdict == admission.VerdictAdmitted,
		Reason:                  admission.DecisionReason(verdict, claims),
	}
}

// runSetup is everything Run resolves before any check executes.
type runSetup struct {
	engine           *Engine
	repository       repo.Repository
	change           change.ChangeSet
	contract         admission.TaskContract
	config           policy.Config
	before           repo.Snapshot
	configDir        string
	discoveryFailure *CheckFailure
	result           Result
}

func prepare(ctx context.Context, version string, opts Options) (runSetup, error) {
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	runner := tool.ExecRunner{}
	git := repo.ExecGit{Runner: runner}

	r, err := repo.Discover(ctx, git, opts.Dir)
	if err != nil {
		return runSetup{}, err
	}
	before, err := snapshotIfGit(ctx, git, r)
	if err != nil {
		return runSetup{}, err
	}
	cfg, err := loadProjectConfig(r.Root)
	if err != nil {
		return runSetup{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	resolved, err := policy.Resolve(cfg, now)
	if err != nil {
		return runSetup{}, err
	}
	contract, err := admission.LoadContract(opts.ContractPath, r.Root)
	if err != nil {
		return runSetup{}, err
	}
	base, origin, err := change.ResolveBase(ctx, git, r, opts.Base)
	if err != nil {
		return runSetup{}, err
	}
	cs, err := change.Build(ctx, git, r, base, origin)
	if err != nil {
		return runSetup{}, err
	}

	engine := &Engine{
		Runner: runner, Git: git, Logger: logger, Policy: resolved,
		Version: version, Concurrency: opts.Limit, ChangedEntries: cs.Entries,
		Progress: opts.Progress, phase: "head",
	}
	configDir, err := os.MkdirTemp("", "goharness-config-")
	if err != nil {
		return runSetup{}, fmt.Errorf("creating temporary config directory: %w", err)
	}
	engine.GolangciConfig, err = tool.WriteStrictConfig(configDir)
	if err != nil {
		return runSetup{}, errors.Join(err, os.RemoveAll(configDir))
	}

	return runSetup{
		engine: engine, repository: r, change: cs, contract: contract,
		config: cfg, before: before, configDir: configDir,
		discoveryFailure: engine.discoverGolangci(ctx, r.Root),
		result: Result{
			Mode: opts.Mode, Repository: r, Contract: contract,
			PolicyPacks: resolved.Packs(), Change: cs, Golangci: engine.Golangci,
		},
	}, nil
}

func applyTimeout(ctx context.Context, opts Options) (context.Context, context.CancelFunc) {
	if opts.Timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, opts.Timeout)
}

// interrupted reports whether an error is the run being cancelled or timing
// out rather than a genuine failure. Either way the answer is INCONCLUSIVE: an
// interrupted verification never claims safety.
func interrupted(parent, run context.Context, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return parent.Err() != nil || run.Err() != nil
}

func interruptedResult(result Result, parent, run context.Context, started time.Time) Result {
	reason, kind := "interrupted", "the run was cancelled before it could gather evidence"
	result.Interrupted = true
	if errors.Is(run.Err(), context.DeadlineExceeded) && parent.Err() == nil {
		reason, kind = "timed out", "the run exceeded its --timeout before it could gather evidence"
		result.Interrupted = false
		result.TimedOut = true
	}
	result.Failures = append(result.Failures, CheckFailure{
		CheckID: "lifecycle", Tool: "goharness", Reason: reason + ": " + kind,
		Hint: "rerun without interrupting, or raise --timeout",
	})
	result.Decision = admission.AdmissionDecision{
		Verdict: admission.VerdictInconclusive,
		Reason:  reason + " before every applicable claim had evidence",
	}
	result.Duration = time.Since(started)
	return result
}

func (e *Engine) discoverGolangci(ctx context.Context, root string) *CheckFailure {
	discovered, err := tool.DiscoverGolangci(root)
	if err == nil {
		discovered, err = discovered.ResolveVersion(ctx, e.Runner)
	}
	if err == nil && !discovered.MatchesPin() {
		err = fmt.Errorf("golangci-lint at %s reports version %q, but goharness pins %s exactly",
			discovered.Path, discovered.Version, tool.GolangciLintPin)
	}
	e.Golangci = discovered
	if err == nil {
		return nil
	}
	return &CheckFailure{
		CheckID: admission.ProducerGolangci, Tool: "golangci-lint",
		Reason: err.Error(), Hint: hintFor(admission.ProducerGolangci),
	}
}

func golangciUnproducible(reason string) []admission.Unproducible {
	kinds := []admission.EvidenceKind{
		admission.KindLintCorrectness, admission.KindLintReliability,
		admission.KindLintSecurity, admission.KindLintSimplicity,
		admission.KindLintOperability, admission.KindLintArchitecture,
		admission.KindLintReuse,
	}
	out := make([]admission.Unproducible, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, admission.Unproducible{
			Kind: kind, Reason: reason,
			Remedy: "install golangci-lint " + tool.GolangciLintPin + " or point GOHARNESS_GOLANGCI_LINT at it",
		})
	}
	return out
}

func (e *Engine) applyWorktreeGuard(ctx context.Context, r repo.Repository, before repo.Snapshot, run *runOutput, result *Result) {
	if !r.HasGit {
		run.Produced = append(run.Produced, admission.KindWorktreeReadOnly)
		return
	}
	after, err := repo.CaptureSnapshot(ctx, e.Git, r.Root)
	if err != nil {
		run.Unproducible = append(run.Unproducible, admission.Unproducible{
			Kind: admission.KindWorktreeReadOnly, Reason: "the worktree state could not be re-read: " + err.Error(),
		})
		result.Unproducible = run.Unproducible
		return
	}
	if before.Equal(after) {
		run.Produced = append(run.Produced, admission.KindWorktreeReadOnly)
		return
	}
	result.Failures = append(result.Failures, CheckFailure{
		CheckID: admission.ProducerWorktree, Tool: "git",
		Reason: "the worktree changed while verification was running:\n" + before.Diff(after),
		Hint:   "verification is read-only; a concurrent editor or a tool with side effects modified the tree",
	})
	run.Unproducible = append(run.Unproducible, admission.Unproducible{
		Kind:   admission.KindWorktreeReadOnly,
		Reason: "the worktree changed during the run, so the evidence describes a tree that no longer exists",
		Remedy: "stop editing while goharness runs, then verify again",
	})
	result.Unproducible = run.Unproducible
}

type executeInput struct {
	repository repo.Repository
	change     change.ChangeSet
	contract   admission.TaskContract
	mode       Mode
	config     policy.Config
	result     *Result
	planOnly   bool
}

func (e *Engine) execute(ctx context.Context, in executeInput) (runOutput, error) {
	repositoryWide := in.mode == ModeAudit || in.change.FullScope
	baseAvailable := in.mode == ModeVerify && in.change.HasBase() && in.repository.HasGit

	headTarget, execution, err := e.buildTarget(ctx, targetInput{
		root: in.repository.Root, modulePath: in.repository.ModulePath,
		change: in.change, mode: in.mode,
		contract: in.contract, config: in.config, repositoryWide: repositoryWide,
	})
	if err != nil {
		return runOutput{}, err
	}

	risks, err := admission.DetectRisks(ctx, admission.DetectionInput{
		Root:         in.repository.Root,
		ChangedFiles: in.change.GoFiles(),
		ScopeFiles:   headTarget.files,
		Contract:     in.contract,
		AllActive:    in.mode == ModeAudit,
	})
	if err != nil {
		return runOutput{}, err
	}
	plan := admission.BuildPlan(admission.PlanInput{
		Contract: in.contract, Risks: risks, BaseAvailable: baseAvailable,
		RepositoryWide: in.mode == ModeAudit,
	})
	headTarget.analyzeOpts = analyzeOptionsFor(risks, in.repository, in.config)
	headTarget.raceTests = risks.Has(admission.RiskConcurrency)
	headTarget.leakCheck = risks.Has(admission.RiskConcurrency)

	execution.Checks = headTarget.checksFor(plan.Checks)
	in.result.Risks = risks
	in.result.Plan = plan
	in.result.Execution = execution

	e.Logger.Info("plan built",
		zap.Int("packages", len(execution.Packages)),
		zap.Int("obligations", len(plan.Obligations)),
		zap.Int("checks", len(execution.Checks)))

	if in.planOnly {
		return runOutput{Timings: map[string]time.Duration{}}, nil
	}

	out, err := e.schedule(ctx, execution.Checks)
	if err != nil {
		return runOutput{}, err
	}
	out.Evidence = evidence.Finalize(decorate(e.Policy, out.Evidence))
	out.VulnDB = headTarget.vulnDB

	if !baseAvailable {
		return out, nil
	}
	if err := e.compareWithBase(ctx, in, headTarget, plan, &out); err != nil {
		return runOutput{}, err
	}
	return out, nil
}

func (e *Engine) compareWithBase(
	ctx context.Context, in executeInput, headTarget *target,
	plan admission.VerificationPlan, out *runOutput,
) (err error) {
	wt, err := repo.AddBaseWorktree(ctx, e.Git, in.repository.Root, in.change.Base)
	if err != nil {
		return err
	}
	defer func() {
		if rmErr := wt.Remove(ctx); rmErr != nil && err == nil {
			err = rmErr
		}
	}()

	baseChange := change.ChangeSet{FullScope: true, BaseOrigin: change.BaseUnavailable}
	baseTarget, basePlan, err := e.buildTarget(ctx, targetInput{
		root: wt.Dir, modulePath: in.repository.ModulePath,
		change: baseChange, mode: in.mode, contract: in.contract,
		config: in.config, restrict: &scopeRestriction{
			lint: headTarget.packages, tests: headTarget.testPackages,
		},
		isBase: true,
	})
	if err != nil {
		return err
	}
	baseTarget.analyzeOpts = headTarget.analyzeOpts
	basePlan.Checks = baseTarget.checksFor(plan.Checks)

	e.phase = "base"
	baseRun, err := e.schedule(ctx, basePlan.Checks)
	if err != nil {
		return err
	}
	if len(baseRun.Failures) > 0 {
		out.Failures = append(out.Failures, baseRun.Failures...)
		out.Unproducible = append(out.Unproducible, baseRun.Unproducible...)
		return nil
	}
	baseEvidence := evidence.Finalize(decorate(e.Policy, baseRun.Evidence))
	cmp := evidence.Compare(baseEvidence, out.Evidence)
	merged := slices.Concat(cmp.New, cmp.Preexisting, cmp.Fixed)
	evidence.SortPresentation(merged)
	out.Evidence = merged
	in.result.BaseCompared = true

	e.phase = "comparison"
	comparator := &comparison{engine: e, head: headTarget, base: baseTarget}
	comparisonRun, err := e.schedule(ctx, comparator.checksFor(plan.Checks))
	if err != nil {
		return err
	}
	comparisonRun.Evidence = evidence.Finalize(decorate(e.Policy, comparisonRun.Evidence))
	out.merge(comparisonRun)
	evidence.SortPresentation(out.Evidence)
	return nil
}

func analyzeOptionsFor(risks admission.RiskProfile, r repo.Repository, cfg policy.Config) analyze.Options {
	rules := make([]analyze.ImportRule, 0, len(cfg.Architecture))
	for _, rule := range cfg.Architecture {
		rules = append(rules, analyze.ImportRule{From: rule.From, Deny: rule.Deny, Reason: rule.Reason})
	}
	return analyze.Options{
		Concurrency: risks.Has(admission.RiskConcurrency),
		Network:     risks.Has(admission.RiskNetwork),
		Persistence: risks.Has(admission.RiskPersistence),
		Architecture: analyze.ArchitectureRules{
			ModulePath: r.ModulePath, ForbiddenImports: rules,
		},
	}
}

func filterOut(failures []CheckFailure, checkID string) []CheckFailure {
	out := make([]CheckFailure, 0, len(failures))
	for _, f := range failures {
		if f.CheckID != checkID {
			out = append(out, f)
		}
	}
	return out
}

func snapshotIfGit(ctx context.Context, git repo.Git, r repo.Repository) (repo.Snapshot, error) {
	if !r.HasGit {
		return repo.Snapshot{}, nil
	}
	return repo.CaptureSnapshot(ctx, git, r.Root)
}

func loadProjectConfig(root string) (policy.Config, error) {
	data, err := os.ReadFile(filepath.Join(root, "goharness.yaml"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return policy.Config{}, nil
		}
		return policy.Config{}, fmt.Errorf("reading goharness.yaml: %w", err)
	}
	return policy.ParseConfig(data)
}

func decorate(p policy.ResolvedPolicy, items []evidence.Evidence) []evidence.Evidence {
	out := make([]evidence.Evidence, 0, len(items))
	for _, e := range items {
		if e.Classification == "" {
			e = p.Decorate(e)
		}
		out = append(out, e)
	}
	return out
}

// scopeRestriction mirrors the head scope onto the base worktree so both sides
// of the comparison examine the same packages.
type scopeRestriction struct {
	lint  []string
	tests []string
}

type targetInput struct {
	root           string
	modulePath     string
	change         change.ChangeSet
	mode           Mode
	contract       admission.TaskContract
	config         policy.Config
	repositoryWide bool
	restrict       *scopeRestriction
	isBase         bool
}

func (e *Engine) buildTarget(ctx context.Context, in targetInput) (*target, ExecutionPlan, error) {
	graph, err := change.LoadGraph(ctx, in.root)
	if err != nil {
		return nil, ExecutionPlan{}, err
	}
	lintScope, testScope := scopeFor(in.mode)

	var lintPkgs, testPkgs []string
	switch {
	case in.restrict != nil:
		lintPkgs = graph.PatternsFor(in.restrict.lint)
		testPkgs = graph.PatternsFor(in.restrict.tests)
	case in.mode == ModeAudit || in.change.FullScope:
		lintPkgs = graph.Packages()
		testPkgs = graph.Packages()
	default:
		seeds := graph.SeedPackages(in.change.GoFiles())
		lintPkgs = graph.Affected(seeds, lintScope)
		testPkgs = graph.Affected(seeds, testScope)
	}
	files, err := graph.FilesFor(lintPkgs)
	if err != nil {
		return nil, ExecutionPlan{}, err
	}

	t := &target{
		engine: e, root: in.root, modulePath: in.modulePath, graph: graph,
		packages: lintPkgs, testPackages: testPkgs, files: files,
		changed: in.change.GoFiles(), contract: in.contract, isBase: in.isBase,
	}
	plan := ExecutionPlan{
		Mode: in.mode, Packages: lintPkgs, Files: files, Tests: testPkgs,
	}
	return t, plan, nil
}
