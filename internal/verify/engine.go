package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

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
	Logger         *slog.Logger
	Policy         policy.ResolvedPolicy
	Golangci       tool.Golangci
	GolangciConfig string
	Version        string
	Concurrency    int64
	ChangedEntries []change.Entry
	// EmptyChange says the run had a base revision to diff against and the diff
	// held nothing, in this module or outside it: there is no change to admit.
	EmptyChange bool
	Progress    func(ProgressEvent)
	// ConfigDigest identifies the project configuration in force, so cached
	// evidence produced under a different policy is never reused.
	ConfigDigest string
	// GoVersion is the toolchain the go command in this module resolves to. It
	// decides which standard-library vulnerabilities apply, so it is recorded and
	// keyed rather than left to whatever the scanner would discover on its own.
	GoVersion string
	// GoVersionErr is why GoVersion is empty, kept because a check that cannot
	// run has to say what stopped it rather than report an absence.
	GoVersionErr error
	// ToolchainFloor is the module's go.mod toolchain directive, empty when it
	// names none.
	ToolchainFloor string
	// NoCache recomputes the base snapshot even when a cached one matches.
	NoCache bool
	// Debt is the acknowledged-debt ledger committed at HEAD, and is nil in every
	// mode but audit. Verify performs a real base comparison and must never
	// consult a ledger: two mechanisms for the same question would let a change
	// pick whichever one suits it.
	Debt  *policy.DebtLedger
	phase string
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
	mutation     *MutationCoverage
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
	Mutation     *MutationCoverage
}

func (o *runOutput) merge(other runOutput) {
	o.Evidence = append(o.Evidence, other.Evidence...)
	o.Failures = append(o.Failures, other.Failures...)
	o.Skipped = append(o.Skipped, other.Skipped...)
	o.Produced = append(o.Produced, other.Produced...)
	o.Unproducible = append(o.Unproducible, other.Unproducible...)
	if other.Mutation != nil {
		o.Mutation = other.Mutation
	}
	if o.Timings == nil {
		o.Timings = map[string]time.Duration{}
	}
	maps.Copy(o.Timings, other.Timings)
}

// schedule runs the checks respecting their dependencies, with independent
// checks running concurrently under a semaphore bounded by GOMAXPROCS. Each
// goroutine writes only its own slot and returns before Wait completes, so its
// lifetime is visible here; the coordinator owns all aggregation.
//
// Every check acquires weight 1, and that is a measurement rather than an
// oversight. Charging the core-saturating subprocesses (build, vet, test,
// golangci-lint, the vulnerability scan) half the limit each, so that at most
// two of them overlap, was tried against a forty-package module and made an
// audit 14% slower and a verify 16% slower. None of those tools is parallel
// enough to fill the machine on its own, so overlapping their serial phases
// beats protecting them from each other. Change this only with numbers.
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

// harnessError marks a check failure as a defect in goharness rather than in
// the tool the check drives.
//
// Without it the report attributes the failure to whatever the check normally
// runs, and a reader who trusts that attribution goes looking for a problem in
// their toolchain, or worse, in their code. A tool fault is never a fact about
// the repository, and it is not a fact about the repository's tools either.
type harnessError struct{ err error }

func (f harnessError) Error() string { return f.err.Error() }

func (f harnessError) Unwrap() error { return f.err }

// maxNamedPaths keeps a hygiene fault readable when a producer got every path
// wrong, which is how this fault actually presents itself.
const maxNamedPaths = 3

// pathHygiene refuses to fingerprint evidence whose file is not a
// module-relative path inside the tree that produced it.
//
// A path that escaped its tree, an absolute one above all, spells a fingerprint
// the other revision can never equal. Every finding the producer made then reads
// as introduced by the change, and the change is rejected for debt it did not
// write: a production monorepo lost go vet and go fix to exactly this, 81 rows
// blamed on lines that predated the branch. It is a fault in goharness and not a
// fact about the repository, so it leaves through the channel that says so and
// the obligations this check was carrying go unproducible rather than passing on
// evidence nobody should trust.
func pathHygiene(checkID string, items []evidence.Evidence) error {
	var named []string
	count := 0
	for _, e := range items {
		if e.File == "" || !escapesTree(e.File) {
			continue
		}
		count++
		if len(named) < maxNamedPaths {
			named = append(named, e.RuleID+" at "+e.File)
		}
	}
	if count == 0 {
		return nil
	}
	return harnessError{err: fmt.Errorf(
		"%s reported %d finding(s) by a path outside the tree it examined, so they "+
			"cannot be compared against the other revision: %s",
		checkID, count, strings.Join(named, "; "))}
}

// escapesTree reports a file path that is not module-relative.
func escapesTree(file string) bool {
	return filepath.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../")
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
		e.Logger.LogAttrs(ctx, slog.LevelInfo, "check finished",
			slog.String("check", check.ID),
			slog.Duration("elapsed", outcome.elapsed),
			slog.Bool("failed", outcome.failure != nil))
	}()

	e.Logger.LogAttrs(ctx, slog.LevelInfo, "check started", slog.String("check", check.ID))
	result, err := check.run(ctx)
	if err == nil {
		err = pathHygiene(check.ID, result.evidence)
	}
	outcome.evidence = result.evidence
	outcome.unproducible = result.unproducible
	outcome.mutation = result.mutation
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
			who := attribute(o.tool, o.id, o.failure)
			out.Failures = append(out.Failures, CheckFailure{
				CheckID: o.id, Tool: who.tool, Reason: who.detail, Hint: who.remedy,
			})
			for _, kind := range checks[i].Produces {
				unproduced[kind] = true
				out.Unproducible = append(out.Unproducible, admission.Unproducible{
					Kind: kind, Reason: who.reason, Remedy: who.remedy,
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
			if o.mutation != nil {
				out.Mutation = o.mutation
			}
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

// blame is who a failed check is attributed to and what a reader is told.
type blame struct {
	tool   string
	reason string
	detail string
	remedy string
}

// attribute names who failed and phrases the gap the failure leaves.
//
// A reason is the sentence a reader acts on, so it has to say which side the
// fault fell on. Anything else would let a harness defect read as a defect in
// the repository, which is how an audit sends its operator hunting for a
// build-constraint problem that does not exist.
//
// A run that outlived its own --timeout, or was interrupted, is the run's
// fault and nobody else's. Reporting "go test -race: context deadline
// exceeded" as a tool failure with no hint sent two releases' worth of CI
// reports to a reader with nothing to act on; the deadline is goharness's.
func attribute(checkTool, checkID string, failure error) blame {
	var fault harnessError
	switch {
	case errors.Is(failure, context.DeadlineExceeded):
		reason := "the run's --timeout expired while " + checkID + " was still running, so it produced no answer"
		return blame{
			tool: "goharness", reason: reason, detail: reason,
			remedy: "rerun with a larger --timeout, or narrow the change",
		}
	case errors.Is(failure, context.Canceled):
		reason := "the run was interrupted while " + checkID + " was still running, so it produced no answer"
		return blame{
			tool: "goharness", reason: reason, detail: reason,
			remedy: "rerun without interrupting",
		}
	case errors.As(failure, &fault):
		return blame{
			tool: "goharness",
			reason: "goharness itself failed while producing this evidence, so the " +
				"repository was not judged on it; see failures[] for the fault: " + firstLine(failure.Error()),
			detail: failure.Error(), remedy: hintFor(checkID),
		}
	default:
		return blame{
			tool: checkTool, reason: checkID + " failed: " + firstLine(failure.Error()),
			detail: failure.Error(), remedy: hintFor(checkID),
		}
	}
}

func hintFor(checkID string) string {
	switch checkID {
	case admission.ProducerGolangci:
		return "run `goharness doctor` to inspect golangci-lint discovery and the pinned version"
	case admission.ProducerVulnScan:
		return "run `goharness setup` to provision the vulnerability database snapshot"
	case admission.ProducerGoFix:
		return "run `go tool fix help` to see the analyzers the installed toolchain registers"
	case admission.ProducerVisibility:
		return "this is a fault in goharness, not a defect in the repository; " +
			"report it with the paths above and the module's location inside the repository"
	case admission.ProducerMutation:
		return "add a test that exercises the changed functions"
	case admission.ProducerBenchmark:
		return "the benchmark run failed before it measured anything; the reason above is its output, " +
			"and `go test -run '^$' -bench . ` on the changed packages reproduces it"
	default:
		return ""
	}
}

// Blocking reports whether one finding stops admission.
//
// A required finding blocks unless the base revision already had it. The
// ungrandfatherable core, inline suppressions above all, blocks on a
// pre-existing finding too, but only on a line this change wrote: one it
// leaves as it found it, in a file it edits, is the repository's debt,
// reported beside the change and rejected by an audit, where no ledger may
// acknowledge it. Enforcing the core across every file a change opens made
// a legacy monorepo unable to admit anything, and the author of a change
// could neither fix a directive they did not write nor except it, because
// the exception is a policy edit no change may grant itself.
//
// Nothing about the anti-laundering property moves: a suppression the change
// adds is new and blocks wherever it is, one it rewrites or moves sits on an
// added line and blocks, and one the run could not place is the change's.
func Blocking(e evidence.Evidence) bool {
	if e.Classification != evidence.ClassificationRequired {
		return false
	}
	switch e.State {
	case evidence.StateFixed:
		return false
	case evidence.StatePreexisting:
		return policy.IsUngrandfatherable(e.RuleID) && e.Origin.WrittenByChange()
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
	Logger       *slog.Logger
	Progress     func(ProgressEvent)
	// PlanOnly stops the run once the obligation set is known, which is what
	// --explain-plan needs: the plan without paying for the evidence.
	PlanOnly bool
	// NoCache recomputes the base snapshot from scratch. A run with it must
	// reach the same verdict as one without; that is what makes the cache
	// trustworthy rather than merely fast.
	NoCache bool
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
	// GoVersion is the toolchain that produced this run's evidence, which for the
	// security claim is the standard library that was actually judged.
	GoVersion   string
	PolicyPacks []string
	// GeneratedExempt names the in-scope files this run did not judge because
	// they carry a generated header and the change leaves them alone. An ADMITTED
	// whose scope is invisible is not auditable, so what was skipped is reported
	// rather than merely applied.
	GeneratedExempt []string
	// LeakBlockedPackages names the test packages where goroutine-leak
	// verification could not be injected because a TestMain already exists.
	LeakBlockedPackages []string
	// Mutation is what the mutation check measured, nil when it did not run.
	Mutation *MutationCoverage
	// BaseTestPackages names the test packages the base revision ran, which are
	// exactly the ones whose head evidence a base result can reclassify, and
	// empty when head's suite passed. A base that ran less than head has to say
	// so, or the comparison cannot be audited.
	BaseTestPackages []string
	// Debt is the acknowledged-debt ledger this audit was judged against, nil
	// when there was none and in every mode but audit.
	Debt *policy.DebtLedger
	// PolicyShadow describes what the repository's own lint configuration hides
	// from itself. It is a report section and never a claim: a configuration is
	// not a defect in the code, and a gate that rejected a change over someone's
	// .golangci.yml would be overreach. Nil outside audit and where no
	// configuration was found.
	PolicyShadow *PolicyShadow
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
	// A deadline that expires while the checks are running is absorbed by the
	// scheduler as per-check failures, so the run returns normally with what it
	// had gathered. The result still has to say that the clock, not a tool,
	// ended it.
	if runCtx.Err() != nil {
		result.TimedOut = ctx.Err() == nil && errors.Is(runCtx.Err(), context.DeadlineExceeded)
		result.Interrupted = !result.TimedOut
	}

	result.Evidence = run.Evidence
	result.Failures = run.Failures
	result.Skipped = run.Skipped
	result.Unproducible = run.Unproducible
	result.CheckTimings = run.Timings
	result.Golangci = setup.engine.Golangci
	result.VulnDB = run.VulnDB

	if opts.Mode == ModeAudit {
		result.PolicyShadow = detectPolicyShadow(setup.repository.Root, result.Evidence)
	}

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
		logger = slog.New(slog.DiscardHandler)
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
	cfg, configDigest, err := loadProjectConfig(r.Root)
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
	base, origin, err := change.ResolveBase(ctx, git, r, opts.Base)
	if err != nil {
		return runSetup{}, err
	}
	cs, err := change.Build(ctx, git, r, base, origin)
	if err != nil {
		return runSetup{}, err
	}
	if cs.Added, err = change.Hunks(ctx, git, r, base); err != nil {
		return runSetup{}, err
	}
	contract, err := resolveContract(ctx, git, r, base, opts.ContractPath)
	if err != nil {
		return runSetup{}, err
	}
	// Loading the ledger only in audit is what holds "verify ignores the ledger":
	// the mode is consulted once, here, rather than at every place a state is
	// decided. A ledger that will not parse ends the run, the same answer a
	// malformed policy file gets, because a document that decides what stops
	// blocking must never be read on a guess.
	var ledger *policy.DebtLedger
	if opts.Mode == ModeAudit {
		if ledger, err = ledgerAt(ctx, git, r, r.Head); err != nil {
			return runSetup{}, err
		}
	}

	engine := &Engine{
		Runner: runner, Git: git, Logger: logger, Policy: resolved,
		Version: version, Concurrency: opts.Limit, ChangedEntries: cs.Entries,
		EmptyChange: opts.Mode != ModeAudit && !cs.FullScope &&
			len(cs.Entries) == 0 && len(cs.OutsideModule) == 0,
		Progress: opts.Progress, ConfigDigest: configDigest,
		NoCache: opts.NoCache, Debt: ledger, phase: "head",
	}
	// A failure here is not fatal: the checks that need it report it as an
	// obligation they could not discharge, which is more useful than refusing to
	// run at all. The error travels with the gap so the report can name a cause.
	engine.GoVersion, engine.GoVersionErr = tool.ResolveGoVersion(ctx, runner, r.Root)
	engine.ToolchainFloor = r.ToolchainDirective
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
			GoVersion: engine.GoVersion, Debt: ledger,
		},
	}, nil
}

// resolveContract merges the contract committed at the base revision with the
// one the working tree carries. Only the base copy can grant permissions: it
// predates the change under verification, so the change cannot have written it.
func resolveContract(
	ctx context.Context, git repo.Git, r repo.Repository, base, explicitPath string,
) (_ admission.TaskContract, err error) {
	tree, err := os.OpenRoot(r.Root)
	if err != nil {
		return admission.TaskContract{}, fmt.Errorf("opening %s: %w", r.Root, err)
	}
	defer func() { err = errors.Join(err, tree.Close()) }()
	head, err := admission.LoadContract(explicitPath, tree.FS())
	if err != nil {
		return admission.TaskContract{}, err
	}
	committed, err := contractAt(ctx, git, r, base)
	if err != nil {
		return admission.TaskContract{}, err
	}
	return admission.Merge(committed, head), nil
}

// contractAt reads the task contract as it stands at one revision.
func contractAt(ctx context.Context, git repo.Git, r repo.Repository, rev string) (admission.TaskContract, error) {
	src, found, err := fileAt(ctx, git, r, rev, admission.ContractFileName)
	if err != nil || !found {
		return admission.TaskContract{Source: admission.ContractFromDefault}, err
	}
	return admission.ParseContract([]byte(src), admission.ContractFromBase)
}

// ledgerAt reads the acknowledged-debt ledger as it stands at one revision.
//
// The revision is the whole point. A ledger in the working tree is something
// the change under judgement could have written for itself, so only the
// committed copy counts, exactly as with the task contract. Editing the file is
// itself a policy edit and is reported as one.
func ledgerAt(ctx context.Context, git repo.Git, r repo.Repository, rev string) (*policy.DebtLedger, error) {
	src, found, err := fileAt(ctx, git, r, rev, policy.DebtFileName)
	if err != nil || !found {
		return nil, err
	}
	ledger, err := policy.ParseDebtLedger([]byte(src))
	if err != nil {
		return nil, fmt.Errorf("reading %s at %s: %w", policy.DebtFileName, rev, err)
	}
	return &ledger, nil
}

// fileAt reads one module-root file as it stands at a revision. Absence is
// looked up before the read so that a revision carrying no such file, which is
// the common case, stays distinguishable from a git that will not answer. Both
// queries run at the module root, so the file is found where the module keeps
// it however deep below the repository root that is.
func fileAt(
	ctx context.Context, git repo.Git, r repo.Repository, rev, name string,
) (src string, found bool, err error) {
	if rev == "" || !r.HasGit {
		return "", false, nil
	}
	listed, err := git.Run(ctx, r.Root, "ls-tree", "--name-only", rev, "--", name)
	if err != nil {
		return "", false, fmt.Errorf("looking for %s at %s: %w", name, rev, err)
	}
	if strings.TrimSpace(listed) == "" {
		return "", false, nil
	}
	src, err = git.Run(ctx, r.Root, "show", rev+":./"+name)
	if err != nil {
		return "", false, fmt.Errorf("reading %s at %s: %w", name, rev, err)
	}
	return src, true, nil
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
	// The parent context says why it was cancelled: os/signal names the signal
	// in the cause, and a reader deciding whether a CI runner was preempted or
	// a person pressed Ctrl+C deserves that word rather than "cancelled".
	if cause := context.Cause(parent); cause != nil && !errors.Is(cause, context.Canceled) {
		kind = "the run was stopped by " + cause.Error() + " before it could gather evidence"
	}
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
			Remedy: "run `goharness setup` to provision the pinned, checksum-verified golangci-lint",
		})
	}
	return out
}

// applyWorktreeGuard re-reads the worktree after the run and reports any
// difference. It runs on a context detached from the run's, like every
// cleanup: a run that hit its deadline still has to state the true worktree
// state, and asking git on an expired context reported "could not be re-read"
// as a policy-integrity gap the repository did not have.
func (e *Engine) applyWorktreeGuard(ctx context.Context, r repo.Repository, before repo.Snapshot, run *runOutput, result *Result) {
	if !r.HasGit {
		run.Produced = append(run.Produced, admission.KindWorktreeReadOnly)
		return
	}
	guardCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), repo.CleanupTimeout)
	defer cancel()
	after, err := repo.CaptureSnapshot(guardCtx, e.Git, r.Root)
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

func (e *Engine) execute(ctx context.Context, in executeInput) (_ runOutput, err error) {
	repositoryWide := in.mode == ModeAudit || in.change.FullScope
	baseAvailable := in.mode == ModeVerify && in.change.HasBase() && in.repository.HasGit

	headTarget, execution, err := e.buildTarget(ctx, targetInput{
		root: in.repository.Root, modulePath: in.repository.ModulePath,
		change: in.change, mode: in.mode,
		contract: in.contract, config: in.config, repositoryWide: repositoryWide,
		narrow: baseAvailable,
	})
	if err != nil {
		return runOutput{}, err
	}
	defer func() { err = errors.Join(err, headTarget.close()) }()

	risks, err := admission.DetectRisks(ctx, admission.DetectionInput{
		Tree:         headTarget.tree.FS(),
		ChangedFiles: in.change.Files, // every file: a migration or a go.mod edit activates a domain by its path
		ScopeFiles:   headTarget.files,
		Contract:     in.contract,
		AllActive:    in.mode == ModeAudit,
	})
	if err != nil {
		return runOutput{}, err
	}
	plan := admission.BuildPlan(admission.PlanInput{
		Contract: in.contract, Risks: risks, BaseAvailable: baseAvailable,
		HasDiff: !in.change.FullScope, RepositoryWide: in.mode == ModeAudit,
	})
	headTarget.analyzeOpts = analyzeOptionsFor(risks, in.repository, in.config)
	headTarget.raceTests = risks.Has(admission.RiskConcurrency)
	headTarget.leakCheck = risks.Has(admission.RiskConcurrency)

	execution.Checks = headTarget.checksFor(plan.Checks)
	in.result.Risks = risks
	in.result.Plan = plan
	in.result.Execution = execution
	in.result.GeneratedExempt = slices.Sorted(maps.Keys(headTarget.exemptFiles))

	e.Logger.LogAttrs(ctx, slog.LevelInfo, "plan built",
		slog.Int("packages", len(execution.Packages)),
		slog.Int("obligations", len(plan.Obligations)),
		slog.Int("checks", len(execution.Checks)))

	if in.planOnly {
		return runOutput{Timings: map[string]time.Duration{}}, nil
	}

	if err := headTarget.prepare(ctx); err != nil {
		return runOutput{}, err
	}
	out, err := e.schedule(ctx, execution.Checks)
	if err != nil {
		return runOutput{}, err
	}
	out.Evidence = evidence.Finalize(decorate(e.Policy, out.Evidence))
	out.Evidence = applyDebtLedger(e.Debt, out.Evidence)
	out.VulnDB = headTarget.vulnDB
	// Read after schedule returns, so the only goroutine that could have written
	// it has finished; the same discipline the vulnerability snapshot follows.
	in.result.LeakBlockedPackages = headTarget.leakBlocked

	if baseAvailable {
		if err := e.compareWithBase(ctx, in, headTarget, plan, &out); err != nil {
			return runOutput{}, err
		}
	}
	// Last, because this is the only point where the evidence set is complete on
	// both paths: the comparison merges its own producers into it.
	//
	// A repository-wide run places nothing. An audit answers for the repository
	// rather than for the commit it happens to sit on, and attributing its
	// findings to that commit's diff would let a rule that blocks while
	// pre-existing stop blocking everywhere the last commit did not reach, which
	// is precisely what the un-baselineable core exists to prevent.
	if !repositoryWide {
		out.Evidence = headTarget.attributeOrigin(in.change, out.Evidence)
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
	baseTests, baseTestsRenamedFrom := baseTestScope(out.Evidence, in.change, headTarget)
	// A worktree materializes the whole repository, so the module sits at the
	// same prefix below it that it occupies below the git root. Taking the
	// worktree root as the module root builds every base check outside the
	// module, where there is no go.mod and nothing resolves.
	baseRoot := filepath.Join(wt.Dir, filepath.FromSlash(in.repository.ModulePrefix))
	baseTarget, basePlan, err := e.buildTarget(ctx, targetInput{
		root: baseRoot, modulePath: in.repository.ModulePath,
		change: baseChange, mode: in.mode, contract: in.contract,
		config: in.config, restrict: &scopeRestriction{
			lint: headTarget.packages, tests: baseTests,
			local: headTarget.localScope, moduleChanged: headTarget.moduleChanged,
			renamedFrom: renamedGoFiles(in.change), testsRenamedFrom: baseTestsRenamedFrom,
		},
		isBase: true,
	})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, baseTarget.close()) }()
	baseTarget.analyzeOpts = headTarget.analyzeOpts
	// The base runs its tests the way head ran them, leak detector included:
	// a leak head found in a package the base also leaks in is pre-existing
	// debt, and it can only be recognised as such if the base looked for it.
	baseTarget.raceTests = headTarget.raceTests
	baseTarget.leakCheck = headTarget.leakCheck
	in.result.BaseTestPackages = baseTarget.testPackages
	basePlan.Checks = baseTarget.checksFor(plan.Checks)

	e.phase = "base"
	baseRun, err := e.baseRun(ctx, in.change.Base, baseTarget, basePlan.Checks)
	if err != nil {
		return err
	}
	if len(baseRun.Failures) > 0 {
		out.Failures = append(out.Failures, baseRun.Failures...)
		out.Unproducible = append(out.Unproducible, baseRun.Unproducible...)
		return nil
	}
	// Realigned first: the base tree names a moved file by the path it had there,
	// and comparing the two coordinate systems reports the move itself as a defect.
	baseEvidence := evidence.Realign(
		evidence.Finalize(decorate(e.Policy, baseRun.Evidence)), in.change.Renames())
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
	in.result.Mutation = comparisonRun.Mutation
	evidence.SortPresentation(out.Evidence)
	return nil
}

// baseTestScope names the test packages the base revision has to run.
//
// A base test result is consumed by exactly one thing: the comparison that
// decides whether a head test failure or goroutine leak already existed. A
// test that passes at head produces no row, so its base result cannot move a
// verdict, and a failure only the base had would be credit rather than a
// block. Running the whole closure at base therefore paid for the most
// expensive check in the run twice to learn nothing the verdict uses; on this
// repository the second race run was six minutes of thirteen, and the reason
// two releases failed their own gate on a ten-minute budget.
//
// The returned paths are head import paths. The second list names the base
// paths of moved Go files whose head package is among them, because a renamed
// package has no import path at base to mirror and would otherwise resolve to
// nothing there.
func baseTestScope(items []evidence.Evidence, cs change.ChangeSet, head *target) (pkgs, renamedFrom []string) {
	set := map[string]bool{}
	for _, e := range items {
		if e.Package == "" {
			continue
		}
		if e.RuleID == policy.RuleTestFailure || e.RuleID == policy.RuleGoroutineLeak {
			set[e.Package] = true
		}
	}
	for _, entry := range cs.Entries {
		if entry.OldPath == "" || !strings.HasSuffix(entry.Path, ".go") {
			continue
		}
		if pkg, ok := head.graph.PackageForFile(entry.Path); ok && set[pkg] {
			renamedFrom = append(renamedFrom, entry.OldPath)
		}
	}
	slices.Sort(renamedFrom)
	return slices.Sorted(maps.Keys(set)), renamedFrom
}

// baseRun produces the base snapshot's evidence, from the cache when one
// matches this exact revision, scope, policy and toolchain, and by running the
// checks otherwise.
func (e *Engine) baseRun(ctx context.Context, base string, t *target, checks []Check) (runOutput, error) {
	key := e.baseCacheKey(baseCacheInput{
		base:         base,
		packages:     t.packages,
		testPackages: t.testPackages,
		raceTests:    t.raceTests,
		leakCheck:    t.leakCheck,
		judged:       t.judged,
		exempt:       slices.Sorted(maps.Keys(t.exemptFiles)),
		checks:       checkIDs(checks),
		analyzeOpts:  describeAnalyzeOptions(t.analyzeOpts),
		configDigest: e.ConfigDigest,
	})
	if !e.NoCache {
		if cached, ok := e.readBaseSnapshot(key); ok {
			return cached, nil
		}
	}
	// After the cache lookup, so a reused snapshot never pays to parse a base
	// tree whose findings are already known.
	if err := t.prepare(ctx); err != nil {
		return runOutput{}, err
	}
	out, err := e.schedule(ctx, checks)
	if err != nil {
		return runOutput{}, err
	}
	if !e.NoCache && len(out.Failures) == 0 {
		e.writeBaseSnapshot(key, base, out)
	}
	return out, nil
}

func checkIDs(checks []Check) []string {
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		out = append(out, c.ID)
	}
	slices.Sort(out)
	return out
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

// loadProjectConfig reads the project policy and returns a digest of the exact
// bytes it was parsed from, which is what tells cached evidence apart from
// evidence produced under a policy that has since been edited.
func loadProjectConfig(root string) (_ policy.Config, _ string, err error) {
	tree, err := os.OpenRoot(root)
	if err != nil {
		return policy.Config{}, "", fmt.Errorf("opening %s: %w", root, err)
	}
	defer func() { err = errors.Join(err, tree.Close()) }()
	data, err := tree.ReadFile(policy.ConfigFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return policy.Config{}, "none", nil
		}
		return policy.Config{}, "", fmt.Errorf("reading %s: %w", policy.ConfigFileName, err)
	}
	cfg, err := policy.ParseConfig(data)
	if err != nil {
		return policy.Config{}, "", err
	}
	return cfg, toolcache.Sum(data), nil
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

// partitionGenerated splits the in-scope files into the ones this run judges
// and the generated ones it exempts.
//
// Generated code is exempt only while the change leaves it alone. A file the
// change wrote or rewrote is judged in full whatever its header says, because
// the marker is a claim the author controls: exempting it would turn three
// words of comment into a suppression for a whole file. The decision reads the
// head diff in both trees, so a regenerated file is examined at base and at
// head alike and its unchanged findings stay pre-existing debt.
func (e *Engine) partitionGenerated(tree fs.FS, files []string) (p generatedPartition, err error) {
	changed := make(map[string]bool, len(e.ChangedEntries))
	for _, entry := range e.ChangedEntries {
		if entry.Status != change.StatusDeleted {
			changed[entry.Path] = true
		}
	}
	p = generatedPartition{
		judged:    make([]string, 0, len(files)),
		exempt:    map[string]bool{},
		generated: map[string]bool{},
	}
	for _, rel := range files {
		generated, genErr := analyze.IsGenerated(tree, rel)
		if genErr != nil {
			return generatedPartition{}, genErr
		}
		if generated {
			p.generated[rel] = true
		}
		if generated && !changed[rel] {
			p.exempt[rel] = true
			continue
		}
		p.judged = append(p.judged, rel)
	}
	return p, nil
}

// generatedPartition is how one tree's in-scope files divide.
//
// exempt and generated are deliberately different sets. exempt is what this run
// does not judge at all; generated is every file whose contents a tool wrote,
// including the ones the change regenerated and which are therefore judged in
// full. The second set exists because a comparison between two revisions of
// generated code cannot key functions by name: regenerating after a type is
// deleted renumbers every function after it, so the same name at base and head
// is two different functions and the delta between them measures the numbering.
type generatedPartition struct {
	judged    []string
	exempt    map[string]bool
	generated map[string]bool
}

// scopeRestriction mirrors the head scope onto the base worktree so both sides
// of the comparison examine the same packages.
type scopeRestriction struct {
	lint  []string
	tests []string
	// local and moduleChanged mirror the head run's directory-local narrowing.
	// Both sides have to narrow identically, or what the comparison measures is
	// the narrowing rather than the change.
	local         []string
	moduleChanged bool
	// renamedFrom names the base-side paths of the Go files the change moved.
	//
	// The rest of this restriction travels as import paths, and a package the
	// change renamed has none at base: mirroring head's paths onto the base tree
	// resolves a moved package to nothing, so the base scope comes out empty and
	// every finding in the moved code reads as introduced by the move. These paths
	// are resolved against the base graph, where they still exist.
	renamedFrom []string
	// testsRenamedFrom is the same repair for the test scope, which is narrower
	// than the lint scope (see baseTestScope) and so needs its own list: only
	// the moved files whose head package produced test evidence belong in it.
	testsRenamedFrom []string
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
	// narrow permits the directory-local checks to examine only the directories
	// the change touched. It holds only where a base comparison will happen,
	// because that is the whole justification: with nothing to compare against,
	// every finding is the change's to answer for and skipping a directory would
	// be skipping evidence.
	narrow bool
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
		lintPkgs = withPackages(graph.PatternsFor(in.restrict.lint), graph.SeedPackages(in.restrict.renamedFrom))
		testPkgs = withPackages(graph.PatternsFor(in.restrict.tests), graph.SeedPackages(in.restrict.testsRenamedFrom))
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
	tree, err := os.OpenRoot(in.root)
	if err != nil {
		return nil, ExecutionPlan{}, fmt.Errorf("opening %s: %w", in.root, err)
	}
	partition, err := e.partitionGenerated(tree.FS(), files)
	if err != nil {
		return nil, ExecutionPlan{}, errors.Join(err, tree.Close())
	}

	t := &target{
		engine: e, root: in.root, tree: tree, modulePath: in.modulePath, graph: graph,
		packages: lintPkgs, testPackages: testPkgs,
		files: files, judged: partition.judged, exemptFiles: partition.exempt,
		generatedFiles: partition.generated,
		changed:        in.change.GoFiles(), contract: in.contract, isBase: in.isBase,
	}
	t.localScope, t.moduleChanged = localScopeFor(in)
	plan := ExecutionPlan{
		Mode: in.mode, Packages: lintPkgs, Files: partition.judged, Tests: testPkgs,
		LocalScope: t.localScope,
	}
	return t, plan, nil
}

// withPackages merges two package path lists into one sorted set.
func withPackages(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	set := make(map[string]bool, len(base)+len(extra))
	for _, p := range slices.Concat(base, extra) {
		set[p] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// renamedGoFiles lists the base-side paths of the Go files the change moved.
func renamedGoFiles(cs change.ChangeSet) []string {
	var out []string
	for from := range cs.Renames() {
		if strings.HasSuffix(from, ".go") {
			out = append(out, from)
		}
	}
	slices.Sort(out)
	return out
}

// localScopeFor decides which package directories the directory-local checks
// examine, and nil when they must examine all of them.
//
// A package directory whose judged files are byte-identical at base and head
// produces identical findings at both from any check reading only that
// directory. Identical findings carry identical fingerprints, since occurrence
// indexes are keyed per rule, file and package rather than globally, so they
// pair in the comparison and can be neither new nor fixed. Skipping such a
// directory therefore removes pre-existing rows and nothing else, which is only
// worth having where a pre-existing row does not block: target.localFor holds
// that half of the condition and names the checks that may not narrow.
//
// The base side never decides this for itself. Two sides that narrowed
// independently would be comparing two different questions.
func localScopeFor(in targetInput) (dirs []string, moduleChanged bool) {
	if in.restrict != nil {
		return in.restrict.local, in.restrict.moduleChanged
	}
	if !in.narrow || in.repositoryWide || in.change.FullScope {
		return nil, false
	}
	set := map[string]bool{}
	for _, entry := range in.change.Entries {
		if !strings.HasSuffix(entry.Path, ".go") {
			continue
		}
		set[path.Dir(entry.Path)] = true
		// A move is two directories: the one the file left, which is why the base
		// tree has to be scanned there, and the one it arrived in. Narrowing to the
		// destination alone would leave the base side of a moved file unexamined and
		// hand every finding in it back as new, which is the defect this narrowing
		// sits next to rather than a second instance of it.
		if entry.OldPath != "" {
			set[path.Dir(entry.OldPath)] = true
		}
	}
	// A change with no Go file in it narrows to nothing, which is correct: no
	// directory-local check can have anything to say about it. The empty
	// non-nil slice is what carries that, since nil means no narrowing at all.
	return slices.Sorted(maps.Keys(set)), in.change.TouchesModuleFiles()
}
