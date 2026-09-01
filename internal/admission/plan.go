package admission

import (
	"slices"
	"strings"
)

// Producer names the check that satisfies an obligation. They are the stable
// identifiers the execution DAG is keyed by.
const (
	ProducerCompile      = "compile"
	ProducerGofmt        = "gofmt"
	ProducerGoimports    = "goimports"
	ProducerModTidy      = "modtidy"
	ProducerNative       = "native"
	ProducerVet          = "vet"
	ProducerGoFix        = "gofix"
	ProducerGolangci     = "golangci-lint"
	ProducerTest         = "test"
	ProducerRaceTest     = "race-test"
	ProducerVulnScan     = "vuln-scan"
	ProducerDependency   = "dependency-delta"
	ProducerMetrics      = "metrics"
	ProducerClone        = "clone-scan"
	ProducerScope        = "scope-scan"
	ProducerPolicyGuard  = "policy-guard"
	ProducerVisibility   = "change-visibility"
	ProducerMigration    = "migration-scan"
	ProducerWorktree     = "worktree-guard"
	ProducerAPICompat    = "api-compat"
	ProducerMaintainable = "maintainability-delta"
	ProducerAntiWeaken   = "anti-weakening"
	ProducerMutation     = "mutation"
	ProducerBenchmark    = "benchmark"
)

// PlannedCheck is one node of the execution DAG as data: the runnable closures
// live in the verify package, keyed by these IDs.
type PlannedCheck struct {
	ID        string         `json:"id"`
	Tool      string         `json:"tool"`
	DependsOn []string       `json:"dependsOn,omitempty"`
	Produces  []EvidenceKind `json:"produces"`
	NeedsBase bool           `json:"needsBase"`
}

// VerificationPlan is the closed set of obligations for one run, together with
// the checks that will discharge them.
type VerificationPlan struct {
	Contract    TaskContract
	Risks       RiskProfile
	Obligations []RequiredEvidence
	Checks      []PlannedCheck
	// BaseAvailable records whether a base revision exists. Obligations that
	// compare two snapshots are not merely unproduced without one: they have no
	// subject at all, and their claims are NOT_APPLICABLE rather than
	// INCONCLUSIVE.
	BaseAvailable bool
}

// PlanInput is what the planner needs beyond the contract and risk profile.
type PlanInput struct {
	Contract      TaskContract
	Risks         RiskProfile
	BaseAvailable bool
	// HasDiff records that the run has a real change set to reason about, as
	// opposed to a whole tree taken as the subject. Obligations about the change
	// itself have no subject without one.
	HasDiff        bool
	RepositoryWide bool
}

// BuildPlan turns a contract and a risk profile into the closed obligation set
// and the deterministic check DAG that discharges it.
func BuildPlan(in PlanInput) VerificationPlan {
	plan := VerificationPlan{
		Contract:      in.Contract,
		Risks:         in.Risks,
		BaseAvailable: in.BaseAvailable,
	}
	add := func(kind EvidenceKind, producer string, claim Dimension, because string) {
		plan.Obligations = append(plan.Obligations, RequiredEvidence{
			Kind: kind, Producer: producer, Claim: claim, Because: because,
		})
	}

	const always = "applies to every change"
	add(KindCompileClean, ProducerCompile, DimCorrectness, always)
	add(KindVetClean, ProducerVet, DimCorrectness, always)
	add(KindFixScan, ProducerGoFix, DimSimplicity, always)
	add(KindInlineMigration, ProducerGoFix, DimMaintainability, always)
	add(KindDialAddress, ProducerGoFix, DimReliability, always)
	// A -race run executes the same tests, so when concurrency risk activates
	// it the plain run would only repeat work. One producer discharges both
	// obligations rather than the suite running twice.
	testProducer := ProducerTest
	if in.Risks.Has(RiskConcurrency) {
		testProducer = ProducerRaceTest
	}
	add(KindTestsPass, testProducer, DimCorrectness, always)
	add(KindLintCorrectness, ProducerGolangci, DimCorrectness, always)
	add(KindLintSimplicity, ProducerGolangci, DimSimplicity, always)
	add(KindComplexityMetrics, ProducerMetrics, DimSimplicity, always)
	add(KindFormatClean, ProducerGofmt, DimMaintainability, always)
	add(KindModuleTidy, ProducerModTidy, DimArchitecture, always)
	add(KindLintArchitecture, ProducerGolangci, DimArchitecture, always)
	add(KindArchitectureScan, ProducerNative, DimArchitecture, always)
	add(KindLintReuse, ProducerGolangci, DimReuse, always)
	add(KindDuplicationScan, ProducerClone, DimReuse, always)
	add(KindLintReliability, ProducerGolangci, DimReliability, always)
	add(KindTestNatives, ProducerNative, DimTestEffectiveness, always)
	add(KindLintSecurity, ProducerGolangci, DimSecurity, always)
	add(KindLintOperability, ProducerGolangci, DimOperability, always)
	add(KindHygieneScan, ProducerNative, DimPolicyIntegrity, always)
	add(KindPolicyGuard, ProducerPolicyGuard, DimPolicyIntegrity, always)
	add(KindWorktreeReadOnly, ProducerWorktree, DimPolicyIntegrity, always)

	if in.HasDiff {
		add(KindChangeVisible, ProducerVisibility, DimCorrectness,
			"a change is only judged where the toolchain can see it")
	}
	if in.Contract.HasScope() {
		add(KindScopeConformance, ProducerScope, DimRequirements, "the contract declares a scope")
	}
	if in.BaseAvailable {
		add(KindMaintainDelta, ProducerMaintainable, DimMaintainability,
			"a base revision exists, so maintainability can be compared")
	}
	switch {
	case in.RepositoryWide:
		add(KindVulnerabilityScan, ProducerVulnScan, DimSecurity,
			"repository audit scans for known vulnerabilities")
	case in.Risks.Has(RiskDependency):
		// Reachability can also change without a dependency change, when new
		// code calls an already-vulnerable function; that is the audit's job.
		// The gate scans where the module set itself moved, because a bumped
		// or added requirement can bring a known vulnerability into the build
		// without a Go line changing, and no other check would notice.
		add(KindVulnerabilityScan, ProducerVulnScan, DimSecurity,
			"the change touches dependencies")
	}

	addRiskObligations(&plan, in, add)
	slices.SortStableFunc(plan.Obligations, func(a, b RequiredEvidence) int {
		if c := strings.Compare(string(a.Claim), string(b.Claim)); c != 0 {
			return c
		}
		return strings.Compare(string(a.Kind), string(b.Kind))
	})
	plan.Checks = checksFor(plan.Obligations)
	return plan
}

type addFunc func(kind EvidenceKind, producer string, claim Dimension, because string)

func addRiskObligations(plan *VerificationPlan, in PlanInput, add addFunc) {
	risks := in.Risks
	if risks.Has(RiskConcurrency) {
		add(KindRaceClean, ProducerRaceTest, DimConcurrencySafety, "the change touches concurrency")
		add(KindLeakClean, ProducerRaceTest, DimConcurrencySafety, "the change touches concurrency")
		add(KindGoroutineLifetime, ProducerNative, DimConcurrencySafety, "the change touches concurrency")
	}
	if risks.HasAny(RiskConcurrency, RiskNetwork) {
		add(KindBoundedResources, ProducerNative, DimBoundedResources,
			"the change touches concurrency or the network")
	}
	if risks.Has(RiskNetwork) {
		add(KindNetworkScan, ProducerNative, DimReliability, "the change touches the network")
	}
	if risks.Has(RiskPersistence) {
		add(KindTxPairing, ProducerNative, DimOperability, "the change touches persistence")
		add(KindMigrationOrder, ProducerMigration, DimOperability, "the change touches persistence")
	}
	if risks.Has(RiskPublicAPI) && in.BaseAvailable {
		add(KindAPICompat, ProducerAPICompat, DimArchitecture, "the change alters exported API")
	}
	if risks.Has(RiskTests) && in.BaseAvailable {
		add(KindAntiWeakening, ProducerAntiWeaken, DimTestEffectiveness, "the change edits tests")
		add(KindMutationSignal, ProducerMutation, DimTestEffectiveness, "the change edits tests")
	}
	if risks.Has(RiskHotPath) && in.BaseAvailable {
		add(KindBenchDelta, ProducerBenchmark, DimPerformance, "the change touches a benchmarked path")
		add(KindAllocDelta, ProducerBenchmark, DimPerformance, "the change touches a benchmarked path")
	}
	if risks.Has(RiskDependency) && in.BaseAvailable {
		add(KindDependencyDelta, ProducerDependency, DimArchitecture, "the change touches dependencies")
	}
}

func checksFor(obligations []RequiredEvidence) []PlannedCheck {
	produces := map[string][]EvidenceKind{}
	for _, o := range obligations {
		if !slices.Contains(produces[o.Producer], o.Kind) {
			produces[o.Producer] = append(produces[o.Producer], o.Kind)
		}
	}
	catalogue := map[string]PlannedCheck{
		ProducerCompile:      {ID: ProducerCompile, Tool: "go build"},
		ProducerGofmt:        {ID: ProducerGofmt, Tool: "gofmt"},
		ProducerGoimports:    {ID: ProducerGoimports, Tool: "goimports"},
		ProducerModTidy:      {ID: ProducerModTidy, Tool: "go mod tidy"},
		ProducerNative:       {ID: ProducerNative, Tool: "goharness"},
		ProducerMetrics:      {ID: ProducerMetrics, Tool: "goharness"},
		ProducerClone:        {ID: ProducerClone, Tool: "goharness"},
		ProducerScope:        {ID: ProducerScope, Tool: "goharness"},
		ProducerPolicyGuard:  {ID: ProducerPolicyGuard, Tool: "goharness"},
		ProducerVisibility:   {ID: ProducerVisibility, Tool: "go/build"},
		ProducerMigration:    {ID: ProducerMigration, Tool: "goharness"},
		ProducerDependency:   {ID: ProducerDependency, Tool: "goharness", NeedsBase: true},
		ProducerWorktree:     {ID: ProducerWorktree, Tool: "git"},
		ProducerVet:          {ID: ProducerVet, Tool: "go vet", DependsOn: []string{ProducerCompile}},
		ProducerGoFix:        {ID: ProducerGoFix, Tool: "go fix", DependsOn: []string{ProducerCompile}},
		ProducerGolangci:     {ID: ProducerGolangci, Tool: "golangci-lint", DependsOn: []string{ProducerCompile}},
		ProducerTest:         {ID: ProducerTest, Tool: "go test", DependsOn: []string{ProducerCompile}},
		ProducerRaceTest:     {ID: ProducerRaceTest, Tool: "go test -race", DependsOn: []string{ProducerCompile}},
		ProducerVulnScan:     {ID: ProducerVulnScan, Tool: "golang.org/x/vuln", DependsOn: []string{ProducerCompile}},
		ProducerAPICompat:    {ID: ProducerAPICompat, Tool: "go/types", NeedsBase: true},
		ProducerMaintainable: {ID: ProducerMaintainable, Tool: "goharness", NeedsBase: true},
		ProducerAntiWeaken:   {ID: ProducerAntiWeaken, Tool: "goharness", NeedsBase: true},
		ProducerMutation:     {ID: ProducerMutation, Tool: "go test -overlay", NeedsBase: true},
		ProducerBenchmark:    {ID: ProducerBenchmark, Tool: "go test -bench", NeedsBase: true},
	}

	checks := make([]PlannedCheck, 0, len(produces))
	for producer, kinds := range produces {
		check, ok := catalogue[producer]
		if !ok {
			continue
		}
		slices.Sort(kinds)
		check.Produces = kinds
		checks = append(checks, check)
	}
	// goimports has no obligation of its own; it shares the formatting claim
	// with gofmt and always runs alongside it.
	if _, ok := produces[ProducerGofmt]; ok {
		fmtCheck := catalogue[ProducerGoimports]
		fmtCheck.Produces = []EvidenceKind{KindFormatClean}
		checks = append(checks, fmtCheck)
	}
	slices.SortFunc(checks, func(a, b PlannedCheck) int { return strings.Compare(a.ID, b.ID) })
	return checks
}

// CheckIDs lists the planned check IDs in execution order.
func (p VerificationPlan) CheckIDs() []string {
	out := make([]string, 0, len(p.Checks))
	for _, c := range p.Checks {
		out = append(out, c.ID)
	}
	return out
}

// ObligationsFor returns the obligations belonging to one dimension.
func (p VerificationPlan) ObligationsFor(dim Dimension) []RequiredEvidence {
	var out []RequiredEvidence
	for _, o := range p.Obligations {
		if o.Claim == dim {
			out = append(out, o)
		}
	}
	return out
}

// AppliesTo reports whether any obligation activates a dimension.
func (p VerificationPlan) AppliesTo(dim Dimension) bool {
	return slices.ContainsFunc(p.Obligations, func(o RequiredEvidence) bool { return o.Claim == dim })
}
