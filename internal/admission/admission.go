// Package admission holds the claims-based admission model: the quality
// dimensions a change is judged on, the evidence obligations each dimension
// needs, the risk profile that decides which dimensions apply, and the decision
// rule that turns claims into a verdict.
//
// There is no aggregate score anywhere in this package. The verdict is a pure
// conjunction over claims, so a failure in one dimension can never be
// compensated by strength in another.
package admission

import (
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// Dimension is one axis a change is judged on.
type Dimension string

// The fourteen quality dimensions.
const (
	DimRequirements      Dimension = "requirements-compliance"
	DimCorrectness       Dimension = "correctness"
	DimSimplicity        Dimension = "simplicity"
	DimMaintainability   Dimension = "maintainability"
	DimArchitecture      Dimension = "architecture"
	DimReuse             Dimension = "appropriate-reuse"
	DimConcurrencySafety Dimension = "concurrency-safety"
	DimBoundedResources  Dimension = "bounded-resources"
	DimReliability       Dimension = "reliability"
	DimTestEffectiveness Dimension = "test-effectiveness"
	DimPerformance       Dimension = "performance"
	DimSecurity          Dimension = "security"
	DimOperability       Dimension = "operability"
	DimPolicyIntegrity   Dimension = "policy-integrity"
)

// Dimensions returns every dimension in report order.
func Dimensions() []Dimension {
	return []Dimension{
		DimRequirements, DimCorrectness, DimSimplicity, DimMaintainability,
		DimArchitecture, DimReuse, DimConcurrencySafety, DimBoundedResources,
		DimReliability, DimTestEffectiveness, DimPerformance, DimSecurity,
		DimOperability, DimPolicyIntegrity,
	}
}

// ClaimState is the outcome of one quality claim.
type ClaimState string

// The four claim states.
const (
	ClaimPass          ClaimState = "PASS"
	ClaimFail          ClaimState = "FAIL"
	ClaimInconclusive  ClaimState = "INCONCLUSIVE"
	ClaimNotApplicable ClaimState = "NOT_APPLICABLE"
)

// EvidenceKind names one evidence obligation.
type EvidenceKind string

// Evidence obligations. Each is produced by exactly one check; a check may
// produce several.
const (
	KindChangeVisible     EvidenceKind = "change-visible"
	KindCompileClean      EvidenceKind = "compile-clean"
	KindVetClean          EvidenceKind = "vet-clean"
	KindFixScan           EvidenceKind = "fix-scan"
	KindInlineMigration   EvidenceKind = "inline-migration"
	KindDialAddress       EvidenceKind = "dial-address"
	KindTestsPass         EvidenceKind = "tests-pass"
	KindLintCorrectness   EvidenceKind = "lint-correctness"
	KindLintReliability   EvidenceKind = "lint-reliability"
	KindLintSecurity      EvidenceKind = "lint-security"
	KindLintSimplicity    EvidenceKind = "lint-simplicity"
	KindLintOperability   EvidenceKind = "lint-operability"
	KindLintArchitecture  EvidenceKind = "lint-architecture"
	KindLintReuse         EvidenceKind = "lint-reuse"
	KindFormatClean       EvidenceKind = "format-clean"
	KindModuleTidy        EvidenceKind = "module-tidy"
	KindHygieneScan       EvidenceKind = "hygiene-scan"
	KindTestNatives       EvidenceKind = "test-natives"
	KindComplexityMetrics EvidenceKind = "complexity-metrics"
	KindArchitectureScan  EvidenceKind = "architecture-scan"
	KindDuplicationScan   EvidenceKind = "duplication-scan"
	KindWorktreeReadOnly  EvidenceKind = "worktree-readonly"
	KindScopeConformance  EvidenceKind = "scope-conformance"
	KindRaceClean         EvidenceKind = "race-clean"
	KindLeakClean         EvidenceKind = "goroutine-leak-clean"
	KindPolicyGuard       EvidenceKind = "policy-guard"
	KindGoroutineLifetime EvidenceKind = "goroutine-lifecycle"
	KindBoundedResources  EvidenceKind = "bounded-resources"
	KindNetworkScan       EvidenceKind = "network-scan"
	KindTxPairing         EvidenceKind = "tx-pairing"
	KindMigrationOrder    EvidenceKind = "migration-order"
	KindAPICompat         EvidenceKind = "api-compat"
	KindAntiWeakening     EvidenceKind = "anti-weakening"
	KindMutationSignal    EvidenceKind = "mutation-signal"
	KindBenchDelta        EvidenceKind = "bench-delta"
	KindAllocDelta        EvidenceKind = "alloc-delta"
	KindMaintainDelta     EvidenceKind = "maintainability-delta"
	KindVulnerabilityScan EvidenceKind = "vulnerability-scan"
)

// RequiredEvidence is one obligation the plan commits to producing. An
// obligation with no produced result forces INCONCLUSIVE on its claim; it is
// never silently downgraded to PASS.
type RequiredEvidence struct {
	Kind     EvidenceKind `json:"kind"`
	Producer string       `json:"producer"`
	Claim    Dimension    `json:"claim"`
	Because  string       `json:"because"`
}

// QualityClaim is the judgement for one dimension of one run.
type QualityClaim struct {
	Dimension       Dimension      `json:"dimension"`
	State           ClaimState     `json:"state"`
	EvidenceRefs    []string       `json:"evidenceRefs"`
	MissingEvidence []EvidenceKind `json:"missingEvidence"`
	Reason          string         `json:"reason"`
}

// Verdict is the admission outcome.
type Verdict string

// Verdicts and their exit codes.
const (
	VerdictAdmitted     Verdict = "ADMITTED"
	VerdictRejected     Verdict = "REJECTED"
	VerdictInconclusive Verdict = "INCONCLUSIVE"
)

// ExitCode maps a verdict onto the process exit status.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictAdmitted:
		return 0
	case VerdictRejected:
		return 1
	default:
		return 2
	}
}

// AdmissionDecision is the full result of an admission run.
type AdmissionDecision struct {
	Verdict                 Verdict            `json:"verdict"`
	Claims                  []QualityClaim     `json:"claims"`
	UnmetObligations        []RequiredEvidence `json:"unmetObligations"`
	SufficientForCompletion bool               `json:"sufficientForCompletion"`
	Reason                  string             `json:"reason"`
}

// Decide applies the decision rule exactly: any applicable FAIL rejects; else
// any applicable INCONCLUSIVE is inconclusive; else the change is admitted.
func Decide(claims []QualityClaim) Verdict {
	if slices.ContainsFunc(claims, func(c QualityClaim) bool { return c.State == ClaimFail }) {
		return VerdictRejected
	}
	if slices.ContainsFunc(claims, func(c QualityClaim) bool { return c.State == ClaimInconclusive }) {
		return VerdictInconclusive
	}
	return VerdictAdmitted
}

// ClaimsInState returns the claims in one state, in dimension order.
func ClaimsInState(claims []QualityClaim, state ClaimState) []QualityClaim {
	var out []QualityClaim
	for _, c := range claims {
		if c.State == state {
			out = append(out, c)
		}
	}
	return out
}

// DecisionReason is a single sentence naming why the verdict came out as it
// did, for the top of the report and for the agent protocol.
func DecisionReason(verdict Verdict, claims []QualityClaim) string {
	switch verdict {
	case VerdictAdmitted:
		return "every applicable quality claim has sufficient evidence"
	case VerdictRejected:
		return "failing claims: " + joinDimensions(ClaimsInState(claims, ClaimFail))
	default:
		return "claims without sufficient evidence: " + joinDimensions(ClaimsInState(claims, ClaimInconclusive))
	}
}

func joinDimensions(claims []QualityClaim) string {
	names := make([]string, 0, len(claims))
	for _, c := range claims {
		names = append(names, string(c.Dimension))
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// Blocking reports whether one piece of evidence can fail its claim: it must be
// required, and either new or exempt from debt grandfathering.
type Blocking func(evidence.Evidence) bool
