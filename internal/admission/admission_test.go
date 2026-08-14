package admission_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

func TestFourteenDimensions(t *testing.T) {
	t.Parallel()
	dims := admission.Dimensions()
	if len(dims) != 14 {
		t.Fatalf("dimensions = %d, want 14", len(dims))
	}
	seen := map[admission.Dimension]bool{}
	for _, d := range dims {
		if seen[d] {
			t.Fatalf("duplicate dimension %s", d)
		}
		seen[d] = true
	}
}

// TestEveryRuleHasADimension keeps the model total: a rule the harness can emit
// but cannot place would silently fall into policy-integrity.
func TestEveryRuleHasADimension(t *testing.T) {
	t.Parallel()
	for _, rule := range policy.Registry() {
		if _, ok := admission.DimensionOf(rule.ID); !ok {
			t.Errorf("rule %s has no dimension", rule.ID)
		}
	}
}

func TestDecisionRuleIsAPureConjunction(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		claims []admission.QualityClaim
		want   admission.Verdict
	}{
		{
			name:   "all pass admits",
			claims: claims(admission.ClaimPass, admission.ClaimPass, admission.ClaimNotApplicable),
			want:   admission.VerdictAdmitted,
		},
		{
			name:   "one fail rejects even beside many passes",
			claims: claims(admission.ClaimPass, admission.ClaimPass, admission.ClaimFail),
			want:   admission.VerdictRejected,
		},
		{
			name:   "fail outranks inconclusive",
			claims: claims(admission.ClaimInconclusive, admission.ClaimFail),
			want:   admission.VerdictRejected,
		},
		{
			name:   "inconclusive outranks pass",
			claims: claims(admission.ClaimPass, admission.ClaimInconclusive),
			want:   admission.VerdictInconclusive,
		},
		{
			name:   "not applicable never decides",
			claims: claims(admission.ClaimNotApplicable, admission.ClaimNotApplicable),
			want:   admission.VerdictAdmitted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := admission.Decide(tc.claims); got != tc.want {
				t.Fatalf("Decide = %s, want %s", got, tc.want)
			}
		})
	}
}

func claims(states ...admission.ClaimState) []admission.QualityClaim {
	out := make([]admission.QualityClaim, 0, len(states))
	dims := admission.Dimensions()
	for i, state := range states {
		out = append(out, admission.QualityClaim{Dimension: dims[i], State: state})
	}
	return out
}

func basePlan(t *testing.T) admission.VerificationPlan {
	t.Helper()
	return admission.BuildPlan(admission.PlanInput{Contract: admission.TaskContract{}})
}

// TestUnproducedObligationForcesInconclusive is the model's central promise:
// evidence that could not be produced is never quietly a pass.
func TestUnproducedObligationForcesInconclusive(t *testing.T) {
	t.Parallel()
	plan := basePlan(t)
	all := kinds(plan)

	full := admission.EvaluateClaims(admission.ClaimInput{
		Plan: plan, Produced: all, Blocking: neverBlocking,
	})
	if got := admission.Decide(full); got != admission.VerdictAdmitted {
		t.Fatalf("with every obligation discharged the verdict is %s, want ADMITTED", got)
	}

	withoutTests := slices.DeleteFunc(slices.Clone(all), func(k admission.EvidenceKind) bool {
		return k == admission.KindTestsPass
	})
	partial := admission.EvaluateClaims(admission.ClaimInput{
		Plan: plan, Produced: withoutTests, Blocking: neverBlocking,
		Unproducible: []admission.Unproducible{{
			Kind: admission.KindTestsPass, Reason: "the test binary would not build",
			Remedy: "fix the build",
		}},
	})
	if got := admission.Decide(partial); got != admission.VerdictInconclusive {
		t.Fatalf("with one obligation unproduced the verdict is %s, want INCONCLUSIVE", got)
	}
	for _, claim := range partial {
		if claim.Dimension != admission.DimCorrectness {
			continue
		}
		if claim.State != admission.ClaimInconclusive {
			t.Fatalf("correctness = %s, want INCONCLUSIVE", claim.State)
		}
		if !slices.Contains(claim.MissingEvidence, admission.KindTestsPass) {
			t.Fatalf("missing evidence = %v", claim.MissingEvidence)
		}
		if claim.Reason == "" {
			t.Fatal("the claim gives no reason")
		}
	}
}

func TestAdvisoryFindingsNeverFlipAVerdict(t *testing.T) {
	t.Parallel()
	plan := basePlan(t)
	result := admission.EvaluateClaims(admission.ClaimInput{
		Plan:     plan,
		Produced: kinds(plan),
		Evidence: []evidence.Evidence{{
			RuleID: policy.RuleFunctionLength, Fingerprint: "abc",
			Classification: evidence.ClassificationAdvisory,
		}},
		Blocking: func(e evidence.Evidence) bool {
			return e.Classification == evidence.ClassificationRequired
		},
	})
	if got := admission.Decide(result); got != admission.VerdictAdmitted {
		t.Fatalf("an advisory finding produced %s", got)
	}
	for _, claim := range result {
		if claim.Dimension == admission.DimSimplicity && len(claim.EvidenceRefs) != 1 {
			t.Fatalf("the advisory finding is not recorded inside its claim: %+v", claim)
		}
	}
}

func TestRequiredViolationFailsItsClaim(t *testing.T) {
	t.Parallel()
	plan := basePlan(t)
	result := admission.EvaluateClaims(admission.ClaimInput{
		Plan:     plan,
		Produced: kinds(plan),
		Evidence: []evidence.Evidence{{
			RuleID: policy.RuleSuppressNolint, Fingerprint: "abc",
			Classification: evidence.ClassificationRequired,
		}},
		Blocking: func(e evidence.Evidence) bool {
			return e.Classification == evidence.ClassificationRequired
		},
	})
	if got := admission.Decide(result); got != admission.VerdictRejected {
		t.Fatalf("verdict = %s, want REJECTED", got)
	}
	for _, claim := range result {
		if claim.Dimension == admission.DimPolicyIntegrity && claim.State != admission.ClaimFail {
			t.Fatalf("policy-integrity = %s, want FAIL", claim.State)
		}
	}
}

func kinds(plan admission.VerificationPlan) []admission.EvidenceKind {
	out := make([]admission.EvidenceKind, 0, len(plan.Obligations))
	for _, o := range plan.Obligations {
		out = append(out, o.Kind)
	}
	return out
}

func neverBlocking(evidence.Evidence) bool { return false }

func TestRiskObligationsAreAdditive(t *testing.T) {
	t.Parallel()
	plain := admission.BuildPlan(admission.PlanInput{})
	concurrent := admission.BuildPlan(admission.PlanInput{
		Risks: profileWith(admission.RiskConcurrency),
	})
	if len(concurrent.Obligations) <= len(plain.Obligations) {
		t.Fatalf("concurrency risk added no obligations: %d vs %d",
			len(concurrent.Obligations), len(plain.Obligations))
	}
	if !slices.Contains(kinds(concurrent), admission.KindRaceClean) {
		t.Fatalf("concurrency risk did not require race evidence: %v", kinds(concurrent))
	}
	if plain.AppliesTo(admission.DimConcurrencySafety) {
		t.Fatal("concurrency-safety applies without a concurrency change")
	}
}

// TestRaceRunSubsumesThePlainTestRun keeps the suite from running twice for the
// same evidence.
func TestRaceRunSubsumesThePlainTestRun(t *testing.T) {
	t.Parallel()
	plan := admission.BuildPlan(admission.PlanInput{Risks: profileWith(admission.RiskConcurrency)})
	if slices.Contains(plan.CheckIDs(), admission.ProducerTest) {
		t.Fatalf("both test runs were planned: %v", plan.CheckIDs())
	}
	if !slices.Contains(plan.CheckIDs(), admission.ProducerRaceTest) {
		t.Fatalf("the race run was not planned: %v", plan.CheckIDs())
	}
}

func TestDiffObligationsNeedABase(t *testing.T) {
	t.Parallel()
	withoutBase := admission.BuildPlan(admission.PlanInput{Risks: profileWith(admission.RiskTests)})
	if slices.Contains(kinds(withoutBase), admission.KindMutationSignal) {
		t.Fatal("mutation evidence was demanded with no base revision to diff against")
	}
	withBase := admission.BuildPlan(admission.PlanInput{
		Risks: profileWith(admission.RiskTests), BaseAvailable: true,
	})
	if !slices.Contains(kinds(withBase), admission.KindMutationSignal) {
		t.Fatalf("mutation evidence was not demanded with a base: %v", kinds(withBase))
	}
}

func profileWith(domains ...admission.RiskDomain) admission.RiskProfile {
	return admission.RiskProfile{Active: domains}
}

func TestContractScopeMatching(t *testing.T) {
	t.Parallel()
	contract := admission.TaskContract{DeclaredScope: []string{"internal/lib/", "cmd/app"}}
	cases := map[string]bool{
		"internal/lib/a.go":      true,
		"internal/lib/deep/b.go": true,
		"cmd/app/main.go":        true,
		"cmd/app":                true,
		"internal/other/c.go":    false,
		"README.md":              false,
	}
	for file, want := range cases {
		if got := contract.InScope(file); got != want {
			t.Errorf("InScope(%q) = %v, want %v", file, got, want)
		}
	}
	if !(admission.TaskContract{}).InScope("anything") {
		t.Fatal("a contract with no declared scope excluded a file")
	}
}

func TestLoadContractFallsBackToTheImplicitDefault(t *testing.T) {
	t.Parallel()
	contract, err := admission.LoadContract("", t.TempDir())
	if err != nil {
		t.Fatalf("LoadContract: %v", err)
	}
	if contract.Source != admission.ContractFromDefault {
		t.Fatalf("source = %q, want the implicit default", contract.Source)
	}
	if contract.AllowAPIBreak {
		t.Fatal("the implicit contract permits API breaks")
	}
	if contract.HasScope() {
		t.Fatal("the implicit contract declares a scope")
	}
}

func TestParseContractReadsTheDocumentedShape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeContract(t, dir, `# a task
goal: make the parser strict
allowApiBreak: true
scope:
  - internal/policy/
  - internal/admission/
risks:
  - concurrency
  - hot-path
budgets:
  BenchmarkFingerprint:
    maxTimeIncreasePercent: 5
    maxAllocIncreasePercent: 0
`)
	contract, err := admission.LoadContract("", dir)
	if err != nil {
		t.Fatalf("LoadContract: %v", err)
	}
	if contract.Goal != "make the parser strict" || !contract.AllowAPIBreak {
		t.Fatalf("contract = %+v", contract)
	}
	if len(contract.DeclaredScope) != 2 || len(contract.DeclaredRisks) != 2 {
		t.Fatalf("scope = %v risks = %v", contract.DeclaredScope, contract.DeclaredRisks)
	}
	budget := contract.BudgetFor("BenchmarkFingerprint")
	if budget.MaxTimeIncreasePercent != 5 || budget.MaxAllocIncreasePercent != 0 {
		t.Fatalf("budget = %+v", budget)
	}
	fallback := contract.BudgetFor("BenchmarkOther")
	if fallback != admission.DefaultBudget() {
		t.Fatalf("unnamed benchmark budget = %+v, want the default", fallback)
	}
}

func TestParseContractRejectsUnknownKeysAndRisks(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"unknown key":  "surprise: yes\n",
		"unknown risk": "risks:\n  - telepathy\n",
		"bad bool":     "allowApiBreak: perhaps\n",
		"bad budget":   "budgets:\n  BenchmarkX:\n    maxTimeIncreasePercent: soon\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeContract(t, dir, body)
			if _, err := admission.LoadContract("", dir); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func writeContract(t *testing.T, dir, body string) {
	t.Helper()
	path := filepath.Join(dir, admission.ContractFileName)
	if err := writeFile(path, body); err != nil {
		t.Fatalf("writing contract: %v", err)
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
