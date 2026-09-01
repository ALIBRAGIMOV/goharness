package verify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

func run(t *testing.T, f *fixture, mode verify.Mode) verify.Result {
	t.Helper()
	result, err := verify.Run(t.Context(), "test", verify.Options{Mode: mode, Dir: f.verifyDir()})
	if err != nil {
		t.Fatalf("verify.Run(%s): %v", mode, err)
	}
	return result
}

func ruleIDs(items []evidence.Evidence) []string {
	out := make([]string, 0, len(items))
	for _, e := range items {
		out = append(out, e.RuleID)
	}
	return out
}

func blockingRules(items []evidence.Evidence) []string {
	var out []string
	for _, e := range items {
		if verify.Blocking(e) {
			out = append(out, e.RuleID)
		}
	}
	return out
}

func requireVerdict(t *testing.T, result verify.Result, want admission.Verdict) {
	t.Helper()
	if result.Decision.Verdict != want {
		t.Fatalf("verdict = %s (%s), want %s\nblocking: %v\nfailures: %+v\nunproducible: %+v",
			result.Decision.Verdict, result.Decision.Reason, want,
			blockingRules(result.Evidence), result.Failures, result.Unproducible)
	}
}

func TestSuppressionDirectiveRejectsTheChange(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", suppressedLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleSuppressNolint) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleSuppressNolint)
	}
}

func TestEmDashInACommentRejectsTheChange(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", emDashLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleCommentEmDash) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleCommentEmDash)
	}
}

func TestSuppressionAndEmDashInsideStringLiteralsAreAdmitted(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", literalsOnlyLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	for _, id := range ruleIDs(result.Evidence) {
		if id == policy.RuleSuppressNolint || id == policy.RuleSuppressStaticcheck || id == policy.RuleCommentEmDash {
			t.Fatalf("a string literal produced %s", id)
		}
	}
}

// TestNewlyIntroducedLintProblemRejectsTheChange runs under every layout
// because it is the shortest end-to-end statement the harness makes: a defect
// the change introduced blocks it, and the evidence names the file in the
// module's own coordinates. Both halves failed for a module below the git root,
// and the base comparison this exercises builds its own worktree, where the
// module has to be found again at the same prefix.
func TestNewlyIntroducedLintProblemRejectsTheChange(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := newFixtureIn(t, lay)
		f.write("lib/lib.go", cleanLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("clean baseline")
		f.write("lib/lib.go", uncheckedErrorLibrary)
		f.commit("introduce an unchecked error")

		result := run(t, f, verify.ModeVerify)
		if !result.BaseCompared {
			t.Fatalf("base comparison did not run; change = %+v", result.Change)
		}
		requireVerdict(t, result, admission.VerdictRejected)
		if !slices.Contains(blockingRules(result.Evidence), "GCL-errcheck") {
			t.Fatalf("blocking rules = %v, want GCL-errcheck", blockingRules(result.Evidence))
		}
		for _, e := range result.Evidence {
			if e.RuleID != "GCL-errcheck" {
				continue
			}
			if e.State != evidence.StateNew {
				t.Fatalf("errcheck finding state = %q, want %q", e.State, evidence.StateNew)
			}
			if e.File != "lib/lib.go" {
				t.Fatalf("evidence file = %q, want the module-relative path", e.File)
			}
		}
	})
}

// TestPreexistingDebtDoesNotBlockVerify is the false-positive guard of the case
// above, and runs under every layout for the same reason: the base worktree is
// where the module prefix has to be applied a second time, and a base the
// harness cannot build is a base against which everything looks new.
func TestPreexistingDebtDoesNotBlockVerify(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := newFixtureIn(t, lay)
		f.write("lib/lib.go", uncheckedErrorLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("baseline that already carries debt")
		f.write("lib/lib.go", debtPlusAdditionLibrary)
		f.commit("unrelated addition")

		result := run(t, f, verify.ModeVerify)
		if !result.BaseCompared {
			t.Fatalf("base comparison did not run; change = %+v", result.Change)
		}
		requireVerdict(t, result, admission.VerdictAdmitted)

		var sawDebt bool
		for _, e := range result.Evidence {
			if e.RuleID != "GCL-errcheck" {
				continue
			}
			sawDebt = true
			if e.State != evidence.StatePreexisting {
				t.Fatalf("debt state = %q, want %q", e.State, evidence.StatePreexisting)
			}
		}
		if !sawDebt {
			t.Fatalf("pre-existing debt was not reported at all: %v", ruleIDs(result.Evidence))
		}
	})
}

func TestChangedPackagePullsInReverseDependentTests(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", consumerLibrary)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("two packages, one depending on the other")
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)

	wantPkg := fixtureModule + "/consumer"
	if !slices.Contains(result.Execution.Tests, wantPkg) {
		t.Fatalf("planned test packages = %v, want the reverse dependent %s", result.Execution.Tests, wantPkg)
	}
	if !slices.Contains(result.Execution.Packages, wantPkg) {
		t.Fatalf("planned packages = %v, want the reverse dependent %s", result.Execution.Packages, wantPkg)
	}
}

func TestFastModeStopsAtDirectDependents(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", consumerLibrary)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("two packages")
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeFast)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if result.BaseCompared {
		t.Fatal("fast mode performed a base comparison")
	}
	if !slices.Contains(result.Execution.Packages, fixtureModule+"/consumer") {
		t.Fatalf("fast mode dropped the direct dependent: %v", result.Execution.Packages)
	}
	if slices.Contains(result.Execution.Tests, fixtureModule+"/consumer") {
		t.Fatalf("fast mode ran reverse dependent tests: %v", result.Execution.Tests)
	}
}

func TestGolangciLintRunsInFastAndVerify(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", renamedAnswerLibrary)

	for _, mode := range []verify.Mode{verify.ModeFast, verify.ModeVerify} {
		result := run(t, f, mode)
		if !slices.Contains(result.Execution.Tools(), "golangci-lint") {
			t.Fatalf("%s tools = %v, want golangci-lint", mode, result.Execution.Tools())
		}
		if !slices.Contains(result.Execution.CheckIDs(), admission.ProducerGolangci) {
			t.Fatalf("%s checks = %v, want %s", mode, result.Execution.CheckIDs(), admission.ProducerGolangci)
		}
		doc := report.Build("test", result)
		if doc.Versions.GolangciLint != "2.13.2" || !doc.Versions.GolangciLintMatches {
			t.Fatalf("%s report records golangci-lint %q (matches=%v)",
				mode, doc.Versions.GolangciLint, doc.Versions.GolangciLintMatches)
		}
	}
}

func TestJSONReportRecordsEveryPin(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")

	result := run(t, f, verify.ModeVerify)
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "test", result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc["schema"] != report.SchemaID {
		t.Fatalf("schema = %v, want %s", doc["schema"], report.SchemaID)
	}
	versions, ok := doc["versions"].(map[string]any)
	if !ok {
		t.Fatalf("versions block missing: %v", doc)
	}
	if versions["uberGuideCommit"] != policy.UberGuideCommit {
		t.Fatalf("uberGuideCommit = %v, want %s", versions["uberGuideCommit"], policy.UberGuideCommit)
	}
	for _, key := range []string{"goharness", "go", "golangciLint", "golangciLintPin"} {
		if versions[key] == "" || versions[key] == nil {
			t.Fatalf("versions.%s is empty in %v", key, versions)
		}
	}
	if _, present := doc["verdict"]; !present {
		t.Fatal("report has no verdict")
	}
}

func TestToolCrashIsInconclusiveAndNeverEvidence(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")

	script := filepath.Join(t.TempDir(), "fake-golangci-lint")
	body := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then\n" +
		"  echo 'golangci-lint has version 2.13.2 built with go1.27.0'\n" +
		"  exit 0\n" +
		"fi\n" +
		"echo 'panic: internal linter failure' >&2\n" +
		"exit 3\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing fake linter: %v", err)
	}
	isolateLinterSources(t)
	t.Setenv("GOHARNESS_GOLANGCI_LINT", script)
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	if len(result.Execution.Packages) == 0 {
		t.Fatal("the fixture change produced an empty scope, so the linter never ran")
	}
	requireVerdict(t, result, admission.VerdictInconclusive)
	if result.Decision.Verdict.ExitCode() != 2 {
		t.Fatalf("exit code = %d, want 2", result.Decision.Verdict.ExitCode())
	}
	if len(result.Failures) == 0 {
		t.Fatal("no CheckFailure recorded for the crashing tool")
	}
	for _, e := range result.Evidence {
		if strings.HasPrefix(e.RuleID, "GCL-") {
			t.Fatalf("a tool crash produced evidence: %+v", e)
		}
	}
	var sawLintFailure bool
	for _, failure := range result.Failures {
		if failure.CheckID == admission.ProducerGolangci {
			sawLintFailure = true
			if failure.Hint == "" {
				t.Fatal("the golangci-lint failure carries no doctor hint")
			}
		}
	}
	if !sawLintFailure {
		t.Fatalf("failures = %+v, want one for %s", result.Failures, admission.ProducerGolangci)
	}
}

func TestVersionMismatchIsInconclusive(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.commit("clean baseline")

	script := filepath.Join(t.TempDir(), "old-golangci-lint")
	body := "#!/bin/sh\necho 'golangci-lint has version 1.64.8 built with go1.22.0'\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing fake linter: %v", err)
	}
	isolateLinterSources(t)
	t.Setenv("GOHARNESS_GOLANGCI_LINT", script)
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)
	var mentionsPin bool
	for _, failure := range result.Failures {
		if strings.Contains(failure.Reason, "2.13.2") {
			mentionsPin = true
		}
	}
	if !mentionsPin {
		t.Fatalf("failures do not mention the pinned version: %+v", result.Failures)
	}
}

func TestVerificationIsReadOnly(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline with debt")
	f.write("lib/lib.go", debtPlusAdditionLibrary)

	for _, mode := range []verify.Mode{verify.ModeFast, verify.ModeVerify} {
		before := f.porcelain()
		result := run(t, f, mode)
		after := f.porcelain()
		if before != after {
			t.Fatalf("%s modified the worktree:\nbefore:\n%s\nafter:\n%s", mode, before, after)
		}
		for _, failure := range result.Failures {
			if failure.CheckID == "worktree-guard" {
				t.Fatalf("the worktree guard tripped: %s", failure.Reason)
			}
		}
	}
	if leftovers := f.git("worktree", "list"); strings.Count(leftovers, "\n") != 1 {
		t.Fatalf("a temporary base worktree was left behind:\n%s", leftovers)
	}
}

func TestRepeatedRunsProduceIdenticalReports(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", consumerLibrary)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("baseline")
	f.write("lib/lib.go", debtPlusAdditionLibrary)

	render := func() []byte {
		encoded, err := report.DeterministicJSON("test", run(t, f, verify.ModeVerify))
		if err != nil {
			t.Fatalf("DeterministicJSON: %v", err)
		}
		return encoded
	}
	first, second := render(), render()
	if !bytes.Equal(first, second) {
		t.Fatalf("two runs produced different reports:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func TestRepositoryWithoutCommitsUsesFullScope(t *testing.T) {
	useGolangci(t)
	// With no base, every file is the change's, go.mod included, so the
	// dependency domain is active and the scan needs a snapshot to answer.
	provisionSnapshot(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if !result.Risks.Has(admission.RiskDependency) {
		t.Fatalf("a full-scope change did not activate the dependency domain: %+v", result.Risks)
	}
	if !result.Change.FullScope {
		t.Fatal("a repository with no commits did not fall back to full scope")
	}
	if result.BaseCompared {
		t.Fatal("a repository with no commits attempted a base comparison")
	}
}

func TestIneffectiveTestIsRejected(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib_test.go", ineffectiveLibraryTest)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleTestNoAssertion) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleTestNoAssertion)
	}
}

func TestFailingTestIsRejected(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", wrongAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleTestFailure) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleTestFailure)
	}
}

func TestCompilationFailureIsRejectedAndSkipsDependentChecks(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.commit("clean baseline")
	f.write("lib/lib.go", brokenLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleCompile) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleCompile)
	}
	for _, id := range []string{admission.ProducerVet, admission.ProducerGolangci, admission.ProducerTest} {
		if !slices.Contains(result.Skipped, id) {
			t.Fatalf("skipped = %v, want %s to be skipped after a compile failure", result.Skipped, id)
		}
	}
}

func TestProjectConfigExceptionDowngradesAFinding(t *testing.T) {
	useGolangci(t)
	bare := newFixture(t)
	bare.write("lib/lib.go", cleanLibrary)
	bare.write("lib/lib_test.go", cleanLibraryTest)
	bare.commit("clean baseline")
	bare.write("lib/lib.go", uncheckedErrorLibrary)

	if got := run(t, bare, verify.ModeFast); got.Decision.Verdict != admission.VerdictRejected {
		t.Fatalf("without configuration the verdict is %s, want REJECTED", got.Decision.Verdict)
	}

	// A second fixture carries the exception in its baseline: policy is
	// reviewed history, not part of the diff under judgment, so the policy
	// guard stays silent and only the excepted finding is at stake.
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("goharness.yaml", "exceptions:\n"+
		"  - rule: GCL-errcheck\n"+
		"    scope: lib/\n"+
		"    reason: legacy helper scheduled for deletion\n"+
		"    owner: platform-team\n"+
		"    expires: 2099-12-31\n")
	f.commit("baseline with reviewed exception")
	f.write("lib/lib.go", uncheckedErrorLibrary)

	result := run(t, f, verify.ModeFast)
	requireVerdict(t, result, admission.VerdictAdmitted)

	var sawExcepted bool
	for _, e := range result.Evidence {
		if e.RuleID != "GCL-errcheck" {
			continue
		}
		sawExcepted = true
		if e.Classification != evidence.ClassificationAdvisory {
			t.Fatalf("excepted finding classification = %q, want advisory", e.Classification)
		}
	}
	if !sawExcepted {
		t.Fatal("the excepted finding disappeared from the report; exceptions must downgrade, never hide")
	}
}

func TestConfigCannotExceptAMandatoryRule(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.commit("clean baseline")
	f.write("goharness.yaml", "exceptions:\n"+
		"  - rule: "+policy.RuleSuppressNolint+"\n"+
		"    scope: lib/\n"+
		"    reason: convenience\n"+
		"    owner: nobody\n"+
		"    expires: 2099-12-31\n")

	_, err := verify.Run(t.Context(), "test", verify.Options{Mode: verify.ModeFast, Dir: f.verifyDir()})
	if err == nil {
		t.Fatal("an exception for a mandatory rule was accepted")
	}
	if !strings.Contains(err.Error(), "mandatory") {
		t.Fatalf("error = %v, want it to name the mandatory rule", err)
	}
}

func TestExplicitBaseFlagChangesWhatCountsAsNew(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	clean := strings.TrimSpace(f.git("rev-parse", "HEAD"))
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.commit("introduce debt")
	f.write("lib/lib.go", debtPlusAdditionLibrary)
	f.commit("unrelated addition")

	againstParent, err := verify.Run(t.Context(), "test",
		verify.Options{Mode: verify.ModeVerify, Dir: f.verifyDir()})
	if err != nil {
		t.Fatalf("verify against the parent commit: %v", err)
	}
	if againstParent.Decision.Verdict != admission.VerdictAdmitted {
		t.Fatalf("against the parent commit the verdict is %s, want ADMITTED (the debt is pre-existing)",
			againstParent.Decision.Verdict)
	}

	againstClean, err := verify.Run(t.Context(), "test",
		verify.Options{Mode: verify.ModeVerify, Dir: f.verifyDir(), Base: clean})
	if err != nil {
		t.Fatalf("verify against the clean commit: %v", err)
	}
	if againstClean.Decision.Verdict != admission.VerdictRejected {
		t.Fatalf("against the clean commit the verdict is %s, want REJECTED (the debt is new)",
			againstClean.Decision.Verdict)
	}
	if againstClean.Change.BaseOrigin != change.BaseFromFlag {
		t.Fatalf("base origin = %q, want %q", againstClean.Change.BaseOrigin, change.BaseFromFlag)
	}
}

func claimFor(t *testing.T, result verify.Result, dim admission.Dimension) admission.QualityClaim {
	t.Helper()
	for _, claim := range result.Decision.Claims {
		if claim.Dimension == dim {
			return claim
		}
	}
	t.Fatalf("no claim for dimension %s in %+v", dim, result.Decision.Claims)
	return admission.QualityClaim{}
}

func TestClaimsTableCoversEveryDimension(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)

	if len(result.Decision.Claims) != len(admission.Dimensions()) {
		t.Fatalf("claims = %d, want one per dimension (%d)",
			len(result.Decision.Claims), len(admission.Dimensions()))
	}
	for _, claim := range result.Decision.Claims {
		switch claim.State {
		case admission.ClaimPass, admission.ClaimNotApplicable:
		default:
			t.Fatalf("claim %s = %s (%s) on a clean change", claim.Dimension, claim.State, claim.Reason)
		}
		if claim.Reason == "" {
			t.Fatalf("claim %s has no reason", claim.Dimension)
		}
	}
	if claimFor(t, result, admission.DimCorrectness).State != admission.ClaimPass {
		t.Fatal("correctness did not pass on a clean change")
	}
}

func TestUnproducibleEvidenceIsInconclusiveNotAdmitted(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("goharness.task.yaml", "goal: declare a hot path with no benchmark\nrisks:\n  - hot-path\n")
	f.commit("baseline declaring a hot path")
	f.write("lib/lib.go", renamedAnswerLibrary)
	f.commit("touch the declared hot path")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)

	claim := claimFor(t, result, admission.DimPerformance)
	if claim.State != admission.ClaimInconclusive {
		t.Fatalf("performance claim = %s (%s), want INCONCLUSIVE", claim.State, claim.Reason)
	}
	if !slices.Contains(claim.MissingEvidence, admission.KindBenchDelta) {
		t.Fatalf("missing evidence = %v, want %s", claim.MissingEvidence, admission.KindBenchDelta)
	}
	var named bool
	for _, u := range result.Unproducible {
		if u.Kind == admission.KindBenchDelta && u.Remedy != "" {
			named = true
		}
	}
	if !named {
		t.Fatalf("the report does not say how to produce bench-delta: %+v", result.Unproducible)
	}
}

func TestMutationEvidenceDetectsWeakTests(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", weakTestLibrary)
	f.write("lib/lib_test.go", weakTestSource)
	f.commit("baseline with a weak test")
	f.write("lib/lib.go", strings.Replace(weakTestLibrary, "score >= 50", "score >= 60", 1))
	f.write("lib/lib_test.go", weakTestSource+"\nfunc TestClassifyStillRuns(t *testing.T) {\n\tif Classify(10) == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n")
	f.commit("change the branch, leave the test blind")

	result := run(t, f, verify.ModeVerify)
	claim := claimFor(t, result, admission.DimTestEffectiveness)
	if claim.State != admission.ClaimFail {
		t.Fatalf("test-effectiveness = %s (%s), want FAIL because no test observes the mutated branch",
			claim.State, claim.Reason)
	}
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleMutantsSurvived) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleMutantsSurvived)
	}
}

func TestMutationEvidencePassesWhenTestsKillMutants(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", weakTestLibrary)
	f.write("lib/lib_test.go", strongTestSource)
	f.commit("baseline with a boundary test")
	f.write("lib/lib.go", strings.Replace(weakTestLibrary, "return \"pass\"", "return \"passed\"", 1))
	f.write("lib/lib_test.go", strings.Replace(strongTestSource, "want pass", "want passed", 1))
	f.write("lib/lib_test.go", strings.ReplaceAll(
		strings.Replace(strongTestSource, "want pass", "want passed", 1), "!= \"pass\"", "!= \"passed\""))
	f.commit("rename the branch result and keep the test exact")

	result := run(t, f, verify.ModeVerify)
	claim := claimFor(t, result, admission.DimTestEffectiveness)
	if claim.State != admission.ClaimPass {
		t.Fatalf("test-effectiveness = %s (%s), want PASS because the tests kill a mutant",
			claim.State, claim.Reason)
	}
}

func TestPublicAPIBreakIsRejectedWithoutAContract(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("api/api.go", publicAPIBase)
	f.write("api/api_test.go", publicAPITest)
	f.commit("public api baseline")
	f.write("api/api.go", publicAPIBreak)
	f.commit("remove an exported function")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleAPIBreak) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleAPIBreak)
	}
}

// TestPublicAPIBreakIsAllowedWhenTheBaseContractRecordsIt is the other half:
// the decision to break an interface is a human one, so it counts when it was
// committed before the change that breaks it, and only then.
func TestPublicAPIBreakIsAllowedWhenTheBaseContractRecordsIt(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("api/api.go", publicAPIBase)
	f.write("api/api_test.go", publicAPITest)
	f.write("goharness.task.yaml", "goal: deliberately drop Farewell\nallowApiBreak: true\n")
	f.commit("public api baseline with the decision recorded")
	f.write("api/api.go", publicAPIBreak)
	f.commit("remove an exported function")

	result := run(t, f, verify.ModeVerify)
	if result.Decision.Verdict == admission.VerdictRejected {
		t.Fatalf("verdict = %s with allowApiBreak set; blocking: %v",
			result.Decision.Verdict, blockingRules(result.Evidence))
	}
	if !result.Contract.AllowAPIBreak || !result.Contract.Authenticated {
		t.Fatalf("the committed grant was not honoured: %+v", result.Contract)
	}
}

func TestAntiWeakeningBlocksARemovedAssertion(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", assertiveTest)
	f.commit("baseline with an exact test")
	f.write("lib/lib_test.go", weakenedTest)
	f.commit("remove the assertions but keep the code")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleAssertionRemoved) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleAssertionRemoved)
	}
}

func TestBenchmarkEvidenceIsProducedWhenBenchmarksExist(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", benchmarkedLibrary)
	f.write("lib/lib_test.go", benchmarkSource)
	f.commit("baseline with a benchmark")
	f.write("lib/lib.go", strings.Replace(benchmarkedLibrary, "total := 0", "total := 0 // widened", 1))
	f.commit("touch the benchmarked function")

	result := run(t, f, verify.ModeVerify)
	claim := claimFor(t, result, admission.DimPerformance)
	if claim.State == admission.ClaimNotApplicable {
		t.Fatalf("performance stayed NOT_APPLICABLE although a benchmark exists: %+v", result.Risks.Active)
	}
	if claim.State == admission.ClaimInconclusive {
		t.Fatalf("benchmarks exist but bench-delta was unproducible: %s", claim.Reason)
	}
}

func TestAuditIsRepositoryWideAndActivatesEveryRisk(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", consumerLibrary)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("two packages")

	result := run(t, f, verify.ModeAudit)
	if len(result.Risks.Active) != len(admission.RiskDomains()) {
		t.Fatalf("audit activated %v, want every domain", result.Risks.Active)
	}
	if len(result.Execution.Packages) != 2 {
		t.Fatalf("audit scope = %v, want both packages", result.Execution.Packages)
	}
	if result.BaseCompared {
		t.Fatal("audit performed a base comparison")
	}
}

func TestFastIsNeverSufficientForCompletion(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")

	fast := run(t, f, verify.ModeFast)
	requireVerdict(t, fast, admission.VerdictAdmitted)
	if fast.Decision.SufficientForCompletion {
		t.Fatal("fast reported itself sufficient for completion")
	}
	verified := run(t, f, verify.ModeVerify)
	if !verified.Decision.SufficientForCompletion {
		t.Fatalf("verify on a clean tree is not sufficient: %s", verified.Decision.Reason)
	}
}

func TestTimeoutIsInconclusiveNeverRejected(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline that would otherwise be rejected")
	f.write("lib/lib.go", debtPlusAdditionLibrary)

	result, err := verify.Run(t.Context(), "test", verify.Options{
		Mode: verify.ModeVerify, Dir: f.verifyDir(), Timeout: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("verify.Run with an exhausted timeout: %v", err)
	}
	if result.Decision.Verdict != admission.VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE; a timed-out run must never claim or deny safety",
			result.Decision.Verdict)
	}
	if !result.TimedOut {
		t.Fatalf("the result does not record the timeout: %+v", result.Failures)
	}
	// The clock is goharness's own. A deadline that surfaced as "go test -race:
	// context deadline exceeded" with no hint read as a broken toolchain, and
	// two releases' worth of CI reports were misdiagnosed on it.
	for _, failure := range result.Failures {
		if failure.Tool != "goharness" {
			t.Fatalf("a run deadline was attributed to %q: %+v", failure.Tool, failure)
		}
		if !strings.Contains(failure.Hint, "--timeout") {
			t.Fatalf("the failure does not say what to raise: %+v", failure)
		}
	}
}

func TestCancellationIsInconclusiveAndCleansUp(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline")
	f.write("lib/lib.go", renamedAnswerLibrary)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := verify.Run(ctx, "test", verify.Options{Mode: verify.ModeVerify, Dir: f.verifyDir()})
	if err != nil {
		t.Fatalf("verify.Run on a cancelled context: %v", err)
	}
	if result.Decision.Verdict != admission.VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", result.Decision.Verdict)
	}
	if leftovers := f.git("worktree", "list"); strings.Count(leftovers, "\n") != 1 {
		t.Fatalf("a cancelled run left a worktree behind:\n%s", leftovers)
	}
}

func TestScopeViolationFailsRequirementsCompliance(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", consumerLibrary)
	f.write("consumer/consumer_test.go", consumerTest)
	f.write("goharness.task.yaml", "goal: only touch lib\nscope:\n  - lib/\n")
	f.commit("baseline with a scoped contract")
	f.write("consumer/consumer.go", consumerLibrary+"\n// Tripled returns three times the answer.\nfunc Tripled() int {\n\treturn lib.Answer() * 3\n}\n")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	claim := claimFor(t, result, admission.DimRequirements)
	if claim.State != admission.ClaimFail {
		t.Fatalf("requirements-compliance = %s (%s), want FAIL", claim.State, claim.Reason)
	}
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleScopeViolation) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleScopeViolation)
	}
}
