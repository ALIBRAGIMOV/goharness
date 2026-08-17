package verify_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The cases in this file are adversarial: each one is a route by which a change
// could have been admitted without the evidence to justify it. They exist to
// stay red if a closure ever regresses, so every one of them asserts a verdict
// that is not ADMITTED, or asserts that a grant had no effect.

// baseline builds a two-commit fixture so that a base revision exists, which is
// what the contract authentication and the diff-reading checks need.
func baseline(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", renamedAnswerLibrary)
	f.commit("second commit so a parent revision exists")
	return f
}

func TestBypassSelfGrantedPolicyEditIsRefused(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("goharness.task.yaml", "goal: sneak a policy change past the gate\nallowPolicyEdit: true\n")
	f.write("goharness.yaml", "# an exception the change wrote for itself\n")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	blocking := blockingRules(result.Evidence)
	for _, want := range []string{policy.RulePolicyGrant, policy.RulePolicyEdit} {
		if !slices.Contains(blocking, want) {
			t.Fatalf("blocking rules = %v, want %s", blocking, want)
		}
	}
	if result.Contract.AllowPolicyEdit {
		t.Fatal("an uncommitted contract granted allowPolicyEdit")
	}
}

func TestBypassSelfGrantedAPIBreakIsRefused(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("api/api.go", publicAPIBase)
	f.write("api/api_test.go", publicAPITest)
	f.commit("published api")
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("second commit so a parent revision exists")
	f.write("api/api.go", publicAPIBreak)
	f.write("goharness.task.yaml", "goal: remove Farewell\nallowApiBreak: true\n")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	blocking := blockingRules(result.Evidence)
	for _, want := range []string{policy.RulePolicyGrant, policy.RuleAPIBreak} {
		if !slices.Contains(blocking, want) {
			t.Fatalf("blocking rules = %v, want %s", blocking, want)
		}
	}
}

func TestBypassGeneratedHeaderOnNewCodeIsStillLinted(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("lib/touch.go", generatedHeaderLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), "GCL-errcheck") {
		t.Fatalf("a generated header exempted new code from the linter: %v", blockingRules(result.Evidence))
	}
}

// TestGeneratedCodeTheChangeLeavesAloneStaysExempt is the false-positive guard
// for the exemption: a repository full of generated code is still adoptable,
// because only the generated files a change touches are judged.
func TestGeneratedCodeTheChangeLeavesAloneStaysExempt(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("lib/touch.go", generatedHeaderLibrary)
	f.commit("baseline with generated code")
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if slices.Contains(ruleIDs(result.Evidence), "GCL-errcheck") {
		t.Fatalf("untouched generated code produced evidence: %v", ruleIDs(result.Evidence))
	}
}

func TestBypassCodeOutsideTheBuildIsNotSilentlyAdmitted(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("lib/hidden.go", excludedLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)
	if !hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
		t.Fatalf("a changed file outside the build produced no obligation: %+v", result.Unproducible)
	}
}

func TestBypassUnderscorePrefixedFileIsNotSilentlyAdmitted(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("lib/_hidden.go", cleanLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)
	if !hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
		t.Fatalf("an underscore-prefixed changed file produced no obligation: %+v", result.Unproducible)
	}
}

// TestTestdataChangesStayOutOfScope is the false-positive guard for the
// visibility obligation: testdata is outside package scope by Go convention,
// which is exactly what keeps the harness's own fixtures from tripping it.
func TestTestdataChangesStayOutOfScope(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("lib/testdata/sample.go", excludedLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
		t.Fatalf("a testdata file was counted as unexamined change: %+v", result.Unproducible)
	}
}

// forgedLinter answers --version with the pinned version and reports a clean
// report for anything else. Writing one is the cheapest way for a change to
// make the strictest linter in the plan agree with it.
const forgedLinter = `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "golangci-lint has version 2.12.2 built with go1.26.4"
  exit 0
fi
echo '{"Issues":[]}'
`

func TestBypassForgedLinterIsNotTrusted(t *testing.T) {
	f := baseline(t)
	f.writeExecutable(tool.GolangciLintLocalPath, forgedLinter)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	isolateLinterSources(t)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)
	if !hasUnproducible(result.Unproducible, admission.KindLintCorrectness) {
		t.Fatalf("a forged linter was believed: %+v", result.Unproducible)
	}
	if result.Golangci.SHA256 != "" {
		t.Fatalf("a forged linter was accepted with sha256 %q", result.Golangci.SHA256)
	}
}

// TestBypassGoflagsCannotSilenceTheTestSuite closes the quietest route of all:
// GOFLAGS is spliced into every go invocation, so one -run pattern makes a
// broken suite report success without touching a line of code.
func TestBypassGoflagsCannotSilenceTheTestSuite(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("lib/lib.go", wrongAnswerLibrary)
	t.Setenv("GOFLAGS", "-run=NoTestHasThisName")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleTestFailure) {
		t.Fatalf("GOFLAGS silenced the test suite: %v", blockingRules(result.Evidence))
	}
}

// isolateLinterSources puts every trusted golangci-lint out of the run's reach,
// so a test can observe what happens when the only candidate is a forgery. The
// stub PATH keeps the toolchain and git reachable and nothing else.
func isolateLinterSources(t *testing.T) {
	t.Helper()
	t.Setenv(tool.GolangciLintEnvVar, "")
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())

	stub := t.TempDir()
	for _, name := range []string{"go", "git", "clang", "cc"} {
		target, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.Symlink(target, filepath.Join(stub, name)); err != nil {
			t.Fatalf("linking %s into the stub PATH: %v", name, err)
		}
	}
	t.Setenv("PATH", stub)
}

func hasUnproducible(items []admission.Unproducible, kind admission.EvidenceKind) bool {
	return slices.ContainsFunc(items, func(u admission.Unproducible) bool { return u.Kind == kind })
}

// TestContractMayStillTightenTheGate is the false-positive guard for the grant
// model: a working-tree contract that only narrows what the change may do is
// honoured in full, because nothing it declares can weaken the verdict.
func TestContractMayStillTightenTheGate(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("worker/worker.go", cleanLibrary)
	f.write("goharness.task.yaml", "goal: touch only the library\nscope:\n  - lib/\n")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleScopeViolation) {
		t.Fatalf("declared scope was ignored: %v", blockingRules(result.Evidence))
	}
	if len(result.Contract.IgnoredGrants) != 0 {
		t.Fatalf("a contract without grants reported ignored grants: %v", result.Contract.IgnoredGrants)
	}
}

// TestFlakyTestIsInconclusiveNotRejected is the adoption case that decides
// whether a real repository can keep the gate switched on. A suite that answers
// differently each run must not be allowed to blame the change in front of it,
// and must not be allowed to pass either.
func TestFlakyTestIsInconclusiveNotRejected(t *testing.T) {
	useGolangci(t)
	f := baseline(t)
	f.write("lib/flaky_test.go", flakyLibraryTest)

	result := run(t, f, verify.ModeVerify)
	if result.Decision.Verdict == admission.VerdictRejected {
		t.Fatalf("a flake rejected the change: %v", blockingRules(result.Evidence))
	}
	if !hasUnproducible(result.Unproducible, admission.KindTestsPass) {
		t.Fatalf("a flake produced no obligation: %+v", result.Unproducible)
	}
	if slices.Contains(ruleIDs(result.Evidence), policy.RuleTestFailure) {
		t.Fatalf("a flake was recorded as a test failure: %v", ruleIDs(result.Evidence))
	}
}
