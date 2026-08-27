package verify_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The cases in this file are adversarial: each one is a route by which a change
// could have been admitted without the evidence to justify it. They exist to
// stay red if a closure ever regresses, so every one of them asserts a verdict
// that is not ADMITTED, or asserts that a grant had no effect.
//
// Every case runs under every repository layout. Two closures in this file once
// held only where the module sat at the git root, and stayed green for a year
// because no fixture ever built anything else; a closure that holds in one
// layout and not another is not a closure.

// baseline builds a two-commit fixture so that a base revision exists, which is
// what the contract authentication and the diff-reading checks need.
func baseline(t *testing.T, lay layout) *fixture {
	t.Helper()
	f := newFixtureIn(t, lay)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", renamedAnswerLibrary)
	f.commit("second commit so a parent revision exists")
	return f
}

func TestBypassSelfGrantedPolicyEditIsRefused(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
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
	})
}

func TestBypassSelfGrantedAPIBreakIsRefused(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := newFixtureIn(t, lay)
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
	})
}

func TestBypassGeneratedHeaderOnNewCodeIsStillLinted(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
		f.write("lib/touch.go", generatedHeaderLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictRejected)
		if !slices.Contains(blockingRules(result.Evidence), "GCL-errcheck") {
			t.Fatalf("a generated header exempted new code from the linter: %v", blockingRules(result.Evidence))
		}
	})
}

// TestGeneratedCodeTheChangeLeavesAloneStaysExempt is the false-positive guard
// for the exemption: a repository full of generated code is still adoptable,
// because only the generated files a change touches are judged.
func TestGeneratedCodeTheChangeLeavesAloneStaysExempt(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := newFixtureIn(t, lay)
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
	})
}

func TestBypassCodeOutsideTheBuildIsNotSilentlyAdmitted(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
		f.write("lib/hidden.go", excludedLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictInconclusive)
		if !hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
			t.Fatalf("a changed file outside the build produced no obligation: %+v", result.Unproducible)
		}
	})
}

func TestBypassUnderscorePrefixedFileIsNotSilentlyAdmitted(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
		f.write("lib/_hidden.go", cleanLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictInconclusive)
		if !hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
			t.Fatalf("an underscore-prefixed changed file produced no obligation: %+v", result.Unproducible)
		}
	})
}

// TestTestdataChangesStayOutOfScope is the false-positive guard for the
// visibility obligation: testdata is outside package scope by Go convention,
// which is exactly what keeps the harness's own fixtures from tripping it.
func TestTestdataChangesStayOutOfScope(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
		f.write("lib/testdata/sample.go", excludedLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictAdmitted)
		if hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
			t.Fatalf("a testdata file was counted as unexamined change: %+v", result.Unproducible)
		}
	})
}

// TestBypassChangeOutsideTheModuleIsNotJudgedAsCode is the false-positive guard
// that pairs with the coordinate normalization: a monorepo's other directories
// change constantly, and a file the module does not contain is neither evidence
// against the change nor a gap in coverage.
func TestBypassChangeOutsideTheModuleIsNotJudgedAsCode(t *testing.T) {
	useGolangci(t)
	f := baseline(t, subdirLayout())
	f.write("lib/inside.go", cleanSecondLibrary)
	f.writeRepo("frontend/app.go", excludedLibrary)
	f.writeRepo("README.md", "# monorepo\n")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if hasUnproducible(result.Unproducible, admission.KindChangeVisible) {
		t.Fatalf("a file outside the module was counted as unexamined change: %+v", result.Unproducible)
	}
	for _, file := range result.Change.Files {
		if file == "frontend/app.go" || file == "README.md" {
			t.Fatalf("a file outside the module entered the change set: %v", result.Change.Files)
		}
	}
	if !slices.Contains(result.Change.OutsideModule, "frontend/app.go") {
		t.Fatalf("a changed file outside the module was dropped without record: %v", result.Change.OutsideModule)
	}
	// The other half of the invariant: what the module does contain arrives
	// module-relative, with no repository prefix left on it for a downstream join
	// to double.
	if !slices.Contains(result.Change.Files, "lib/inside.go") {
		t.Fatalf("a changed file inside the module did not arrive module-relative: %v", result.Change.Files)
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
	eachLayout(t, func(t *testing.T, lay layout) {
		f := baseline(t, lay)
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
	})
}

// TestBypassGoflagsCannotSilenceTheTestSuite closes the quietest route of all:
// GOFLAGS is spliced into every go invocation, so one -run pattern makes a
// broken suite report success without touching a line of code.
func TestBypassGoflagsCannotSilenceTheTestSuite(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
		f.write("lib/lib.go", wrongAnswerLibrary)
		t.Setenv("GOFLAGS", "-run=NoTestHasThisName")

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictRejected)
		if !slices.Contains(blockingRules(result.Evidence), policy.RuleTestFailure) {
			t.Fatalf("GOFLAGS silenced the test suite: %v", blockingRules(result.Evidence))
		}
	})
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
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
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
	})
}

// TestFlakyTestIsInconclusiveNotRejected is the adoption case that decides
// whether a real repository can keep the gate switched on. A suite that answers
// differently each run must not be allowed to blame the change in front of it,
// and must not be allowed to pass either.
func TestFlakyTestIsInconclusiveNotRejected(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		useGolangci(t)
		f := baseline(t, lay)
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
	})
}

// TestBypassHeadCacheCannotReachTheMandatoryCore bounds the one thing a
// per-package head cache adds to the threat model.
//
// The cached answer is content-addressed, so an entry only ever applies to
// bytes it was computed from. What it cannot rule out is someone with write
// access to the cache directory seeding an entry for content they are about to
// commit, which would make that package's findings for the cached check
// disappear. The containment is that the cache speaks for the two formatting
// checks and nothing else: no mandatory rule, and nothing ungrandfatherable,
// can be answered from it, so the rules the harness exists to enforce are
// decided by a fresh computation every run. This test fails the moment a
// cached check starts producing one of them.
func TestBypassHeadCacheCannotReachTheMandatoryCore(t *testing.T) {
	t.Parallel()
	cached := []string{policy.RuleFormatGofmt, policy.RuleFormatGoimports}
	for _, ruleID := range cached {
		if slices.Contains(policy.MandatoryRuleIDs(), ruleID) {
			t.Fatalf("%s is mandatory and answerable from the head cache", ruleID)
		}
		if policy.IsUngrandfatherable(ruleID) {
			t.Fatalf("%s blocks as pre-existing debt and is answerable from the head cache", ruleID)
		}
	}
	// The guard is only worth having while the list above is the whole list, so
	// it is pinned rather than derived: a new cached check has to be added here
	// deliberately, which is where someone reads the paragraph above.
	if got := len(cached); got != 2 {
		t.Fatalf("%d checks answer from the head cache; the containment argument covers 2", got)
	}
}

// TestBypassMovingAFileDoesNotLaunderANewFinding closes the route the rename
// realignment opens.
//
// A base snapshot is read in head's coordinates so that moving a file does not
// hand its existing findings back as introduced. The route that buys is a change
// that moves a file and edits it in the same breath, hoping the move carries the
// edit past the comparison with it.
func TestBypassMovingAFileDoesNotLaunderANewFinding(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		f := newFixtureIn(t, lay)
		f.write("lib/lib.go", cleanLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("clean baseline")
		f.anchor()
		f.move("lib/lib.go", "lib/answer.go")
		f.write("lib/answer.go", suppressedLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictRejected)
		if !slices.Contains(blockingRules(result.Evidence), policy.RuleSuppressNolint) {
			t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleSuppressNolint)
		}
	})
}

// TestMovingAFileIntroducesNothingByItself is the false-positive guard on the
// closure above, and the defect that made it necessary.
//
// A file is part of a finding's identity, so before the base snapshot was
// realigned a branch that reorganised code was rejected for every finding the
// moved files already carried and credited for fixing the same ones. The whole
// directory moves here because a move across directories is the case that also
// decides which directories the narrowed checks have to read at base.
func TestMovingAFileIntroducesNothingByItself(t *testing.T) {
	eachLayout(t, func(t *testing.T, lay layout) {
		f := newFixtureIn(t, lay)
		f.write("lib/lib.go", unformattedLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("baseline carrying formatting debt")
		f.anchor()
		f.move("lib", "pkg")

		result := run(t, f, verify.ModeVerify)
		var seen bool
		for _, e := range result.Evidence {
			if e.RuleID != policy.RuleFormatGofmt {
				continue
			}
			seen = true
			if e.State != evidence.StatePreexisting {
				t.Fatalf("moving a file made its existing finding %s, want %s",
					e.State, evidence.StatePreexisting)
			}
		}
		if !seen {
			t.Fatalf("the moved file's existing finding vanished entirely: %v",
				ruleIDs(result.Evidence))
		}
		if got := blockingRules(result.Evidence); len(got) > 0 {
			t.Fatalf("a move with no edit produced blocking findings: %v", got)
		}
	})
}
