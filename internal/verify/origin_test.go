package verify_test

import (
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The cases in this file pin the second axis a report of a branch needs. State
// says whether a finding existed at the base revision; origin says whether it
// sits in a file the change wrote. Reading either one as the other is how a
// report either buries a branch in debt it did not create or hides a defect it
// did.

func originsByFile(items []evidence.Evidence) map[string]evidence.Origin {
	out := map[string]evidence.Origin{}
	for _, e := range items {
		if e.File != "" {
			out[e.File] = e.Origin
		}
	}
	return out
}

// TestANewFindingInAnUntouchedPackageIsStillTheChangesToAnswerFor is the
// combination a file-level filter must not lose. The change edits one package
// and breaks another it never opened; the finding lands in a file the diff does
// not contain, and it still blocks.
func TestANewFindingInAnUntouchedPackageIsStillTheChangesToAnswerFor(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", consumerLibrary)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("clean baseline")
	f.anchor()
	f.write("lib/lib.go", incompatibleAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)

	origins := originsByFile(result.Evidence)
	if got := origins["consumer/consumer.go"]; got != evidence.OriginUntouched {
		t.Fatalf("origin of the finding in the untouched package = %q, want %q (all: %v)",
			got, evidence.OriginUntouched, origins)
	}
	var blocked bool
	for _, e := range result.Evidence {
		if e.File == "consumer/consumer.go" && verify.Blocking(e) {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("the break in the untouched package does not block: %v", origins)
	}
}

// TestDebtInAFileTheChangeTouchedKeepsBothAxes is the row a reviewer wants and
// neither axis can express alone: old finding, new file to be reading it in.
func TestDebtInAFileTheChangeTouchedKeepsBothAxes(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline carrying debt")
	f.anchor()
	f.write("lib/lib.go", debtPlusAdditionLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)

	var found bool
	for _, e := range result.Evidence {
		if e.RuleID != policy.GolangciRuleID("errcheck") || e.File != "lib/lib.go" {
			continue
		}
		found = true
		if e.State != evidence.StatePreexisting {
			t.Fatalf("state = %q, want %q", e.State, evidence.StatePreexisting)
		}
		if e.Origin != evidence.OriginChanged {
			t.Fatalf("origin = %q, want %q", e.Origin, evidence.OriginChanged)
		}
	}
	if !found {
		t.Fatalf("no errcheck finding survived in the changed file: %v", ruleIDs(result.Evidence))
	}
}

// TestAuditAttributesNothing holds the honest answer where there is no diff:
// unscoped, rather than a guess in either direction.
func TestAuditAttributesNothing(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", emDashLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline")

	result := run(t, f, verify.ModeAudit)
	for _, e := range result.Evidence {
		if e.Origin != evidence.OriginUnscoped {
			t.Fatalf("audit attributed %s in %s to %q; an audit has no diff to attribute against",
				e.RuleID, e.File, e.Origin)
		}
	}
}

// TestOriginPlacesAPackageScopedFindingByItsDirectory covers the findings that
// have no line to sit on. A test failure belongs to a package, and the change is
// answerable for it when it touched anything in that package.
func TestOriginPlacesAPackageScopedFindingByItsDirectory(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.anchor()
	f.write("lib/lib.go", wrongAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleTestFailure) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleTestFailure)
	}
	for _, e := range result.Evidence {
		if e.RuleID != policy.RuleTestFailure {
			continue
		}
		if e.Origin != evidence.OriginChanged {
			t.Fatalf("a test failure in the changed package is %q, want %q (package %q, file %q)",
				e.Origin, evidence.OriginChanged, e.Package, e.File)
		}
	}
}

// TestOriginPlacesAFindingCarryingAnImportPath covers the producers that put a
// package path where a file path usually goes. An API break belongs to the
// package that broke, and reading its locator as an unknown file name would
// report the change's own break as sitting somewhere it never touched.
func TestOriginPlacesAFindingCarryingAnImportPath(t *testing.T) {
	f := newFixture(t)
	f.write("api/api.go", publicAPIBase)
	f.write("api/api_test.go", publicAPITest)
	f.commit("published api")
	f.anchor()
	f.write("api/api.go", publicAPIBreak)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	var found bool
	for _, e := range result.Evidence {
		if e.RuleID != policy.RuleAPIBreak {
			continue
		}
		found = true
		if e.Origin != evidence.OriginChanged {
			t.Fatalf("the API break in the changed package is %q, want %q (file %q, package %q)",
				e.Origin, evidence.OriginChanged, e.File, e.Package)
		}
	}
	if !found {
		t.Fatalf("no API break finding: %v", ruleIDs(result.Evidence))
	}
}

// TestOriginNeverReachesAFingerprint is the guard on the one way a second axis
// could do damage: identity has to stay what it was, or every finding is renamed
// the day the axis is added.
func TestOriginNeverReachesAFingerprint(t *testing.T) {
	t.Parallel()
	plain := evidence.Finalize([]evidence.Evidence{{RuleID: "GH-X", File: "a.go", Message: "boom"}})
	marked := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-X", File: "a.go", Message: "boom", Origin: evidence.OriginChanged},
	})
	if plain[0].Fingerprint != marked[0].Fingerprint {
		t.Fatalf("origin changed a fingerprint: %q vs %q", plain[0].Fingerprint, marked[0].Fingerprint)
	}
}

// incompatibleAnswerLibrary changes an exported signature so that the package
// importing it stops compiling. The defect it produces is located in a file the
// change never opened, which is exactly the case a diff-scoped view must keep.
const incompatibleAnswerLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer(scale int) int {
	return 42 * scale
}
`
