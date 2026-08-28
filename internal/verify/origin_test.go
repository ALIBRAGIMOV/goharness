package verify_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The cases in this file pin the second axis a report of a branch needs. State
// says whether the base revision already had a finding; origin says how close it
// sits to the code this change wrote. Reading either one as the other is how a
// report either buries a branch in debt it did not create or hides a defect it
// did.

func originsOfRule(items []evidence.Evidence, ruleID string) map[string]evidence.Origin {
	out := map[string]evidence.Origin{}
	for _, e := range items {
		if e.RuleID == ruleID && e.File != "" {
			// Several rows can share a file; they agree on origin by construction,
			// and a disagreement would surface as a failure in the case below.
			out[e.File] = e.Origin
		}
	}
	return out
}

// TestOriginDistinguishesEveryDistanceFromTheChange is the whole table in one
// fixture. Only lib/lib.go is edited, and only by appending; everything else in
// the closure predates the branch.
func TestOriginDistinguishesEveryDistanceFromTheChange(t *testing.T) {
	useGolangci(t)
	f := originFixture(t)

	result := run(t, f, verify.ModeVerify)
	errcheck := policy.GolangciRuleID("errcheck")
	origins := originsOfRule(result.Evidence, errcheck)

	for file, want := range map[string]evidence.Origin{
		"lib/sibling.go":       evidence.OriginChangedPackage,
		"consumer/consumer.go": evidence.OriginUntouched,
	} {
		if got := origins[file]; got != want {
			t.Fatalf("origin of %s = %q, want %q (all: %v)", file, got, want, origins)
		}
	}

	// The edited file carries both distances at once, which is the case a
	// file-granular axis cannot express: old debt on old lines, a new defect on
	// a line the branch typed.
	var added, changed int
	for _, e := range result.Evidence {
		if e.RuleID != errcheck || e.File != "lib/lib.go" {
			continue
		}
		switch e.Origin {
		case evidence.OriginAddedLine:
			added++
			if e.State != evidence.StateNew {
				t.Fatalf("a finding on an added line is %q, want %q", e.State, evidence.StateNew)
			}
		case evidence.OriginChangedFile:
			changed++
			if e.State != evidence.StatePreexisting {
				t.Fatalf("a finding on an old line of an edited file is %q, want %q",
					e.State, evidence.StatePreexisting)
			}
		default:
			t.Fatalf("a finding in the edited file is %q, which is not a distance it can be at",
				e.Origin)
		}
	}
	if added == 0 || changed == 0 {
		t.Fatalf("the edited file produced %d added-line and %d changed-file row(s); "+
			"the fixture must produce both or it guards nothing", added, changed)
	}
}

// TestTheDiffViewDropsWhatTheAuthorNeverOpened is the consequence the field
// report asked for: 846 rows in sibling files came back labelled as the
// change's, and a reviewer had to compute the diff by hand to see otherwise.
func TestTheDiffViewDropsWhatTheAuthorNeverOpened(t *testing.T) {
	useGolangci(t)
	f := originFixture(t)

	result := run(t, f, verify.ModeVerify)
	errcheck := policy.GolangciRuleID("errcheck")
	kept, dropped := map[string]bool{}, map[string]bool{}
	for _, e := range result.Evidence {
		if e.RuleID != errcheck {
			continue
		}
		if report.ScopeDiff.Keeps(e) {
			kept[e.File] = true
			continue
		}
		dropped[e.File] = true
	}
	if !kept["lib/lib.go"] {
		t.Fatalf("the diff view dropped the edited file entirely: kept %v", kept)
	}
	for _, file := range []string{"lib/sibling.go", "consumer/consumer.go"} {
		if kept[file] || !dropped[file] {
			t.Fatalf("the diff view kept %s, which the change never opened: kept %v", file, kept)
		}
	}
}

// TestANewFindingInAnUntouchedPackageIsStillTheChangesToAnswerFor is the
// combination no distance filter may lose. The change edits one package and
// breaks another it never opened; the finding lands outside the diff, and it
// still blocks.
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

	var blocked bool
	for _, e := range result.Evidence {
		if e.File != "consumer/consumer.go" {
			continue
		}
		if e.Origin != evidence.OriginUntouched {
			t.Fatalf("origin of the break in the untouched package = %q, want %q",
				e.Origin, evidence.OriginUntouched)
		}
		if verify.Blocking(e) {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("the break in the untouched package does not block")
	}
}

// TestAuditAttributesNothing holds the answer for a run that is not about a
// change.
//
// An audit sits on a commit like any other run, so a diff exists and could be
// attributed against. It must not be. An audit answers for the repository, and
// placing its findings against the last commit would let every rule that blocks
// while pre-existing stop blocking everywhere that commit did not reach, which
// is the whole of the un-baselineable core switched off by an accident of where
// HEAD happens to be.
func TestAuditAttributesNothing(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", emDashLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline")
	f.anchor()
	f.write("lib/second.go", cleanSecondLibrary)
	f.commit("a third commit, so this audit has a diff behind it")

	result := run(t, f, verify.ModeAudit)
	if len(result.Change.Entries) == 0 {
		t.Fatal("the fixture produced no diff, so it does not guard what it claims to")
	}
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
		if e.Origin != evidence.OriginChangedPackage {
			t.Fatalf("a test failure in the changed package is %q, want %q (package %q, file %q)",
				e.Origin, evidence.OriginChangedPackage, e.Package, e.File)
		}
	}
}

// TestARemovedSymbolIsAddressable pins the other half of the same lesson. An
// API break used to carry an import path where a file goes, so the row could not
// be opened, could not be reached by a scoped exception, and could not be placed
// against the diff at all.
func TestARemovedSymbolIsAddressable(t *testing.T) {
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
		if !strings.HasSuffix(e.File, ".go") {
			t.Fatalf("the removed symbol is located at %q, which is not a file a reader can open",
				e.File)
		}
		if e.Line == 0 {
			t.Fatalf("the removed symbol at %s carries no line", e.File)
		}
		if !e.Origin.InChange() {
			t.Fatalf("the removal in the edited file is %q, want a distance inside the change",
				e.Origin)
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
		{RuleID: "GH-X", File: "a.go", Message: "boom", Origin: evidence.OriginAddedLine},
	})
	if plain[0].Fingerprint != marked[0].Fingerprint {
		t.Fatalf("origin changed a fingerprint: %q vs %q", plain[0].Fingerprint, marked[0].Fingerprint)
	}
}

// originFixture builds the repository every distance can be observed in: one
// edited file, a sibling that shares its package, and a package the change never
// opened, each carrying the same rule.
func originFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.write("lib/lib.go", discardingLibrary)
	f.write("lib/sibling.go", discardingSibling)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", discardingConsumer)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("baseline carrying the same debt at three distances")
	f.anchor()
	f.write("lib/lib.go", discardingLibrary+discardingAddition)
	return f
}

// Fixture sources for the distance table. Each carries the same errcheck defect
// so that only the location distinguishes the rows.
const (
	discardingLibrary = `package lib

import "os"

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	return 42
}

// Touch opens a file and discards the error, which errcheck reports.
func Touch(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`

	discardingSibling = `package lib

import "os"

// Helper opens a file and discards the error in a file the change never opens.
func Helper(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`

	discardingConsumer = `package consumer

import (
	"os"

	"example.com/fixture/lib"
)

// Doubled returns twice the library answer.
func Doubled() int {
	return lib.Answer() * 2
}

// Store opens a file and discards the error, a package away from the change.
func Store(name string) {
	f, _ := os.Create(name)
	f.Close()
}
`

	// discardingAddition is what the branch types: a defect of the same rule, on
	// lines that did not exist at the base revision.
	discardingAddition = `
// Extra opens a file and discards the error on a line this change wrote.
func Extra(name string) {
	f, _ := os.Open(name)
	f.Close()
}
`
)
