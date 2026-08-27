package verify_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// These cases hold the narrowing invariant and the line it must not cross.
//
// A package directory whose judged files are byte-identical at base and head
// produces identical findings at both from any check that reads only that
// directory, so those findings pair on fingerprint and can be neither new nor
// fixed. Not scanning such a directory removes pre-existing rows and nothing
// else.
//
// Two guards bound that reasoning, and both have a case here. It covers
// directory-local checks only: compilation, vet, the linter and the tests still
// see the whole reverse dependency closure, because a change in one package can
// create a real new finding in another. And it covers rules that stop blocking
// once they are pre-existing: an ungrandfatherable rule blocks wherever in scope
// it is, so a check that owns one is never narrowed.

func findingsUnder(items []evidence.Evidence, dir string) []evidence.Evidence {
	var out []evidence.Evidence
	for _, e := range items {
		if strings.HasPrefix(e.File, dir+"/") {
			out = append(out, e)
		}
	}
	return out
}

func rulesUnder(items []evidence.Evidence, dir string) []string {
	return ruleIDs(findingsUnder(items, dir))
}

// TestUntouchedDirectoriesAreNotRescannedForDirectoryLocalRules is the
// narrowing itself: debt that would cancel against itself is not computed, so it
// never reaches the report to be filtered out of it.
func TestUntouchedDirectoriesAreNotRescannedForDirectoryLocalRules(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", unformattedConsumer)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("baseline with formatting debt in the consumer")
	f.anchor()
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)

	if got := result.Execution.LocalScope; !slices.Equal(got, []string{"lib"}) {
		t.Fatalf("local scan scope = %v, want [lib]", got)
	}
	if got := rulesUnder(result.Evidence, "consumer"); slices.Contains(got, policy.RuleFormatGofmt) {
		t.Fatalf("an untouched directory was rescanned for a directory-local rule: %v", got)
	}
}

// TestNarrowingKeepsFindingsInTheDirectoriesTheChangeTouched is the
// false-positive guard on the narrowing: the same rule in the same run still
// fires where the change actually is.
func TestNarrowingKeepsFindingsInTheDirectoriesTheChangeTouched(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", unformattedConsumer)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("baseline with formatting debt in the consumer")
	f.anchor()
	f.write("lib/lib.go", unformattedLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleFormatGofmt) {
		t.Fatalf("blocking rules = %v, want %s",
			blockingRules(result.Evidence), policy.RuleFormatGofmt)
	}
}

// TestNarrowingNeverSkipsARuleThatBlocksWhilePreexisting is the guard that
// decides whether the narrowing is an optimisation or a way to switch a rule
// off. A suppression blocks wherever in scope it is, base revision or not, so
// the check that finds one reads every directory however little the change
// touched.
func TestNarrowingNeverSkipsARuleThatBlocksWhilePreexisting(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", suppressedConsumer)
	f.write("consumer/consumer_test.go", consumerTest)
	f.commit("baseline with a suppression in the consumer")
	f.anchor()
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleSuppressNolint) {
		t.Fatalf("blocking rules = %v, want %s; the narrowing skipped a rule "+
			"that blocks even when the base revision already carried it",
			blockingRules(result.Evidence), policy.RuleSuppressNolint)
	}
}

// TestNarrowingLeavesTheCrossPackageToolsAtFullScope is the other bound. The
// narrowing reasoning holds for a check that reads one directory and for no
// other kind, and a run that quietly applied it to compilation would stop seeing
// the packages a change breaks without editing.
func TestNarrowingLeavesTheCrossPackageToolsAtFullScope(t *testing.T) {
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
	if got := result.Execution.LocalScope; !slices.Equal(got, []string{"lib"}) {
		t.Fatalf("local scan scope = %v, want [lib]", got)
	}
	if len(findingsUnder(result.Evidence, "consumer")) == 0 {
		t.Fatalf("the untouched package the change broke produced no evidence: %v",
			ruleIDs(result.Evidence))
	}
}

// TestNothingIsNarrowedWithoutABaseToCompareAgainst holds the precondition. The
// narrowing is paid for by the comparison; with no base every finding is the
// change's to answer for, and skipping a directory would be skipping evidence.
func TestNothingIsNarrowedWithoutABaseToCompareAgainst(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("consumer/consumer.go", unformattedConsumer)
	f.write("consumer/consumer_test.go", consumerTest)

	result := run(t, f, verify.ModeVerify)
	if result.BaseCompared {
		t.Fatal("the fixture has no base revision but the run compared against one")
	}
	if result.Execution.LocalScope != nil {
		t.Fatalf("local scan scope = %v, want no narrowing at all", result.Execution.LocalScope)
	}
	if got := rulesUnder(result.Evidence, "consumer"); !slices.Contains(got, policy.RuleFormatGofmt) {
		t.Fatalf("rules under consumer = %v, want %s with no base to grandfather it",
			got, policy.RuleFormatGofmt)
	}
}

// Fixture sources for the narrowing cases. The formatting ones are deliberately
// misformatted rather than defective: gofmt reads one file's bytes and owns no
// rule that blocks while pre-existing, which is exactly the shape a narrowable
// check has.
const (
	unformattedConsumer = `package consumer

import "example.com/fixture/lib"

// Doubled returns twice the library answer.
func Doubled() int {
	  return lib.Answer()*2
}
`

	unformattedLibrary = `package lib

// Answer returns a constant the fixture tests can observe.
func Answer() int {
	  return 42
}
`

	suppressedConsumer = `package consumer

import "example.com/fixture/lib"

// Doubled returns twice the library answer.
func Doubled() int {
	//nolint:gomnd
	return lib.Answer() * 2
}
`
)
