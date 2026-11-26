package verify_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The cases in this file hold one property: a finding must carry the same
// identity at both revisions, and identity starts with the path.
//
// The base revision is verified in a temporary worktree. When a tool there
// reports a file by a path that escapes that worktree, the string differs from
// the head side's and the two never pair, so every finding the producer made
// reads as introduced by the change. On that run go vet and go fix produced 0
// pre-existing rows against golangci-lint's 856, and 81 findings were blamed on
// lines that predated the branch.
//
// No fixture had ever carried a pre-existing vet or go fix finding, so both
// sides produced nothing and always agreed. That is what these fixtures are for.

func stateCounts(items []evidence.Evidence, ruleID string) map[evidence.State]int {
	out := map[evidence.State]int{}
	for _, e := range items {
		if e.RuleID == ruleID {
			out[e.State]++
		}
	}
	return out
}

// TestEveryProducerMatchesItsOwnFindingsAcrossRevisions is the regression test
// for the path defect. The defects here predate the branch; the branch only
// appends a clean function to the same file.
func TestEveryProducerMatchesItsOwnFindingsAcrossRevisions(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", preexistingDefectLibrary)
	f.write("lib/lib_test.go", preexistingDefectLibraryTest)
	f.commit("baseline carrying a defect for every producer")
	f.anchor()
	f.write("lib/lib.go", preexistingDefectLibrary+preexistingDefectAddition)

	result := run(t, f, verify.ModeVerify)
	if !result.BaseCompared {
		t.Fatal("the fixture produced no base comparison, so it guards nothing")
	}
	for _, ruleID := range []string{
		policy.RuleVet,
		policy.GoFixRuleID("rangeint"),
		policy.GolangciRuleID("errcheck"),
		policy.RuleFormatGofmt,
	} {
		counts := stateCounts(result.Evidence, ruleID)
		if counts[evidence.StatePreexisting] == 0 {
			t.Fatalf("%s produced no pre-existing row, so this rule guards nothing: %v",
				ruleID, counts)
		}
		if counts[evidence.StateNew] > 0 || counts[evidence.StateFixed] > 0 {
			t.Fatalf("%s: %d new and %d fixed row(s) for a defect that predates the branch; "+
				"base and head are not naming the same finding",
				ruleID, counts[evidence.StateNew], counts[evidence.StateFixed])
		}
	}
}

// TestNoFindingCarriesAPathOutsideTheTree is the invariant behind the one above,
// asserted directly so a regression names its cause rather than its symptom.
func TestNoFindingCarriesAPathOutsideTheTree(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", preexistingDefectLibrary)
	f.write("lib/lib_test.go", preexistingDefectLibraryTest)
	f.commit("baseline carrying a defect for every producer")
	f.anchor()
	f.write("lib/lib.go", preexistingDefectLibrary+preexistingDefectAddition)

	result := run(t, f, verify.ModeVerify)
	for _, e := range result.Evidence {
		if e.File == "" {
			continue
		}
		if filepath.IsAbs(e.File) || strings.HasPrefix(e.File, "../") || e.File == ".." {
			t.Fatalf("%s carries a path outside the module: %q", e.RuleID, e.File)
		}
		if e.Fix != nil && strings.Contains(e.Fix.Command, "goharness-base-") {
			t.Fatalf("%s hands back a command naming the base worktree: %q",
				e.RuleID, e.Fix.Command)
		}
	}
}

// TestTwoRunsOfOneCommitAgreeOnEveryFingerprint is the determinism half. A
// fingerprint set that moves between runs makes report-to-report progress
// accounting meaningless: the same commit diffed against itself reported 704
// fixed and 704 introduced.
func TestTwoRunsOfOneCommitAgreeOnEveryFingerprint(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", preexistingDefectLibrary)
	f.write("lib/lib_test.go", preexistingDefectLibraryTest)
	f.commit("baseline carrying a defect for every producer")
	f.anchor()
	f.write("lib/lib.go", preexistingDefectLibrary+preexistingDefectAddition)

	first := fingerprintSet(run(t, f, verify.ModeVerify).Evidence)
	second := fingerprintSet(run(t, f, verify.ModeVerify).Evidence)
	for print, rule := range first {
		if _, ok := second[print]; !ok {
			t.Fatalf("%s %s is in the first run and not the second", rule, print)
		}
	}
	for print, rule := range second {
		if _, ok := first[print]; !ok {
			t.Fatalf("%s %s is in the second run and not the first", rule, print)
		}
	}
}

func fingerprintSet(items []evidence.Evidence) map[string]string {
	out := make(map[string]string, len(items))
	for _, e := range items {
		out[e.Fingerprint] = e.RuleID
	}
	return out
}

// Fixture sources carrying one pre-existing defect per producer: a three-clause
// loop for go fix, a wrong printf verb for go vet, a discarded error for
// errcheck, and misformatted lines for gofmt.
const (
	preexistingDefectLibrary = `package lib

import (
	"fmt"
	"os"
)

// Answer counts to the answer the long way, which go fix modernizes.
func Answer() int {
	total := 0
	for i := 0; i < 42; i++ {
		total++
	}
	return total
}

// Describe prints with a verb that does not match its argument, which go vet
// reports.
func Describe() {
	fmt.Printf("%d\n", "not a number")
}

// Touch opens a file and discards the error, which errcheck reports.
func Touch(name string) {
	f, _ := os.Open(name)
	f.Close()
}

// Misformatted is indented in a way gofmt would rewrite.
func Misformatted() int {
	  return 1
}
`

	preexistingDefectLibraryTest = `package lib

import "testing"

func TestAnswer(t *testing.T) {
	if got := Answer(); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
}
`

	// preexistingDefectAddition is what the branch writes: nothing a producer
	// has anything to say about, so every row in the report predates it.
	preexistingDefectAddition = `
// Doubled returns twice the answer and introduces no finding of its own.
func Doubled() int {
	return Answer() * 2
}
`
)
