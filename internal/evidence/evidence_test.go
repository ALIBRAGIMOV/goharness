package evidence_test

import (
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

func TestFingerprintExcludesLineNumbers(t *testing.T) {
	a := evidence.Fingerprint("GH-X", "a.go", "pkg", "boom", 0)
	b := evidence.Fingerprint("GH-X", "a.go", "pkg", "boom", 0)
	if a != b {
		t.Fatalf("fingerprint is not stable: %q vs %q", a, b)
	}
	if len(a) != evidence.FingerprintLength {
		t.Fatalf("fingerprint length = %d, want %d", len(a), evidence.FingerprintLength)
	}
	if c := evidence.Fingerprint("GH-X", "a.go", "pkg", "boom", 1); c == a {
		t.Fatal("occurrence index does not change the fingerprint")
	}
}

func TestFingerprintNormalizesWhitespace(t *testing.T) {
	spaced := evidence.Fingerprint("GH-X", "a.go", "pkg", "a   b\n c", 0)
	plain := evidence.Fingerprint("GH-X", "a.go", "pkg", "a b c", 0)
	if spaced != plain {
		t.Fatal("message whitespace changed the fingerprint")
	}
}

func TestFinalizeIsDeterministicAndLineIndependent(t *testing.T) {
	first := evidence.Finalize([]evidence.Evidence{
		{RuleID: "B", File: "b.go", Line: 9, Message: "second"},
		{RuleID: "A", File: "a.go", Line: 3, Message: "first"},
		{RuleID: "A", File: "a.go", Line: 40, Message: "first"},
	})
	shifted := evidence.Finalize([]evidence.Evidence{
		{RuleID: "A", File: "a.go", Line: 400, Message: "first"},
		{RuleID: "A", File: "a.go", Line: 30, Message: "first"},
		{RuleID: "B", File: "b.go", Line: 90, Message: "second"},
	})
	if len(first) != len(shifted) {
		t.Fatalf("length mismatch: %d vs %d", len(first), len(shifted))
	}
	for i := range first {
		if first[i].Fingerprint != shifted[i].Fingerprint {
			t.Fatalf("item %d fingerprint changed with line numbers: %q vs %q",
				i, first[i].Fingerprint, shifted[i].Fingerprint)
		}
	}
	if first[0].RuleID != "A" || first[2].RuleID != "B" {
		t.Fatalf("presentation order is wrong: %v", []string{first[0].RuleID, first[1].RuleID, first[2].RuleID})
	}
}

// TestConsequenceOrdersPresentationOnly is the guard on the one way consequence
// classes could do damage.
//
// Occurrence indexes are assigned in identity order, and the fingerprint is
// built from them. If consequence ever reached that ordering, reclassifying a
// rule would silently rename every repeated finding of it, every base
// comparison would read the rename as "fixed, and a new one appeared", and a
// recorded baseline would be invalidated by an edit to a registry field. So the
// class may move a finding up the page and nothing else.
func TestConsequenceOrdersPresentationOnly(t *testing.T) {
	t.Parallel()
	items := []evidence.Evidence{
		{RuleID: "A", File: "a.go", Line: 3, Message: "repeated"},
		{RuleID: "A", File: "a.go", Line: 9, Message: "repeated"},
		{RuleID: "B", File: "b.go", Line: 1, Message: "other"},
	}
	plain := evidence.Finalize(slices.Clone(items))

	classified := slices.Clone(items)
	classified[0].Consequence = evidence.ConsequenceHygiene
	classified[1].Consequence = evidence.ConsequenceHygiene
	classified[2].Consequence = evidence.ConsequenceSilentLoss
	got := evidence.Finalize(classified)

	if got[0].RuleID != "B" {
		t.Fatalf("silent loss did not sort first: %v", []string{got[0].RuleID, got[1].RuleID, got[2].RuleID})
	}
	byPrint := map[string]bool{}
	for _, e := range plain {
		byPrint[e.Fingerprint] = true
	}
	for _, e := range got {
		if !byPrint[e.Fingerprint] {
			t.Fatalf("classifying %s %s changed its fingerprint to %s", e.RuleID, e.File, e.Fingerprint)
		}
	}
}

func TestCompareClassifiesByFingerprint(t *testing.T) {
	base := evidence.Finalize([]evidence.Evidence{
		{RuleID: "A", File: "a.go", Message: "old"},
		{RuleID: "C", File: "c.go", Message: "gone"},
	})
	head := evidence.Finalize([]evidence.Evidence{
		{RuleID: "A", File: "a.go", Message: "old"},
		{RuleID: "B", File: "b.go", Message: "fresh"},
	})
	cmp := evidence.Compare(base, head)

	if len(cmp.New) != 1 || cmp.New[0].RuleID != "B" {
		t.Fatalf("new = %v, want exactly rule B", cmp.New)
	}
	if len(cmp.Preexisting) != 1 || cmp.Preexisting[0].RuleID != "A" {
		t.Fatalf("preexisting = %v, want exactly rule A", cmp.Preexisting)
	}
	if len(cmp.Fixed) != 1 || cmp.Fixed[0].RuleID != "C" {
		t.Fatalf("fixed = %v, want exactly rule C", cmp.Fixed)
	}
	if cmp.New[0].State != evidence.StateNew {
		t.Fatalf("head state = %q, want %q", cmp.New[0].State, evidence.StateNew)
	}
}

func TestAssignFingerprintsNumbersDuplicates(t *testing.T) {
	items := evidence.Finalize([]evidence.Evidence{
		{RuleID: "A", File: "a.go", Message: "same"},
		{RuleID: "A", File: "a.go", Message: "same"},
	})
	if items[0].Fingerprint == items[1].Fingerprint {
		t.Fatal("identical findings in the same file collapsed to one fingerprint")
	}
}

// TestPartialImprovementKeepsItsIdentity is the guard against a gate that
// punishes progress: a function still over a budget, but less over it than
// before, is the same finding and must stay pre-existing debt.
func TestPartialImprovementKeepsItsIdentity(t *testing.T) {
	t.Parallel()
	base := evidence.Finalize([]evidence.Evidence{{
		RuleID: "GH-CX-001", File: "lib/lib.go",
		Message: "Handle has cyclomatic complexity 30, over the budget of 25",
	}})
	head := evidence.Finalize([]evidence.Evidence{{
		RuleID: "GH-CX-001", File: "lib/lib.go",
		Message: "Handle has cyclomatic complexity 27, over the budget of 25",
	}})

	cmp := evidence.Compare(base, head)
	if len(cmp.New) != 0 {
		t.Fatalf("an improvement was reported as a new finding: %+v", cmp.New)
	}
	if len(cmp.Preexisting) != 1 {
		t.Fatalf("preexisting = %d, want 1: %+v", len(cmp.Preexisting), cmp)
	}
}

// TestDifferentSubjectsKeepDifferentIdentities is the other half: masking
// measurements must not merge findings that are about different code.
func TestDifferentSubjectsKeepDifferentIdentities(t *testing.T) {
	t.Parallel()
	items := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-CX-001", File: "lib/lib.go", Message: "Handle has cyclomatic complexity 30"},
		{RuleID: "GH-CX-001", File: "lib/lib.go", Message: "Serve has cyclomatic complexity 30"},
	})
	if items[0].Fingerprint == items[1].Fingerprint {
		t.Fatalf("two findings about different functions share a fingerprint: %+v", items)
	}
}

// TestIdentityIgnoresWhitespaceAndMeasurements pins what a finding's identity
// does and does not include, through the exported entry point that computes it.
func TestIdentityIgnoresWhitespaceAndMeasurements(t *testing.T) {
	t.Parallel()
	same := []string{
		"Handle has complexity 30, over the budget of 25",
		"Handle   has\tcomplexity 27,\nover the budget of 25",
		"  Handle has complexity 4, over the budget of 25  ",
	}
	first := evidence.Fingerprint("GH-CX-001", "lib/lib.go", "lib", same[0], 0)
	for _, message := range same[1:] {
		if got := evidence.Fingerprint("GH-CX-001", "lib/lib.go", "lib", message, 0); got != first {
			t.Fatalf("Fingerprint(%q) = %s, want %s", message, got, first)
		}
	}
	other := evidence.Fingerprint("GH-CX-001", "lib/lib.go", "lib",
		"Serve has complexity 30, over the budget of 25", 0)
	if other == first {
		t.Fatal("findings about different functions share an identity")
	}
}

// TestRealignKeepsAMovedFilesFindings is the unit behind the rename closure. A
// file is part of a finding's identity, so without realignment moving one makes
// every finding it carried new at head and fixed at base at the same time.
func TestRealignKeepsAMovedFilesFindings(t *testing.T) {
	t.Parallel()
	base := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-X", File: "lib/lib.go", Message: "unchecked error"},
		{RuleID: "GH-X", File: "lib/lib.go", Message: "unchecked error"},
		{RuleID: "GH-Y", File: "other/other.go", Message: "untouched"},
	})
	head := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-X", File: "pkg/lib.go", Message: "unchecked error"},
		{RuleID: "GH-X", File: "pkg/lib.go", Message: "unchecked error"},
		{RuleID: "GH-Y", File: "other/other.go", Message: "untouched"},
	})
	realigned := evidence.Realign(base, map[string]string{"lib/lib.go": "pkg/lib.go"})
	cmp := evidence.Compare(realigned, head)
	if len(cmp.New) != 0 || len(cmp.Fixed) != 0 {
		t.Fatalf("a move produced %d new and %d fixed findings, want none of either",
			len(cmp.New), len(cmp.Fixed))
	}
	if len(cmp.Preexisting) != 3 {
		t.Fatalf("pre-existing = %d, want 3", len(cmp.Preexisting))
	}
}

// TestRealignLeavesUnmovedFindingsNamedExactlyAsTheyWere is the guard: renaming
// one group must not renumber any other, or a rename anywhere renames
// everything.
func TestRealignLeavesUnmovedFindingsNamedExactlyAsTheyWere(t *testing.T) {
	t.Parallel()
	items := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-X", File: "lib/lib.go", Message: "moved"},
		{RuleID: "GH-Y", File: "other/other.go", Message: "stays"},
	})
	before := map[string]string{}
	for _, e := range items {
		before[e.File] = e.Fingerprint
	}
	realigned := evidence.Realign(items, map[string]string{"lib/lib.go": "pkg/lib.go"})
	for _, e := range realigned {
		if e.File != "other/other.go" {
			continue
		}
		if e.Fingerprint != before["other/other.go"] {
			t.Fatalf("realigning one file renamed an unrelated finding: %q vs %q",
				e.Fingerprint, before["other/other.go"])
		}
	}
}

// TestRealignWithoutRenamesIsTheIdentity keeps the common path free.
func TestRealignWithoutRenamesIsTheIdentity(t *testing.T) {
	t.Parallel()
	items := evidence.Finalize([]evidence.Evidence{{RuleID: "GH-X", File: "a.go", Message: "boom"}})
	if got := evidence.Realign(items, nil); len(got) != 1 || got[0].Fingerprint != items[0].Fingerprint {
		t.Fatal("realigning against no renames changed the set")
	}
	if got := evidence.Realign(items, map[string]string{"b.go": "c.go"}); got[0].Fingerprint != items[0].Fingerprint {
		t.Fatal("a rename of an unrelated file changed the set")
	}
}

// TestAStatedIdentitySurvivesAVolatileMessage is the mechanism behind the
// producers whose text moves between runs.
//
// A failing test prints a timestamp; a leak profile lists the goroutines it happened to
// find, in the order the runtime handed them over. Naming a finding by its
// description then renames it every run: ten test failures and eleven leaks were
// reported as introduced between two runs of one commit, and one flaky race
// arrived as new, fixed and pre-existing inside a single report.
func TestAStatedIdentitySurvivesAVolatileMessage(t *testing.T) {
	t.Parallel()
	first := evidence.Finalize([]evidence.Evidence{{
		RuleID: "GH-TEST-FAIL", Package: "example.com/x/lib",
		Identity: "GH-TEST-FAIL example.com/x/lib TestThing",
		Message:  "test TestThing failed: 2026/08/27 14:37:27 fetching profile key abc",
	}})
	second := evidence.Finalize([]evidence.Evidence{{
		RuleID: "GH-TEST-FAIL", Package: "example.com/x/lib",
		Identity: "GH-TEST-FAIL example.com/x/lib TestThing",
		Message:  "test TestThing failed: 2026/08/27 15:02:11 fetching profile key zzz",
	}})
	if first[0].Fingerprint != second[0].Fingerprint {
		t.Fatalf("the same failure was named twice: %q vs %q",
			first[0].Fingerprint, second[0].Fingerprint)
	}
}

// TestAStatedIdentityStillTellsFindingsApart is the false-positive guard: an
// identity that collapsed two different findings would hide one of them.
func TestAStatedIdentityStillTellsFindingsApart(t *testing.T) {
	t.Parallel()
	items := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-TEST-FAIL", Package: "p", Identity: "GH-TEST-FAIL p TestOne", Message: "one"},
		{RuleID: "GH-TEST-FAIL", Package: "p", Identity: "GH-TEST-FAIL p TestTwo", Message: "two"},
	})
	if items[0].Fingerprint == items[1].Fingerprint {
		t.Fatal("two different tests were given one identity")
	}
}

// TestAnAbsentIdentityStillFallsBackToTheMessage keeps every scanner that has no
// identity of its own working exactly as it did.
func TestAnAbsentIdentityStillFallsBackToTheMessage(t *testing.T) {
	t.Parallel()
	stated := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-X", File: "a.go", Message: "budget exceeded at 30"},
	})
	moved := evidence.Finalize([]evidence.Evidence{
		{RuleID: "GH-X", File: "a.go", Message: "budget exceeded at 27"},
	})
	if stated[0].Fingerprint != moved[0].Fingerprint {
		t.Fatal("a measurement inside a message changed the identity it is masked out of")
	}
}
