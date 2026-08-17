package evidence_test

import (
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
