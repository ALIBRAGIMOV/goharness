package analyze

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestSortFindingsIsATotalOrderOverEveryKey pins the comparator that every
// scanner's output passes through. The order is what makes two runs of one
// commit produce byte-identical reports, so each key has to be consulted, and
// each has to be consulted only when the ones before it tie. The input below is
// the wanted order reversed, so a comparator that answers "equal" too early
// leaves the pairs where the stable sort found them and the test says so.
func TestSortFindingsIsATotalOrderOverEveryKey(t *testing.T) {
	t.Parallel()
	want := []Finding{
		{RuleID: "GH-A-001", File: "z.go", Package: "p", Line: 1, Column: 1},
		{RuleID: "GH-B-001", File: "a.go", Package: "z", Line: 9, Column: 1},
		{RuleID: "GH-B-001", File: "a.go", Package: "z", Line: 9, Column: 4},
		{RuleID: "GH-B-001", File: "b.go", Package: "a", Line: 2, Column: 1},
		{RuleID: "GH-B-001", File: "b.go", Package: "a", Line: 30, Column: 1},
		{RuleID: "GH-B-001", File: "b.go", Package: "b", Line: 3, Column: 1},
	}
	got := slices.Clone(want)
	slices.Reverse(got)
	sortFindings(got)

	if len(got) != len(want) {
		t.Fatalf("sorting changed the length: %d, want %d", len(got), len(want))
	}
	for i := range want {
		if sortKey(got[i]) != sortKey(want[i]) {
			t.Fatalf("position %d holds %s, want %s\nfull order:\n%s",
				i, sortKey(got[i]), sortKey(want[i]), keys(got))
		}
	}
}

func sortKey(f Finding) string {
	return fmt.Sprintf("%s %s %s %d:%d", f.RuleID, f.File, f.Package, f.Line, f.Column)
}

func keys(findings []Finding) string {
	var out strings.Builder
	for _, f := range findings {
		out.WriteString("  " + sortKey(f) + "\n")
	}
	return out.String()
}
