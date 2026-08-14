package analyze_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

func scan(t *testing.T, name, src string) []analyze.Finding {
	t.Helper()
	findings, err := analyze.ScanFile(name, []byte(src))
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", name, err)
	}
	return findings
}

func ruleIDs(findings []analyze.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}

func contains(ids []string, want string) bool {
	return slices.Contains(ids, want)
}

func TestSuppressionDirectivesAreDetectedInComments(t *testing.T) {
	src := `package p

func F() int {
	//nolint:errcheck
	//lint:ignore SA1000 because
	return 1
}
`
	ids := ruleIDs(scan(t, "p.go", src))
	if !contains(ids, policy.RuleSuppressNolint) {
		t.Fatalf("missing %s in %v", policy.RuleSuppressNolint, ids)
	}
	if !contains(ids, policy.RuleSuppressStaticcheck) {
		t.Fatalf("missing %s in %v", policy.RuleSuppressStaticcheck, ids)
	}
}

func TestSuppressionTokensInStringLiteralsAreIgnored(t *testing.T) {
	src := `package p

const (
	a = "//nolint:errcheck"
	b = "//lint:ignore SA1000 reason"
)
`
	ids := ruleIDs(scan(t, "p.go", src))
	if contains(ids, policy.RuleSuppressNolint) || contains(ids, policy.RuleSuppressStaticcheck) {
		t.Fatalf("string literals were treated as suppression directives: %v", ids)
	}
}

func TestEmDashIsDetectedOnlyInComments(t *testing.T) {
	commented := "package p\n\n// a comment with an \u2014 em dash\nfunc F() {}\n"
	if ids := ruleIDs(scan(t, "p.go", commented)); !contains(ids, policy.RuleCommentEmDash) {
		t.Fatalf("em dash in a comment was not detected: %v", ids)
	}

	literal := "package p\n\nconst S = \"an \u2014 em dash inside a string\"\n"
	if ids := ruleIDs(scan(t, "p.go", literal)); contains(ids, policy.RuleCommentEmDash) {
		t.Fatalf("em dash inside a string literal was flagged: %v", ids)
	}
}

func TestOversizedDocCommentsAreGraded(t *testing.T) {
	build := func(lines int) string {
		var b strings.Builder
		b.WriteString("package p\n\n")
		for range lines {
			b.WriteString("// filler documentation line\n")
		}
		b.WriteString("func F() {}\n")
		return b.String()
	}

	advisory := scan(t, "p.go", build(20))
	if len(advisory) != 1 || advisory[0].RuleID != policy.RuleCommentSize || !advisory[0].Advisory {
		t.Fatalf("20-line doc comment: got %+v, want one advisory %s", advisory, policy.RuleCommentSize)
	}
	required := scan(t, "p.go", build(40))
	if len(required) != 1 || required[0].Advisory {
		t.Fatalf("40-line doc comment: got %+v, want one required finding", required)
	}
	if fine := scan(t, "p.go", build(5)); len(fine) != 0 {
		t.Fatalf("5-line doc comment was flagged: %+v", fine)
	}
}

func TestCommentRestatementHeuristic(t *testing.T) {
	restating := `package p

func F(counter int) int {
	// increment counter value
	counter = counter + value(counter)
	return counter
}

func value(int) int { return 1 }
`
	if ids := ruleIDs(scan(t, "p.go", restating)); !contains(ids, policy.RuleCommentRestates) {
		t.Fatalf("restating comment was not detected: %v", ids)
	}

	informative := `package p

func F(counter int) int {
	// The protocol requires a monotonic sequence, so wrapping is a defect.
	counter = counter + 1
	return counter
}
`
	if ids := ruleIDs(scan(t, "p.go", informative)); contains(ids, policy.RuleCommentRestates) {
		t.Fatalf("informative comment was flagged: %v", ids)
	}
}

func TestDocCommentsAreNeverRestatements(t *testing.T) {
	src := `package p

// Counter returns counter.
func Counter(counter int) int { return counter }
`
	if ids := ruleIDs(scan(t, "p.go", src)); contains(ids, policy.RuleCommentRestates) {
		t.Fatalf("doc comment was flagged as a restatement: %v", ids)
	}
}

func TestNativeChecksSkipNonTestFilesForTestRules(t *testing.T) {
	src := `package p

import "testing"

func TestSomething(t *testing.T) {}
`
	if ids := ruleIDs(scan(t, "p.go", src)); contains(ids, policy.RuleTestEmpty) {
		t.Fatalf("test rules fired on a non-test file: %v", ids)
	}
}

func TestTestEffectivenessRules(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "empty body",
			src:  "package p\n\nimport \"testing\"\n\nfunc TestEmpty(t *testing.T) {}\n",
			want: policy.RuleTestEmpty,
		},
		{
			name: "unconditional skip",
			src:  "package p\n\nimport \"testing\"\n\nfunc TestSkip(t *testing.T) {\n\tt.Skip(\"later\")\n\tif 1 == 2 {\n\t\tt.Fatal(\"x\")\n\t}\n}\n",
			want: policy.RuleTestSkipped,
		},
		{
			name: "no observation",
			src:  "package p\n\nimport \"testing\"\n\nfunc TestNothing(t *testing.T) {\n\tsubject()\n}\n\nfunc subject() {}\n",
			want: policy.RuleTestNoAssertion,
		},
		{
			name: "tautology",
			src:  "package p\n\nimport \"testing\"\n\nfunc TestTaut(t *testing.T) {\n\tif 1 == 1 {\n\t\tt.Fatal(\"impossible\")\n\t}\n}\n",
			want: policy.RuleTestTautology,
		},
		{
			name: "ignored error",
			src:  "package p\n\nimport \"testing\"\n\nfunc TestIgnored(t *testing.T) {\n\tv, _ := subject()\n\tif v != 1 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n\nfunc subject() (int, error) { return 1, nil }\n",
			want: policy.RuleTestIgnoredError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := ruleIDs(scan(t, "p_test.go", tc.src))
			if !contains(ids, tc.want) {
				t.Fatalf("missing %s in %v", tc.want, ids)
			}
		})
	}
}

func TestEffectiveTestIsNotFlagged(t *testing.T) {
	src := `package p

import "testing"

func TestGood(t *testing.T) {
	got := subject()
	if got != 2 {
		t.Fatalf("subject() = %d, want 2", got)
	}
}

func subject() int { return 2 }
`
	for _, f := range scan(t, "p_test.go", src) {
		t.Fatalf("effective test produced a finding: %+v", f)
	}
}

func TestUnparsableFileYieldsNoFindings(t *testing.T) {
	findings := scan(t, "broken.go", "package p\n\nfunc F( {\n")
	if len(findings) != 0 {
		t.Fatalf("unparsable file produced findings: %+v", findings)
	}
}

func writeSource(t *testing.T, dir, name, src string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}
