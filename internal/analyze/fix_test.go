package analyze_test

import (
	"go/format"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// emDash is written as an escape so this file, like every file in the
// repository, contains no U+2014 of its own.
const emDash = "\u2014"

// emDashFixture puts the forbidden rune in three comments and in one string
// literal. The literal is the whole point: the subject repository that produced
// this requirement carries client-facing copy in its literals, and a fixer that
// rewrites those is worse than no fixer at all.
func emDashFixture() string {
	return "package lib\n" +
		"\n" +
		"// Answer returns 42 " + emDash + " the canonical answer.\n" +
		"func Answer() int {\n" +
		"\t// a note " + emDash + " with a second " + emDash + " dash\n" +
		"\treturn 42\n" +
		"}\n" +
		"\n" +
		"/* Motto is client-facing copy " + emDash + " it is prose. */\n" +
		"const Motto = \"we ship " + emDash + " carefully\"\n"
}

func TestEmDashFixerRewritesCommentsAndNotLiterals(t *testing.T) {
	t.Parallel()
	fixer, ok := analyze.FixerFor(policy.RuleCommentEmDash)
	if !ok {
		t.Fatalf("no fixer registered for %s", policy.RuleCommentEmDash)
	}
	src := emDashFixture()
	out, replaced, parsed := fixer.Rewrite("lib/lib.go", []byte(src))
	if !parsed {
		t.Fatal("the fixture did not parse")
	}
	if want := strings.Count(src, emDash) - 1; replaced != want {
		t.Fatalf("replaced %d occurrences, want %d (every one but the literal)", replaced, want)
	}
	fixed := string(out)
	if strings.Count(fixed, emDash) != 1 {
		t.Fatalf("the rewrite did not leave exactly the literal's dash:\n%s", fixed)
	}
	if !strings.Contains(fixed, "const Motto = \"we ship "+emDash+" carefully\"") {
		t.Fatalf("the string literal was rewritten:\n%s", fixed)
	}
	if strings.Contains(fixed, "// Answer returns 42 "+emDash) ||
		!strings.Contains(fixed, "// Answer returns 42 - the canonical answer.") {
		t.Fatalf("a line comment was not rewritten:\n%s", fixed)
	}
	if !strings.Contains(fixed, "/* Motto is client-facing copy - it is prose. */") {
		t.Fatalf("a block comment was not rewritten:\n%s", fixed)
	}

	if _, err := parser.ParseFile(token.NewFileSet(), "lib/lib.go", out, parser.ParseComments); err != nil {
		t.Fatalf("the rewritten file does not parse: %v\n%s", err, fixed)
	}
	canonical, err := format.Source(out)
	if err != nil {
		t.Fatalf("formatting the rewritten file: %v", err)
	}
	if string(canonical) != fixed {
		t.Fatalf("the rewrite left the file un-gofmt-ed:\n%s", fixed)
	}
}

// TestEmDashFixerClosesTheFindingItClaimsTo is the loop that matters: what the
// scanner reports, the fixer removes, and nothing else changes.
func TestEmDashFixerClosesTheFindingItClaimsTo(t *testing.T) {
	t.Parallel()
	src := emDashFixture()
	before := scan(t, "lib/lib.go", src)
	if countRule(before, policy.RuleCommentEmDash) == 0 {
		t.Fatal("the fixture does not trip the rule it exists to exercise")
	}
	fixer, _ := analyze.FixerFor(policy.RuleCommentEmDash)
	out, _, _ := fixer.Rewrite("lib/lib.go", []byte(src))
	after := scan(t, "lib/lib.go", string(out))
	if n := countRule(after, policy.RuleCommentEmDash); n != 0 {
		t.Fatalf("%d em dash finding(s) survived the fixer", n)
	}
	if len(after) != len(before)-countRule(before, policy.RuleCommentEmDash) {
		t.Fatalf("the fixer changed some other finding: before %d, after %d", len(before), len(after))
	}
}

func TestEmDashFixerLeavesUntouchedFilesAlone(t *testing.T) {
	t.Parallel()
	fixer, _ := analyze.FixerFor(policy.RuleCommentEmDash)
	src := []byte("package lib\n\n// Answer is plain prose.\nfunc Answer() int { return 42 }\n")
	out, replaced, parsed := fixer.Rewrite("lib/lib.go", src)
	if !parsed || replaced != 0 || string(out) != string(src) {
		t.Fatalf("a clean file was rewritten: replaced=%d parsed=%t", replaced, parsed)
	}
}

// TestEmDashFixerRefusesWhatItCannotParse keeps the fixer inside its evidence.
// A file that does not parse is the compile check's finding, and rewriting one
// would mean guessing where its comments are.
func TestEmDashFixerRefusesWhatItCannotParse(t *testing.T) {
	t.Parallel()
	fixer, _ := analyze.FixerFor(policy.RuleCommentEmDash)
	_, _, parsed := fixer.Rewrite("lib/broken.go", []byte("package lib\nfunc (\n"))
	if parsed {
		t.Fatal("the fixer claimed to have read a file that does not parse")
	}
}

func TestFixerRegistryOnlyClaimsRulesThatExist(t *testing.T) {
	t.Parallel()
	fixers := analyze.Fixers()
	if len(fixers) == 0 {
		t.Fatal("no fixers are registered")
	}
	for _, f := range fixers {
		if _, ok := policy.Lookup(f.RuleID); !ok {
			t.Fatalf("fixer claims rule %q, which is not in the registry", f.RuleID)
		}
		if f.Summary == "" || f.Rewrite == nil {
			t.Fatalf("fixer %s is incomplete", f.RuleID)
		}
	}
	if _, ok := analyze.FixerFor("GH-NOT-A-RULE"); ok {
		t.Fatal("FixerFor invented a fixer for an unknown rule")
	}
}

func countRule(findings []analyze.Finding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}
