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

func TestSuppressionDirectivesAreDetectedInComments(t *testing.T) {
	src := `package p

func F() int {
	//nolint:errcheck
	//lint:ignore SA1000 because
	return 1
}
`
	ids := ruleIDs(scan(t, "p.go", src))
	if !slices.Contains(ids, policy.RuleSuppressNolint) {
		t.Fatalf("missing %s in %v", policy.RuleSuppressNolint, ids)
	}
	if !slices.Contains(ids, policy.RuleSuppressStaticcheck) {
		t.Fatalf("missing %s in %v", policy.RuleSuppressStaticcheck, ids)
	}
}

func TestSuppressionTokensInStringLiteralsAreIgnored(t *testing.T) {
	src := `package p

const (
	a = "//nolint:errcheck"
	b = "//lint:ignore SA1000 reason"
	c = "// #nosec G304"
	d = "//revive:disable"
)
`
	ids := ruleIDs(scan(t, "p.go", src))
	for _, rule := range []string{
		policy.RuleSuppressNolint, policy.RuleSuppressStaticcheck,
		policy.RuleSuppressNosec, policy.RuleSuppressRevive,
	} {
		if slices.Contains(ids, rule) {
			t.Fatalf("a string literal was treated as a %s suppression: %v", rule, ids)
		}
	}
}

func TestEverySuppressionDialectIsDetected(t *testing.T) {
	cases := map[string]string{
		policy.RuleSuppressNosec:       "// #nosec G204\n",
		policy.RuleSuppressRevive:      "//revive:disable-next-line:atomic\n",
		policy.RuleSuppressStaticcheck: "//lint:file-ignore SA1000 legacy\n",
	}
	for rule, comment := range cases {
		src := "package p\n\n" + comment + "func F() int { return 1 }\n"
		if ids := ruleIDs(scan(t, "p.go", src)); !slices.Contains(ids, rule) {
			t.Fatalf("comment %q did not produce %s: %v", comment, rule, ids)
		}
	}
}

func TestEmDashIsDetectedOnlyInComments(t *testing.T) {
	commented := "package p\n\n// a comment with an \u2014 em dash\nfunc F() {}\n"
	if ids := ruleIDs(scan(t, "p.go", commented)); !slices.Contains(ids, policy.RuleCommentEmDash) {
		t.Fatalf("em dash in a comment was not detected: %v", ids)
	}

	literal := "package p\n\nconst S = \"an \u2014 em dash inside a string\"\n"
	if ids := ruleIDs(scan(t, "p.go", literal)); slices.Contains(ids, policy.RuleCommentEmDash) {
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
	if ids := ruleIDs(scan(t, "p.go", restating)); !slices.Contains(ids, policy.RuleCommentRestates) {
		t.Fatalf("restating comment was not detected: %v", ids)
	}

	informative := `package p

func F(counter int) int {
	// The protocol requires a monotonic sequence, so wrapping is a defect.
	counter = counter + 1
	return counter
}
`
	if ids := ruleIDs(scan(t, "p.go", informative)); slices.Contains(ids, policy.RuleCommentRestates) {
		t.Fatalf("informative comment was flagged: %v", ids)
	}
}

func TestDocCommentsAreNeverRestatements(t *testing.T) {
	src := `package p

// Counter returns counter.
func Counter(counter int) int { return counter }
`
	if ids := ruleIDs(scan(t, "p.go", src)); slices.Contains(ids, policy.RuleCommentRestates) {
		t.Fatalf("doc comment was flagged as a restatement: %v", ids)
	}
}

func TestNativeChecksSkipNonTestFilesForTestRules(t *testing.T) {
	src := `package p

import "testing"

func TestSomething(t *testing.T) {}
`
	if ids := ruleIDs(scan(t, "p.go", src)); slices.Contains(ids, policy.RuleTestEmpty) {
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
			if !slices.Contains(ids, tc.want) {
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

// TestWeakeningReportsADeletedTestOnlyWhenThePackageLosesStrength pins both
// halves of the rule: a suite that comes out of a change able to fail as often
// as it went in has not been weakened, however many test names moved.
func TestWeakeningReportsADeletedTestOnlyWhenThePackageLosesStrength(t *testing.T) {
	t.Parallel()
	base := map[string]analyze.TestShape{
		"lib:TestOldName": {Key: "lib:TestOldName", Package: "lib", File: "lib/lib_test.go",
			Name: "TestOldName", Line: 10, Assertions: 3},
	}
	renamed := map[string]analyze.TestShape{
		"lib:TestNewName": {Key: "lib:TestNewName", Package: "lib", File: "lib/lib_test.go",
			Name: "TestNewName", Line: 10, Assertions: 3},
	}
	survives := func(string) bool { return true }

	if found := analyze.WeakeningFindings(base, renamed, survives); len(found) != 0 {
		t.Fatalf("a rename was reported as weakening: %+v", found)
	}

	weakened := map[string]analyze.TestShape{
		"lib:TestNewName": {Key: "lib:TestNewName", Package: "lib", File: "lib/lib_test.go",
			Name: "TestNewName", Line: 10, Assertions: 1},
	}
	found := analyze.WeakeningFindings(base, weakened, survives)
	if len(found) != 1 || found[0].RuleID != policy.RuleTestDeleted {
		t.Fatalf("a deletion that cost the package assertions was not reported: %+v", found)
	}
}

func TestForwardingLayerIsReported(t *testing.T) {
	t.Parallel()
	const src = `package lib

// Store keeps values.
type Store struct{ inner *Store }

// Put forwards to the inner store and adds nothing.
func (s *Store) Put(key string, value int) error {
	return s.inner.Put(key, value)
}

// Checked adds a decision, so it is not a forwarding layer.
func (s *Store) Checked(key string, value int) error {
	if value < 0 {
		return nil
	}
	return s.inner.Put(key, value)
}
`
	found := scan(t, "lib/store.go", src)
	forwarding := findingsFor(found, policy.RuleForwardingLayer)
	if len(forwarding) != 1 {
		t.Fatalf("forwarding findings = %d, want 1: %+v", len(forwarding), found)
	}
	if !strings.Contains(forwarding[0].Message, "Put") {
		t.Fatalf("the finding does not name the wrapper: %q", forwarding[0].Message)
	}
	if !forwarding[0].Advisory {
		t.Fatal("a new simplicity rule must enter as advisory")
	}
}

func TestSoleImplementationIsReportedOnlyForUnexportedInterfaces(t *testing.T) {
	t.Parallel()
	const src = `package lib

// Reader is the package's contract with its callers.
type Reader interface {
	Read() int
}

type store interface {
	Get() int
	Put(int)
}

// Memory is the only type implementing store.
type Memory struct{}

// Get returns a value.
func (Memory) Get() int { return 1 }

// Put stores a value.
func (Memory) Put(int) {}

// Read satisfies Reader.
func (Memory) Read() int { return 1 }
`
	found := scan(t, "lib/store.go", src)
	sole := findingsFor(found, policy.RuleSoleImplementation)
	if len(sole) != 1 {
		t.Fatalf("sole-implementation findings = %d, want 1 (unexported only): %+v", len(sole), found)
	}
	if !strings.Contains(sole[0].Message, "store") {
		t.Fatalf("the finding does not name the interface: %q", sole[0].Message)
	}
}

func findingsFor(items []analyze.Finding, ruleID string) []analyze.Finding {
	var out []analyze.Finding
	for _, f := range items {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// TestTableDrivenTestWithAHelperIsNotReported is the false-positive guard the
// corpus asked for: assertions in a shared helper are the idiomatic Go form,
// and a required rule must not fire where the scan cannot see.
func TestTableDrivenTestWithAHelperIsNotReported(t *testing.T) {
	t.Parallel()
	const src = `package lib

import "testing"

type routeCase struct{ name string }

func TestRoutes(t *testing.T) {
	cases := []routeCase{{name: "root"}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkRoute(t, c)
		})
	}
}

func TestObservesNothing(t *testing.T) {
	compute()
}

func checkRoute(t *testing.T, c routeCase) {
	if c.name == "" {
		t.Fatal("empty name")
	}
}

func compute() {}
`
	found := findingsFor(scan(t, "lib/route_test.go", src), policy.RuleTestNoAssertion)
	if len(found) != 1 {
		t.Fatalf("no-assertion findings = %d, want 1 (only the test that observes nothing): %+v",
			len(found), found)
	}
	if !strings.Contains(found[0].Message, "TestObservesNothing") {
		t.Fatalf("the wrong test was reported: %q", found[0].Message)
	}
}

// TestNetworkRulesDoNotApplyToTests keeps a production-path rule off test code,
// where a local server and no caller deadline make it meaningless.
func TestNetworkRulesDoNotApplyToTests(t *testing.T) {
	t.Parallel()
	const src = `package lib

import (
	"net/http"
	"testing"
)

func TestFetch(t *testing.T) {
	resp, err := http.Get("http://127.0.0.1:1/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
}
`
	found, err := analyze.ScanFileWithOptions("lib/fetch_test.go", []byte(src), analyze.Options{Network: true})
	if err != nil {
		t.Fatalf("ScanFileWithOptions: %v", err)
	}
	if hits := findingsFor(found, policy.RuleRequestContext); len(hits) != 0 {
		t.Fatalf("a network rule fired on a test file: %+v", hits)
	}
}

// TestDocSizeSparesDocumentationThatEarnsItsLength is the false-positive guard
// for the comment budget: the rule exists for an essay above a trivial
// function, not for a package introduction or a long doc on intricate code.
func TestDocSizeSparesDocumentationThatEarnsItsLength(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("// documentation line\n", 40)
	body := strings.Repeat("\tprintln(1)\n", 50)
	src := "// Package lib is documented at length, as a package introduction should be.\n" +
		long + "package lib\n\n" +
		long + "func Intricate() {\n" + body + "}\n\n" +
		long + "func Trivial() {\n\treturn\n}\n"

	found := findingsFor(scan(t, "lib/lib.go", src), policy.RuleCommentSize)
	var blocking []analyze.Finding
	for _, f := range found {
		if !f.Advisory {
			blocking = append(blocking, f)
		}
	}
	if len(blocking) != 1 {
		t.Fatalf("blocking comment-size findings = %d, want 1 (the essay over the trivial function): %+v",
			len(blocking), found)
	}
	if !strings.Contains(blocking[0].Message, "Trivial") {
		t.Fatalf("the wrong subject was reported: %q", blocking[0].Message)
	}
}
