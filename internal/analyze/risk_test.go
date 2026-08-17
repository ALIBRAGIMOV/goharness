package analyze_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

func scanWith(t *testing.T, name, src string, opts analyze.Options) []analyze.Finding {
	t.Helper()
	findings, err := analyze.ScanFileWithOptions(name, []byte(src), opts)
	if err != nil {
		t.Fatalf("ScanFileWithOptions(%s): %v", name, err)
	}
	return findings
}

func TestGoroutineLifecycleNeedsAVisibleStopSignal(t *testing.T) {
	t.Parallel()
	unbounded := `package p

import "context"

func Start(ctx context.Context) {
	go func() {
		for {
			work()
		}
	}()
}

func work() {}
`
	ids := ruleIDs(scanWith(t, "p.go", unbounded, analyze.Options{Concurrency: true}))
	if !slices.Contains(ids, policy.RuleGoroutineLifetime) {
		t.Fatalf("a goroutine ignoring the caller's context was not reported: %v", ids)
	}

	bounded := `package p

import "context"

func Start(ctx context.Context) {
	go func() {
		<-ctx.Done()
	}()
}
`
	ids = ruleIDs(scanWith(t, "p.go", bounded, analyze.Options{Concurrency: true}))
	if slices.Contains(ids, policy.RuleGoroutineLifetime) {
		t.Fatalf("a goroutine that watches the context was reported: %v", ids)
	}
}

func TestGoroutineLifecycleStaysQuietWithoutAContext(t *testing.T) {
	t.Parallel()
	src := `package p

func Start() {
	go work()
}

func work() {}
`
	ids := ruleIDs(scanWith(t, "p.go", src, analyze.Options{Concurrency: true}))
	if slices.Contains(ids, policy.RuleGoroutineLifetime) {
		t.Fatalf("the rule fired where no stop mechanism was in scope: %v", ids)
	}
}

func TestBoundedResourceScans(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "goroutine per iteration",
			src:  "package p\n\nfunc F(items []int) {\n\tfor range items {\n\t\tgo work()\n\t}\n}\n\nfunc work() {}\n",
			want: policy.RuleGoroutineInLoop,
		},
		{
			name: "timer in loop",
			src:  "package p\n\nimport \"time\"\n\nfunc F(n int) {\n\tfor range n {\n\t\t<-time.After(time.Second)\n\t}\n}\n",
			want: policy.RuleTimerInLoop,
		},
		{
			name: "variable channel buffer",
			src:  "package p\n\nfunc F(n int) chan int {\n\treturn make(chan int, n)\n}\n",
			want: policy.RuleVariableChanBuf,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ids := ruleIDs(scanWith(t, "p.go", tc.src, analyze.Options{Concurrency: true}))
			if !slices.Contains(ids, tc.want) {
				t.Fatalf("missing %s in %v", tc.want, ids)
			}
		})
	}
}

func TestBoundedLoopsAreNotReported(t *testing.T) {
	t.Parallel()
	src := `package p

func F(items []int, tokens chan struct{}) {
	for range items {
		tokens <- struct{}{}
		go work()
	}
}

func work() {}
`
	ids := ruleIDs(scanWith(t, "p.go", src, analyze.Options{Concurrency: true}))
	if slices.Contains(ids, policy.RuleGoroutineInLoop) {
		t.Fatalf("a token-bounded loop was reported: %v", ids)
	}
}

func TestConstantChannelBufferIsStatic(t *testing.T) {
	t.Parallel()
	src := `package p

const size = 2

func F() chan int {
	return make(chan int, size)
}
`
	ids := ruleIDs(scanWith(t, "p.go", src, analyze.Options{Concurrency: true}))
	if slices.Contains(ids, policy.RuleVariableChanBuf) {
		t.Fatalf("a constant-sized buffer was reported as variable: %v", ids)
	}
}

func TestNetworkScans(t *testing.T) {
	t.Parallel()
	src := `package p

import "net/http"

func F() {
	client := &http.Client{}
	_ = client
	_, _ = http.Get("http://example.invalid")
}
`
	ids := ruleIDs(scanWith(t, "p.go", src, analyze.Options{Network: true}))
	for _, want := range []string{policy.RuleClientTimeout, policy.RuleRequestContext} {
		if !slices.Contains(ids, want) {
			t.Fatalf("missing %s in %v", want, ids)
		}
	}
}

func TestClientWithATimeoutIsNotReported(t *testing.T) {
	t.Parallel()
	src := `package p

import (
	"net/http"
	"time"
)

func F() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}
`
	ids := ruleIDs(scanWith(t, "p.go", src, analyze.Options{Network: true}))
	if slices.Contains(ids, policy.RuleClientTimeout) {
		t.Fatalf("a client with a timeout was reported: %v", ids)
	}
}

func TestTransactionPairing(t *testing.T) {
	t.Parallel()
	unresolved := `package p

import "database/sql"

func F(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec("insert into t values (1)")
	return err
}
`
	ids := ruleIDs(scanWith(t, "p.go", unresolved, analyze.Options{Persistence: true}))
	if !slices.Contains(ids, policy.RuleTxNotResolved) {
		t.Fatalf("an unresolved transaction was not reported: %v", ids)
	}

	resolved := `package p

import "database/sql"

func F(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec("insert into t values (1)"); err != nil {
		return err
	}
	return tx.Commit()
}
`
	ids = ruleIDs(scanWith(t, "p.go", resolved, analyze.Options{Persistence: true}))
	if slices.Contains(ids, policy.RuleTxNotResolved) {
		t.Fatalf("a committed transaction was reported: %v", ids)
	}
}

func TestBannedPackageNames(t *testing.T) {
	t.Parallel()
	ids := ruleIDs(scanWith(t, "internal/util/util.go", "package util\n\nfunc F() {}\n", analyze.Options{}))
	if !slices.Contains(ids, policy.RuleBannedPackageName) {
		t.Fatalf("a package named util was not reported: %v", ids)
	}
	ids = ruleIDs(scanWith(t, "internal/policy/policy.go", "package policy\n\nfunc F() {}\n", analyze.Options{}))
	if slices.Contains(ids, policy.RuleBannedPackageName) {
		t.Fatalf("a meaningful package name was reported: %v", ids)
	}
}

func TestForbiddenImportsComeFromConfiguration(t *testing.T) {
	t.Parallel()
	src := `package report

import _ "example.com/m/internal/tool"

func F() {}
`
	opts := analyze.Options{Architecture: analyze.ArchitectureRules{
		ModulePath: "example.com/m",
		ForbiddenImports: []analyze.ImportRule{
			{From: "internal/report", Deny: "internal/tool", Reason: "reports must not run tools"},
		},
	}}
	findings := scanWith(t, "internal/report/report.go", src, opts)
	if !slices.Contains(ruleIDs(findings), policy.RuleForbiddenImport) {
		t.Fatalf("the declared direction was not enforced: %v", ruleIDs(findings))
	}
	if !strings.Contains(findings[0].Message, "reports must not run tools") {
		t.Fatalf("the configured reason is missing: %q", findings[0].Message)
	}
	if got := scanWith(t, "internal/report/report.go", src, analyze.Options{}); len(got) != 0 {
		t.Fatalf("an import was forbidden without configuration: %+v", got)
	}
}

func TestComplexityAndNestingBudgets(t *testing.T) {
	t.Parallel()
	var deep strings.Builder
	deep.WriteString("package p\n\nfunc F(a, b, c, d, e, f int) int {\n")
	for i := range 6 {
		deep.WriteString(strings.Repeat("\t", i+1) + "if a > " + string(rune('0'+i)) + " {\n")
	}
	deep.WriteString(strings.Repeat("\t", 7) + "return 1\n")
	for i := 6; i > 0; i-- {
		deep.WriteString(strings.Repeat("\t", i) + "}\n")
	}
	deep.WriteString("\treturn 0\n}\n")

	metrics := metricsFor(t, "p.go", deep.String())
	ids := ruleIDs(analyze.SimplicityFindings(metrics))
	if !slices.Contains(ids, policy.RuleNesting) {
		t.Fatalf("a six-level nest was not reported: %v", ids)
	}
}

func TestMaintainabilityDeltaNeedsBothSnapshots(t *testing.T) {
	t.Parallel()
	base := metricsFor(t, "p.go", "package p\n\n// F does one thing.\nfunc F(a int) int {\n\treturn a\n}\n")

	var grown strings.Builder
	grown.WriteString("package p\n\n// F does one thing.\nfunc F(a int) int {\n")
	for i := range 12 {
		grown.WriteString("\tif a == " + string(rune('0'+i%10)) + " {\n\t\treturn " + string(rune('0'+i%10)) + "\n\t}\n")
	}
	grown.WriteString("\treturn a\n}\n")
	head := metricsFor(t, "p.go", grown.String())

	ids := ruleIDs(analyze.MaintainabilityFindings(base, head))
	if !slices.Contains(ids, policy.RuleComplexityDelta) {
		t.Fatalf("a large complexity rise was not reported: %v", ids)
	}
	if got := analyze.MaintainabilityFindings(base, base); len(got) != 0 {
		t.Fatalf("an unchanged snapshot produced findings: %+v", got)
	}
}

func metricsFor(t *testing.T, name, src string) analyze.Metrics {
	t.Helper()
	dir := t.TempDir()
	writeSource(t, dir, name, src)
	metrics, err := analyze.ComputeMetrics(context.Background(), dir, []string{name})
	if err != nil {
		t.Fatalf("ComputeMetrics: %v", err)
	}
	return metrics
}

func TestMutantGenerationIsDeterministic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package p

// Classify reports a grade.
func Classify(score int) string {
	if score >= 50 {
		return "pass"
	}
	return "fail"
}
`
	writeSource(t, dir, "p.go", src)
	targets := []analyze.FunctionTarget{{Package: ".", File: "p.go", Name: "Classify"}}

	first, err := analyze.GenerateMutants(context.Background(), dir, targets, 16)
	if err != nil {
		t.Fatalf("GenerateMutants: %v", err)
	}
	second, err := analyze.GenerateMutants(context.Background(), dir, targets, 16)
	if err != nil {
		t.Fatalf("GenerateMutants: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("no mutants were generated for a function with a comparison")
	}
	if !slices.EqualFunc(first, second, func(a, b analyze.Mutant) bool {
		return a.Description == b.Description && string(a.Source) == string(b.Source)
	}) {
		t.Fatal("mutant generation is not deterministic")
	}
	if !strings.Contains(string(first[0].Source), "score < 50") {
		t.Fatalf("the first mutant did not flip the comparison:\n%s", first[0].Source)
	}
}

func TestMutantsRespectTheBudget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var src strings.Builder
	src.WriteString("package p\n\n// F branches many times.\nfunc F(a int) int {\n")
	for i := range 30 {
		src.WriteString("\tif a > " + string(rune('0'+i%10)) + " {\n\t\treturn " + string(rune('0'+i%10)) + "\n\t}\n")
	}
	src.WriteString("\treturn 0\n}\n")
	writeSource(t, dir, "p.go", src.String())

	mutants, err := analyze.GenerateMutants(context.Background(), dir,
		[]analyze.FunctionTarget{{Package: ".", File: "p.go", Name: "F"}}, 16)
	if err != nil {
		t.Fatalf("GenerateMutants: %v", err)
	}
	if len(mutants) != 16 {
		t.Fatalf("mutants = %d, want the budget of 16", len(mutants))
	}
}

func TestAntiWeakeningDetectsRemovedAssertions(t *testing.T) {
	t.Parallel()
	baseDir, headDir := t.TempDir(), t.TempDir()
	writeSource(t, baseDir, "p_test.go", `package p

import "testing"

func TestThing(t *testing.T) {
	if 1 != 1 {
		t.Fatal("impossible")
	}
	if 2 != 2 {
		t.Fatal("impossible")
	}
}
`)
	writeSource(t, headDir, "p_test.go", `package p

import "testing"

func TestThing(t *testing.T) {
	t.Skip("later")
}
`)
	base, err := analyze.TestShapes(context.Background(), baseDir, []string{"p_test.go"})
	if err != nil {
		t.Fatalf("TestShapes(base): %v", err)
	}
	head, err := analyze.TestShapes(context.Background(), headDir, []string{"p_test.go"})
	if err != nil {
		t.Fatalf("TestShapes(head): %v", err)
	}
	ids := ruleIDs(analyze.WeakeningFindings(base, head, func(string) bool { return true }))
	for _, want := range []string{policy.RuleAssertionRemoved, policy.RuleSkipAdded} {
		if !slices.Contains(ids, want) {
			t.Fatalf("missing %s in %v", want, ids)
		}
	}
}

func TestAntiWeakeningIsQuietOnAnUnchangedTest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeSource(t, dir, "p_test.go", `package p

import "testing"

func TestThing(t *testing.T) {
	if 1 != 1 {
		t.Fatal("impossible")
	}
}
`)
	shapes, err := analyze.TestShapes(context.Background(), dir, []string{"p_test.go"})
	if err != nil {
		t.Fatalf("TestShapes: %v", err)
	}
	if got := analyze.WeakeningFindings(shapes, shapes, func(string) bool { return true }); len(got) != 0 {
		t.Fatalf("an unchanged test produced findings: %+v", got)
	}
}
