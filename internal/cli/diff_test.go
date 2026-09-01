package cli_test

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/cli"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
)

// runToReport performs one real run over the fixture and stores its JSON
// document, returning the path. The CLI-level test is over two runs of the same
// subject rather than two hand-written documents, because the property that
// matters is that fingerprints survive an edit to the file they name.
func runToReport(t *testing.T, dir, name string, wantExit int) string {
	t.Helper()
	code, out, errOut := invoke(t, "fast", "--dir", dir, "--json")
	if code != wantExit {
		t.Fatalf("goharness fast exit = %d, want %d\n%s%s", code, wantExit, out, errOut)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// TestDiffBurnsDownTwoRealRuns is the end-to-end case: one finding introduced,
// then repaired, seen from outside the harness by fingerprint alone.
func TestDiffBurnsDownTwoRealRuns(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	source := filepath.Join(dir, "lib", "lib.go")

	writeFile(t, source, suppressedSource)
	before := runToReport(t, dir, "before.json", cli.ExitRejected)
	writeFile(t, source, fixtureSource)
	after := runToReport(t, dir, "after.json", cli.ExitAdmitted)

	code, out, errOut := invoke(t, "diff", before, after)
	if code != report.DiffExitClean {
		t.Fatalf("diff of a repair exit = %d, want %d\n%s%s",
			code, report.DiffExitClean, out, errOut)
	}
	for _, want := range []string{"fixed 1", "GH-SUPPRESS-001", "REJECTED", "ADMITTED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the burn-down does not mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "introduced 1") {
		t.Fatalf("a repair was reported as an introduction:\n%s", out)
	}
}

// TestDiffFailsWhenBlockingEvidenceIsIntroduced runs the same two reports the
// other way round, which is the regression the exit code exists to catch.
func TestDiffFailsWhenBlockingEvidenceIsIntroduced(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	source := filepath.Join(dir, "lib", "lib.go")

	clean := runToReport(t, dir, "clean.json", cli.ExitAdmitted)
	writeFile(t, source, suppressedSource)
	dirty := runToReport(t, dir, "dirty.json", cli.ExitRejected)

	code, out, errOut := invoke(t, "diff", clean, dirty)
	if code != report.DiffExitIntroduced {
		t.Fatalf("diff of a regression exit = %d, want %d\n%s%s",
			code, report.DiffExitIntroduced, out, errOut)
	}

	code, jsonOut, errOut := invoke(t, "diff", "--json", clean, dirty)
	if code != report.DiffExitIntroduced {
		t.Fatalf("--json exit = %d, want %d\n%s", code, report.DiffExitIntroduced, errOut)
	}
	var d report.Diff
	if err := json.Unmarshal([]byte(jsonOut), &d); err != nil {
		t.Fatalf("stdout is not a valid diff document (%v):\n%s", err, jsonOut)
	}
	if d.Schema != report.DiffSchemaID {
		t.Fatalf("schema = %q, want %q", d.Schema, report.DiffSchemaID)
	}
	if d.Counts.Introduced.Blocking < 1 {
		t.Fatalf("introduced blocking = %d, want at least one: %s", d.Counts.Introduced.Blocking, jsonOut)
	}
	if d.SubjectMismatch {
		t.Fatalf("two runs of one fixture were read as different subjects: %s", jsonOut)
	}
	if !d.Verdict.Changed || d.Verdict.To != "REJECTED" {
		t.Fatalf("verdict transition = %+v", d.Verdict)
	}
}

// TestDiffIsDeterministicAndReadOnly holds the command to the two properties
// every consumer depends on: the same inputs render the same bytes, and reading
// two reports touches nothing.
func TestDiffIsDeterministicAndReadOnly(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	first := runToReport(t, dir, "first.json", cli.ExitAdmitted)
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), suppressedSource)
	second := runToReport(t, dir, "second.json", cli.ExitRejected)

	before := porcelain(t, dir)
	_, textA, _ := invoke(t, "diff", first, second)
	_, textB, _ := invoke(t, "diff", first, second)
	_, jsonA, _ := invoke(t, "diff", "--json", first, second)
	_, jsonB, _ := invoke(t, "diff", "--json", first, second)
	if textA != textB || jsonA != jsonB {
		t.Fatal("two diffs of the same two reports differ")
	}
	if after := porcelain(t, dir); after != before {
		t.Fatalf("goharness diff changed the worktree:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestDiffOperationalErrorsAreExitTwo keeps the error code separate from the
// regression code. Two is "there is no answer", which is what
// INCONCLUSIVE means everywhere else in this binary.
func TestDiffOperationalErrorsAreExitTwo(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	writeFile(t, good, `{"schema":"`+report.SchemaID+`","evidence":[]}`)
	wrongSchema := filepath.Join(dir, "wrong.json")
	writeFile(t, wrongSchema, `{"schema":"goharness.report/v1","evidence":[]}`)
	malformed := filepath.Join(dir, "bad.json")
	writeFile(t, malformed, "{not json")

	for name, args := range map[string][]string{
		"missing file":  {"diff", filepath.Join(dir, "absent.json"), good},
		"wrong schema":  {"diff", wrongSchema, good},
		"the diff form": {"diff", good, wrongSchema},
		"malformed":     {"diff", malformed, good},
		"one operand":   {"diff", good},
		"three":         {"diff", good, good, good},
		"none":          {"diff"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, _ := invoke(t, args...)
			if code != report.DiffExitError {
				t.Fatalf("exit = %d, want %d\n%s", code, report.DiffExitError, out)
			}
			if out != "" {
				t.Fatalf("a failed diff wrote to stdout:\n%s", out)
			}
		})
	}
}

// TestDiffOfDifferentSubjectsWarnsAndProceeds pins the trap the other way: a
// mismatch is stated, never used as a reason to refuse.
func TestDiffOfDifferentSubjectsWarnsAndProceeds(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "one.json")
	writeFile(t, one, `{"schema":"`+report.SchemaID+
		`","mode":"verify","module":{"path":"example.com/a"},"evidence":[]}`)
	two := filepath.Join(dir, "two.json")
	writeFile(t, two, `{"schema":"`+report.SchemaID+
		`","mode":"audit","module":{"path":"example.com/b"},"evidence":[]}`)

	code, out, _ := invoke(t, "diff", one, two)
	if code != report.DiffExitClean {
		t.Fatalf("exit = %d, want a mismatch not to fail the command", code)
	}
	if !strings.Contains(out, "different subjects") {
		t.Fatalf("no mismatch warning:\n%s", out)
	}
}

// TestDiffHelpStatesItsOwnExitCodes keeps the trap documented where an operator
// meets it: diff's codes are not the verification codes, and a caller that
// assumed they were would read a regression as a rejection.
func TestDiffHelpStatesItsOwnExitCodes(t *testing.T) {
	code, out, _ := invoke(t, "help", "diff")
	if code != cli.ExitAdmitted {
		t.Fatalf("help diff exit = %d", code)
	}
	for _, want := range []string{
		"usage: goharness diff", "NOT the verification exit codes",
		"goharness.report/v2", "subjectMismatch",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("diff help is missing %q:\n%s", want, out)
		}
	}
}
