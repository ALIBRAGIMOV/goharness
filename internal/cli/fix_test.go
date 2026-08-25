package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/cli"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
)

// cliEmDash is written as an escape: the repository forbids the raw rune in Go
// source, and a fixture that needs it puts it inside a string literal.
const cliEmDash = "\u2014"

// emDashRepoSource carries the rune in a comment and in a string literal, so a
// fixer that cannot tell them apart fails this test rather than a real
// repository's client-facing copy.
func emDashRepoSource() string {
	return "package lib\n" +
		"\n" +
		"// Answer returns the answer " + cliEmDash + " constantly.\n" +
		"func Answer() int {\n" +
		"\treturn 42\n" +
		"}\n" +
		"\n" +
		"// Motto is copy that ships to a customer.\n" +
		"const Motto = \"we ship " + cliEmDash + " carefully\"\n" +
		"\n" +
		"// Second observes nothing " + cliEmDash + " it is here to make two findings.\n" +
		"func Second() int {\n" +
		"\treturn Answer()\n" +
		"}\n"
}

func TestFixRewritesCommentsAndLeavesLiteralsAlone(t *testing.T) {
	dir := newFixtureRepo(t)
	path := filepath.Join(dir, "lib", "lib.go")
	writeFile(t, path, emDashRepoSource())

	code, out, errOut := invoke(t, "fix", "--rule", policy.RuleCommentEmDash, "--dir", dir)
	if code != cli.ExitAdmitted {
		t.Fatalf("exit = %d (%s)", code, errOut)
	}
	if !strings.Contains(out, "lib/lib.go") || !strings.Contains(out, "2 replacement") {
		t.Fatalf("fix did not report what it changed:\n%s", out)
	}
	fixed := readFile(t, path)
	if strings.Contains(fixed, "// Answer returns the answer "+cliEmDash) {
		t.Fatalf("the comment was not fixed:\n%s", fixed)
	}
	if !strings.Contains(fixed, "const Motto = \"we ship "+cliEmDash+" carefully\"") {
		t.Fatalf("the string literal was rewritten:\n%s", fixed)
	}
	// The whole point of the command: what it fixed, the gate no longer reports.
	if code, _, _ := invoke(t, "fix", "--rule", policy.RuleCommentEmDash, "--dry-run", "--dir", dir); code != cli.ExitAdmitted {
		t.Fatalf("a second run over the fixed tree exited %d", code)
	}
}

// TestFixDryRunWritesNothing is the property that makes --dry-run usable as a
// review step rather than a preview of an edit already made.
func TestFixDryRunWritesNothing(t *testing.T) {
	dir := newFixtureRepo(t)
	path := filepath.Join(dir, "lib", "lib.go")
	writeFile(t, path, emDashRepoSource())
	before := readFile(t, path)

	code, out, errOut := invoke(t, "fix", "--rule", policy.RuleCommentEmDash, "--dry-run", "--dir", dir)
	if code != cli.ExitAdmitted {
		t.Fatalf("exit = %d (%s)", code, errOut)
	}
	if !strings.Contains(out, "--- a/lib/lib.go") || !strings.Contains(out, "+++ b/lib/lib.go") ||
		!strings.Contains(out, "@@") {
		t.Fatalf("--dry-run did not print a unified diff:\n%s", out)
	}
	if !strings.Contains(out, "-// Answer returns the answer "+cliEmDash) ||
		!strings.Contains(out, "+// Answer returns the answer - constantly.") {
		t.Fatalf("the diff does not show the substitution:\n%s", out)
	}
	if got := readFile(t, path); got != before {
		t.Fatalf("--dry-run wrote to the tree:\n%s", got)
	}
}

func TestFixRejectsARuleItCannotFix(t *testing.T) {
	dir := newFixtureRepo(t)
	for _, args := range [][]string{
		{"fix", "--dir", dir},
		{"fix", "--rule", policy.RuleSuppressNolint, "--dir", dir},
		{"fix", "--rule", "GH-NOT-A-RULE", "--dir", dir},
	} {
		code, _, errOut := invoke(t, args...)
		if code != cli.ExitInconclusive {
			t.Fatalf("goharness %s exit = %d, want %d", strings.Join(args, " "), code, cli.ExitInconclusive)
		}
		if !strings.Contains(errOut, policy.RuleCommentEmDash) {
			t.Fatalf("the refusal does not list what can be fixed:\n%s", errOut)
		}
	}
}

// TestEmDashEvidenceCarriesItsFixCommand closes the loop between the finding
// and the command: an agent reading the report should not have to know this
// subcommand exists.
func TestEmDashEvidenceCarriesItsFixCommand(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), emDashRepoSource())

	_, out, errOut := invoke(t, "fast", "--dir", dir, "--json")
	doc := decodeReport(t, out, errOut)
	for _, f := range doc.Evidence {
		if f.RuleID != policy.RuleCommentEmDash {
			continue
		}
		if f.Fix == nil || !strings.Contains(f.Fix.Command, "goharness fix --rule "+policy.RuleCommentEmDash) {
			t.Fatalf("the em dash finding carries no fix command: %+v", f)
		}
		if f.Consequence == "" {
			t.Fatalf("the em dash finding carries no consequence class: %+v", f)
		}
		return
	}
	t.Fatalf("the fixture produced no em dash finding:\n%s", errOut)
}

// TestExplainResolvesAFingerprintFromAReport is what makes a truncated document
// usable: every row it omits stays addressable by name.
func TestExplainResolvesAFingerprintFromAReport(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), emDashRepoSource())

	_, out, errOut := invoke(t, "fast", "--dir", dir, "--json")
	doc := decodeReport(t, out, errOut)
	if len(doc.Evidence) == 0 {
		t.Fatalf("the fixture produced no evidence:\n%s", errOut)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	writeFile(t, path, out)

	want := doc.Evidence[0]
	code, explained, explainErr := invoke(t, "explain", want.Fingerprint, "--report", path)
	if code != cli.ExitAdmitted {
		t.Fatalf("exit = %d (%s)", code, explainErr)
	}
	for _, needle := range []string{want.Fingerprint, want.RuleID, want.Consequence, "blocking:"} {
		if needle == "" {
			continue
		}
		if !strings.Contains(explained, needle) {
			t.Fatalf("explain output does not name %q:\n%s", needle, explained)
		}
	}
	if !strings.Contains(explained, "rationale:") {
		t.Fatalf("explain by fingerprint dropped the rule's own entry:\n%s", explained)
	}

	code, _, missing := invoke(t, "explain", "0000000000000000", "--report", path)
	if code != cli.ExitInconclusive || !strings.Contains(missing, "no finding with fingerprint") {
		t.Fatalf("an unknown fingerprint exited %d: %s", code, missing)
	}
	code, _, noReport := invoke(t, "explain", want.Fingerprint)
	if code != cli.ExitInconclusive || !strings.Contains(noReport, "--report") {
		t.Fatalf("a fingerprint without a report exited %d: %s", code, noReport)
	}
}

// TestEvidenceTopTruncatesAndSaysSo keeps the budgeted rendering honest: it
// carries the same verdict and the same counts as the full document, and it
// never leaves a consumer guessing whether it holds everything.
func TestEvidenceTopTruncatesAndSaysSo(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), emDashRepoSource())

	_, full, fullErr := invoke(t, "fast", "--dir", dir, "--json")
	fullDoc := decodeReport(t, full, fullErr)
	if len(fullDoc.Evidence) == 0 {
		t.Fatalf("the fixture produced no evidence:\n%s", fullErr)
	}
	if fullDoc.EvidenceTruncated || fullDoc.EvidenceOmitted != 0 {
		t.Fatal("the default rendering declared itself truncated")
	}

	_, top, topErr := invoke(t, "fast", "--dir", dir, "--json",
		"--evidence", "top", "--evidence-limit", "1")
	topDoc := decodeReport(t, top, topErr)
	if len(topDoc.Evidence) != 1 || !topDoc.EvidenceTruncated {
		t.Fatalf("truncation kept %d findings, truncated=%t", len(topDoc.Evidence), topDoc.EvidenceTruncated)
	}
	if topDoc.EvidenceOmitted != len(fullDoc.Evidence)-1 {
		t.Fatalf("omitted %d of %d", topDoc.EvidenceOmitted, len(fullDoc.Evidence))
	}
	if topDoc.Verdict != fullDoc.Verdict || topDoc.Summary.Total != fullDoc.Summary.Total {
		t.Fatal("truncation changed the verdict or the counts it reports")
	}

	code, _, badMode := invoke(t, "fast", "--dir", dir, "--json", "--evidence", "some")
	if code != cli.ExitInconclusive || !strings.Contains(badMode, "unknown --evidence mode") {
		t.Fatalf("an unknown mode exited %d: %s", code, badMode)
	}
}

func decodeReport(t *testing.T, stdout, stderr string) report.Document {
	t.Helper()
	var doc report.Document
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not a report (%v)\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	return doc
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}
