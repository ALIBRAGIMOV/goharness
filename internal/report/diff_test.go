package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
)

// finding builds one evidence row of a synthetic report. Fingerprints are
// written by hand here rather than derived, because the comparison's whole
// contract is that it looks at nothing else.
func finding(fingerprint, ruleID, consequence string, blocking bool) report.Finding {
	return report.Finding{
		Fingerprint: fingerprint, RuleID: ruleID, Consequence: consequence,
		File: "a.go", Message: "m", Severity: evidence.SeverityError,
		Classification: evidence.ClassificationRequired,
		Blocking:       blocking,
	}
}

func document(verdict string, claims []admission.QualityClaim, items ...report.Finding) report.Document {
	return report.Document{
		Schema:   report.SchemaID,
		Verdict:  verdict,
		Mode:     "verify",
		Module:   report.Module{Path: "example.com/x"},
		Claims:   claims,
		Evidence: items,
	}
}

func claim(dim admission.Dimension, state admission.ClaimState) admission.QualityClaim {
	return admission.QualityClaim{Dimension: dim, State: state}
}

func TestDiffSchemaIsVersionedFromBirth(t *testing.T) {
	t.Parallel()
	if report.DiffSchemaID != "goharness.diff/v1" {
		t.Fatalf("diff schema = %q", report.DiffSchemaID)
	}
	if report.DiffSchemaID == report.SchemaID {
		t.Fatal("the diff document must not claim to be a report")
	}
}

func TestDiffPartitionsEvidenceByFingerprint(t *testing.T) {
	t.Parallel()
	oldDoc := document("REJECTED", nil,
		finding("aaaa", "GCL-errcheck", evidence.ConsequenceSilentLoss, true),
		finding("bbbb", "GH-COMMENT-001", evidence.ConsequenceHygiene, true),
		finding("cccc", "GH-DUP-001", evidence.ConsequenceStructural, false),
	)
	newDoc := document("REJECTED", nil,
		finding("bbbb", "GH-COMMENT-001", evidence.ConsequenceHygiene, true),
		finding("cccc", "GH-DUP-001", evidence.ConsequenceStructural, false),
		finding("dddd", "GCL-gosec", evidence.ConsequenceUnsafeBehavior, true),
	)
	d := report.CompareDocuments(oldDoc, newDoc)

	if got := d.Counts.Fixed; got.Total != 1 || got.Blocking != 1 {
		t.Fatalf("fixed = %+v, want one blocking", got)
	}
	if got := d.Counts.Introduced; got.Total != 1 || got.Blocking != 1 {
		t.Fatalf("introduced = %+v, want one blocking", got)
	}
	if got := d.Counts.Remaining; got.Total != 2 || got.Blocking != 1 || got.Advisory != 1 {
		t.Fatalf("remaining = %+v, want one of each", got)
	}
	if d.ExitCode != report.DiffExitIntroduced {
		t.Fatalf("exit = %d, want %d when blocking evidence was introduced",
			d.ExitCode, report.DiffExitIntroduced)
	}
}

// TestDiffExitsCleanWhenOnlyDebtRemains is the false-positive guard on the exit
// code: a run that repaired findings and left the rest alone went the right way,
// and a supervisor that treated that as a regression would punish repair.
func TestDiffExitsCleanWhenOnlyDebtRemains(t *testing.T) {
	t.Parallel()
	oldDoc := document("REJECTED", nil,
		finding("aaaa", "GCL-errcheck", evidence.ConsequenceSilentLoss, true),
		finding("bbbb", "GH-COMMENT-001", evidence.ConsequenceHygiene, true),
	)
	newDoc := document("REJECTED", nil,
		finding("bbbb", "GH-COMMENT-001", evidence.ConsequenceHygiene, true),
	)
	if d := report.CompareDocuments(oldDoc, newDoc); d.ExitCode != report.DiffExitClean {
		t.Fatalf("exit = %d, want %d", d.ExitCode, report.DiffExitClean)
	}
}

// TestDiffIntroducedAdvisoryDoesNotFail keeps advisory findings off the failing
// axis, exactly as the verdict itself keeps them off it.
func TestDiffIntroducedAdvisoryDoesNotFail(t *testing.T) {
	t.Parallel()
	newDoc := document("ADMITTED", nil,
		finding("dddd", "GH-DUP-001", evidence.ConsequenceStructural, false))
	d := report.CompareDocuments(document("ADMITTED", nil), newDoc)
	if d.Counts.Introduced.Advisory != 1 {
		t.Fatalf("introduced advisory = %d", d.Counts.Introduced.Advisory)
	}
	if d.ExitCode != report.DiffExitClean {
		t.Fatalf("exit = %d, want %d", d.ExitCode, report.DiffExitClean)
	}
}

func TestDiffGroupsByConsequenceThenRule(t *testing.T) {
	t.Parallel()
	newDoc := document("REJECTED", nil,
		finding("1111", "GH-COMMENT-001", evidence.ConsequenceHygiene, true),
		finding("2222", "GCL-gosec", evidence.ConsequenceUnsafeBehavior, true),
		finding("3333", "GCL-errcheck", evidence.ConsequenceSilentLoss, true),
		finding("4444", "GCL-errcheck", evidence.ConsequenceSilentLoss, true),
	)
	d := report.CompareDocuments(document("ADMITTED", nil), newDoc)

	var classes []string
	for _, g := range d.Introduced {
		classes = append(classes, g.Consequence)
	}
	want := []string{
		evidence.ConsequenceSilentLoss, evidence.ConsequenceUnsafeBehavior, evidence.ConsequenceHygiene,
	}
	if strings.Join(classes, ",") != strings.Join(want, ",") {
		t.Fatalf("groups = %v, want consequence order %v", classes, want)
	}
	first := d.Introduced[0]
	if len(first.Rules) != 1 || first.Rules[0].Total != 2 {
		t.Fatalf("silent-loss group = %+v, want one rule counted twice", first)
	}
	if strings.Join(first.Rules[0].Fingerprints, ",") != "3333,4444" {
		t.Fatalf("fingerprints = %v, want both identities carried", first.Rules[0].Fingerprints)
	}
}

// TestDiffToleratesReportsWithoutConsequenceClasses is the compatibility case:
// a report written before consequence classes existed carries none, and the
// comparison must group it as unclassified rather than fail.
func TestDiffToleratesReportsWithoutConsequenceClasses(t *testing.T) {
	t.Parallel()
	newDoc := document("REJECTED", nil,
		finding("1111", "GCL-errcheck", "", true),
		finding("2222", "GCL-gosec", evidence.ConsequenceUnsafeBehavior, true),
	)
	d := report.CompareDocuments(document("ADMITTED", nil), newDoc)
	if len(d.Introduced) != 2 {
		t.Fatalf("groups = %d, want two", len(d.Introduced))
	}
	if last := d.Introduced[1]; last.Consequence != "" {
		t.Fatalf("last group = %q, want the unclassified one to sort last", last.Consequence)
	}
	var text bytes.Buffer
	if err := report.WriteDiffText(&text, d, report.DiffTextOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !strings.Contains(text.String(), "unclassified") {
		t.Fatalf("unclassified group is unnamed in the text form:\n%s", text.String())
	}
}

func TestDiffReportsVerdictAndClaimTransitions(t *testing.T) {
	t.Parallel()
	oldDoc := document("REJECTED", []admission.QualityClaim{
		claim(admission.DimReliability, admission.ClaimFail),
		claim(admission.DimSecurity, admission.ClaimPass),
	})
	newDoc := document("ADMITTED", []admission.QualityClaim{
		claim(admission.DimReliability, admission.ClaimPass),
		claim(admission.DimSecurity, admission.ClaimPass),
	})
	d := report.CompareDocuments(oldDoc, newDoc)

	if !d.Verdict.Changed || d.Verdict.From != "REJECTED" || d.Verdict.To != "ADMITTED" {
		t.Fatalf("verdict transition = %+v", d.Verdict)
	}
	moved := map[string]report.ClaimTransition{}
	for _, c := range d.Claims {
		moved[c.Dimension] = c
	}
	if c := moved[string(admission.DimReliability)]; !c.Changed || c.From != "FAIL" || c.To != "PASS" {
		t.Fatalf("reliability = %+v", c)
	}
	if c := moved[string(admission.DimSecurity)]; c.Changed {
		t.Fatalf("security did not move but reads as changed: %+v", c)
	}

	var text bytes.Buffer
	if err := report.WriteDiffText(&text, d, report.DiffTextOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	for _, want := range []string{"REJECTED", "ADMITTED", "reliability", "FAIL -> PASS"} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text form is missing %q:\n%s", want, text.String())
		}
	}
}

// TestDiffFlagsASubjectMismatchWithoutRefusing keeps the warning a warning. Two
// honest reports of different modules still diff mechanically; refusing would
// hide the mismatch instead of stating it.
func TestDiffFlagsASubjectMismatchWithoutRefusing(t *testing.T) {
	t.Parallel()
	oldDoc := document("REJECTED", nil, finding("aaaa", "GCL-gosec", "", true))
	newDoc := document("REJECTED", nil, finding("aaaa", "GCL-gosec", "", true))
	newDoc.Module.Path = "example.com/other"
	newDoc.Mode = "audit"

	d := report.CompareDocuments(oldDoc, newDoc)
	if !d.SubjectMismatch {
		t.Fatal("differing module and mode did not set subjectMismatch")
	}
	if d.Counts.Remaining.Total != 1 {
		t.Fatalf("the comparison stopped at the mismatch: %+v", d.Counts)
	}
	if d.ExitCode != report.DiffExitClean {
		t.Fatalf("exit = %d, want a mismatch not to fail the command", d.ExitCode)
	}
	var text bytes.Buffer
	if err := report.WriteDiffText(&text, d, report.DiffTextOptions{}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !strings.Contains(text.String(), "different subjects") {
		t.Fatalf("no warning line:\n%s", text.String())
	}
}

// TestDiffDeclaresATruncatedInput is the same discipline the report itself
// applies to truncation: a comparison of a selection is not a burn-down of a
// run, and the reader is told which one they are holding.
func TestDiffDeclaresATruncatedInput(t *testing.T) {
	t.Parallel()
	newDoc := document("REJECTED", nil, finding("aaaa", "GCL-gosec", "", true))
	newDoc.EvidenceTruncated = true
	newDoc.EvidenceOmitted = 1522

	d := report.CompareDocuments(document("REJECTED", nil), newDoc)
	if !d.New.Truncated || d.New.Omitted != 1522 {
		t.Fatalf("new subject = %+v, want the truncation carried", d.New)
	}
	var text bytes.Buffer
	if err := report.WriteDiffText(&text, d, report.DiffTextOptions{NewLabel: "after.json"}); err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !strings.Contains(text.String(), "truncated") || !strings.Contains(text.String(), "after.json") {
		t.Fatalf("truncation is not declared:\n%s", text.String())
	}
}

func TestDiffJSONIsTaggedAndDeterministic(t *testing.T) {
	t.Parallel()
	oldDoc := document("REJECTED", []admission.QualityClaim{
		claim(admission.DimReliability, admission.ClaimFail)},
		finding("aaaa", "GCL-errcheck", evidence.ConsequenceSilentLoss, true),
		finding("bbbb", "GH-COMMENT-001", evidence.ConsequenceHygiene, true))
	newDoc := document("ADMITTED", []admission.QualityClaim{
		claim(admission.DimReliability, admission.ClaimPass)},
		finding("bbbb", "GH-COMMENT-001", evidence.ConsequenceHygiene, true),
		finding("cccc", "GCL-gosec", evidence.ConsequenceUnsafeBehavior, false))

	render := func() string {
		var b bytes.Buffer
		if err := report.WriteDiffJSON(&b, report.CompareDocuments(oldDoc, newDoc)); err != nil {
			t.Fatalf("rendering: %v", err)
		}
		return b.String()
	}
	first := render()
	if first != render() {
		t.Fatal("two renderings of the same inputs differ")
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(first), &decoded); err != nil {
		t.Fatalf("the diff document is not valid JSON: %v", err)
	}
	for _, key := range []string{
		"schema", "old", "new", "subjectMismatch", "verdict", "claims",
		"counts", "fixed", "introduced", "remaining", "exitCode",
	} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("the diff document has no %q field", key)
		}
	}
	var schema struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal([]byte(first), &schema); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if schema.Schema != report.DiffSchemaID {
		t.Fatalf("schema = %q, want %q", schema.Schema, report.DiffSchemaID)
	}
}

// TestDiffTextIsDeterministic holds the text form to the same rule as the JSON:
// the same two documents render byte for byte the same, whatever order the maps
// inside the comparison happened to iterate in.
func TestDiffTextIsDeterministic(t *testing.T) {
	t.Parallel()
	var items []report.Finding
	for _, r := range []string{"GCL-errcheck", "GCL-gosec", "GH-DUP-001", "GH-COMMENT-001"} {
		for i := range 5 {
			items = append(items, finding(r+string(rune('a'+i)), r, "", true))
		}
	}
	newDoc := document("REJECTED", nil, items...)
	render := func() string {
		var b bytes.Buffer
		if err := report.WriteDiffText(&b, report.CompareDocuments(document("ADMITTED", nil), newDoc),
			report.DiffTextOptions{}); err != nil {
			t.Fatalf("rendering: %v", err)
		}
		return b.String()
	}
	first := render()
	for range 8 {
		if again := render(); again != first {
			t.Fatalf("the text form is not stable across renderings:\n%s\n%s", first, again)
		}
	}
}

func TestParseDocumentRefusesAnyOtherSchema(t *testing.T) {
	t.Parallel()
	for name, data := range map[string]string{
		"another schema":  `{"schema":"goharness.report/v1","evidence":[]}`,
		"a diff document": `{"schema":"goharness.diff/v1"}`,
		"no schema":       `{"evidence":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := report.ParseDocument("r.json", []byte(data)); err == nil {
				t.Fatal("accepted a document this binary does not read")
			}
		})
	}
	if _, err := report.ParseDocument("r.json", []byte("not json at all")); err == nil {
		t.Fatal("accepted malformed input")
	}
	doc, err := report.ParseDocument("r.json", []byte(`{"schema":"`+report.SchemaID+`"}`))
	if err != nil {
		t.Fatalf("rejected its own schema: %v", err)
	}
	if doc.Schema != report.SchemaID {
		t.Fatalf("schema = %q", doc.Schema)
	}
}
