package report_test

import (
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The document's bytes are part of its contract: a consumer diffing two
// reports, or a CI step comparing two runs, reads them as text. This pins the
// encoding decisions rather than leaving them to whatever the encoder does by
// default: no HTML escaping (the document is JSON, not markup), arrays never
// null, map keys in sorted order, two-space indentation, one trailing newline.
func TestReportBytesAreStable(t *testing.T) {
	t.Parallel()
	result := verify.Result{
		Evidence: []evidence.Evidence{{
			RuleID: "GH-TEST", File: "a.go", Message: "x < y && z > 0, see <pkg> \u00e9",
			Severity: evidence.SeverityError, Classification: evidence.ClassificationRequired,
		}},
	}
	encoded, err := report.DeterministicJSON("test", result)
	if err != nil {
		t.Fatalf("DeterministicJSON: %v", err)
	}
	text := string(encoded)
	for _, want := range []string{
		`"message": "x < y && z > 0, see <pkg> é"`,
		`"failures": []`,
		"\n  \"schema\": \"" + report.SchemaID + "\",\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the document does not contain %q:\n%s", want, text)
		}
	}
	for _, reject := range []string{`\u003c`, `\u0026`, `: null`} {
		if strings.Contains(text, reject) {
			t.Errorf("the document contains %q, which the encoding rules exclude:\n%s", reject, text)
		}
	}
	if !strings.HasPrefix(text, "{\n  ") || strings.HasSuffix(text, "\n") {
		t.Errorf("DeterministicJSON is not an indented value without a trailing newline: %q...", text[:min(len(text), 20)])
	}
	if strings.Index(text, `"schema"`) > strings.Index(text, `"verdict"`) {
		t.Errorf("fields are not in declaration order:\n%s", text)
	}
	var b strings.Builder
	if err := report.WriteJSON(&b, "test", result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.HasSuffix(b.String(), "}\n") {
		t.Errorf("WriteJSON does not end the document with one newline: %q", b.String()[len(b.String())-4:])
	}
}
