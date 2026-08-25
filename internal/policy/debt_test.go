package policy_test

import (
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

const validLedger = `# a comment
schema: 1
recordedAt: 0123456789abcdef0123456789abcdef01234567
entries:
  - fingerprint: aaaaaaaaaaaaaaaa
    rule: GCL-errcheck
    file: "lib/lib.go"
  - fingerprint: bbbbbbbbbbbbbbbb
    rule: GH-LEAK-001
`

func TestParseDebtLedgerReadsTheRestrictedShape(t *testing.T) {
	ledger, err := policy.ParseDebtLedger([]byte(validLedger))
	if err != nil {
		t.Fatalf("ParseDebtLedger: %v", err)
	}
	if ledger.Schema != policy.DebtSchema {
		t.Fatalf("schema = %d, want %d", ledger.Schema, policy.DebtSchema)
	}
	if len(ledger.Entries) != 2 {
		t.Fatalf("entries = %+v, want 2", ledger.Entries)
	}
	if ledger.Entries[0].File != "lib/lib.go" || ledger.Entries[0].RuleID != "GCL-errcheck" {
		t.Fatalf("first entry = %+v", ledger.Entries[0])
	}
	// An entry with no file is legitimate: package-scoped evidence has none.
	if ledger.Entries[1].File != "" {
		t.Fatalf("second entry = %+v, want no file", ledger.Entries[1])
	}
	prints := ledger.Fingerprints()
	if !prints["aaaaaaaaaaaaaaaa"] || len(prints) != 2 {
		t.Fatalf("fingerprints = %v", prints)
	}
}

// TestParseDebtLedgerRefusesAnythingItDoesNotUnderstand is the reason this file
// has its own parser rather than a permissive one. A mistyped key in a document
// that decides what stops blocking must never read as an empty document.
func TestParseDebtLedgerRefusesAnythingItDoesNotUnderstand(t *testing.T) {
	cases := map[string]string{
		"unknown top-level key": "schema: 1\nexceptions:\n  - rule: GCL-errcheck\n",
		"unknown entry field":   "schema: 1\nentries:\n  - fingerprint: a\n    rule: b\n    reason: because\n",
		"no schema":             "recordedAt: HEAD\nentries:\n",
		"wrong schema":          "schema: 2\nentries:\n",
		"schema not a number":   "schema: one\nentries:\n",
		"entry without a rule":  "schema: 1\nentries:\n  - fingerprint: a\n",
		"duplicate fingerprint": "schema: 1\nentries:\n  - fingerprint: a\n    rule: b\n  - fingerprint: a\n    rule: c\n",
		"stray content":         "schema: 1\nnot a mapping\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.ParseDebtLedger([]byte(src)); err == nil {
				t.Fatalf("ParseDebtLedger accepted %q", src)
			}
		})
	}
}

// TestRenderDebtLedgerRoundTripsDeterministically is what makes the file
// reviewable: recording the same finding set twice has to produce the same
// bytes, or every re-record shows up as a diff nobody can read.
func TestRenderDebtLedgerRoundTripsDeterministically(t *testing.T) {
	ledger := policy.DebtLedger{
		Schema: policy.DebtSchema, RecordedAt: "abc123",
		Entries: []policy.DebtEntry{
			{Fingerprint: "cccccccccccccccc", RuleID: "GH-CX-001", File: "z/z.go"},
			{Fingerprint: "aaaaaaaaaaaaaaaa", RuleID: "GCL-errcheck", File: "b/b.go"},
			{Fingerprint: "bbbbbbbbbbbbbbbb", RuleID: "GCL-errcheck", File: "a/a.go"},
		},
	}
	first := policy.RenderDebtLedger(ledger)
	shuffled := policy.DebtLedger{Schema: ledger.Schema, RecordedAt: ledger.RecordedAt}
	shuffled.Entries = append(shuffled.Entries,
		ledger.Entries[2], ledger.Entries[0], ledger.Entries[1])
	if second := policy.RenderDebtLedger(shuffled); string(first) != string(second) {
		t.Fatalf("rendering depends on input order:\n%s\n---\n%s", first, second)
	}

	parsed, err := policy.ParseDebtLedger(first)
	if err != nil {
		t.Fatalf("rendered ledger does not parse: %v\n%s", err, first)
	}
	if len(parsed.Entries) != len(ledger.Entries) || parsed.RecordedAt != ledger.RecordedAt {
		t.Fatalf("round trip = %+v", parsed)
	}
	if !strings.HasPrefix(string(first), "#") {
		t.Fatalf("the rendered ledger carries no header saying what it is:\n%s", first)
	}
}

// TestRenderedLedgerNamesItsAuthenticationRule keeps the one property a reader
// of the file has to learn from the file itself: an uncommitted copy does
// nothing.
func TestRenderedLedgerNamesItsAuthenticationRule(t *testing.T) {
	rendered := string(policy.RenderDebtLedger(policy.DebtLedger{
		Schema: policy.DebtSchema, RecordedAt: policy.DebtRecordedUncommitted,
	}))
	if !strings.Contains(rendered, "HEAD") {
		t.Fatalf("the header does not say which copy counts:\n%s", rendered)
	}
}
