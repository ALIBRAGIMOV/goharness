package report_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// scopedResult carries one finding of every combination the two axes produce,
// which is the whole space a rendering scope has to decide over.
func scopedResult() verify.Result {
	r := sampleResult()
	r.Evidence = evidence.Finalize([]evidence.Evidence{
		{
			RuleID: policy.GolangciRuleID("errcheck"), File: "changed.go",
			Message: "new defect in a file the change wrote", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired,
			State:          evidence.StateNew, Origin: evidence.OriginAddedLine,
		},
		{
			RuleID: policy.RuleCompile, File: "untouched.go",
			Message: "new defect the change caused elsewhere", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired,
			State:          evidence.StateNew, Origin: evidence.OriginUntouched,
		},
		{
			RuleID: policy.GolangciRuleID("errcheck"), File: "changed.go",
			Message: "debt in a file the change wrote", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired,
			State:          evidence.StatePreexisting, Origin: evidence.OriginChangedFile,
		},
		{
			RuleID: policy.GolangciRuleID("errcheck"), File: "untouched.go",
			Message: "debt in a file nobody touched", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired,
			State:          evidence.StatePreexisting, Origin: evidence.OriginUntouched,
		},
		{
			RuleID: policy.GolangciRuleID("errcheck"), File: "sibling.go",
			Message: "debt beside a file the change wrote", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired,
			State:          evidence.StatePreexisting, Origin: evidence.OriginChangedPackage,
		},
		{
			RuleID: policy.RuleCommentRestates, File: "untouched.go",
			Message: "advisory note in a file nobody touched", Severity: evidence.SeverityWarning,
			Classification: evidence.ClassificationAdvisory,
			State:          evidence.StatePreexisting, Origin: evidence.OriginUntouched,
		},
		{
			RuleID: policy.GolangciRuleID("errcheck"), File: "changed.go",
			Message: "defect this change removed", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired,
			State:          evidence.StateFixed, Origin: evidence.OriginAddedLine,
		},
		{
			RuleID:  policy.RuleBenchTimeDelta,
			Message: "a finding with nowhere to sit", Severity: evidence.SeverityWarning,
			Classification: evidence.ClassificationAdvisory,
			State:          evidence.StatePreexisting, Origin: evidence.OriginUnscoped,
		},
	})
	return r
}

func messages(doc report.Document) []string {
	out := make([]string, 0, len(doc.Evidence))
	for _, f := range doc.Evidence {
		out = append(out, f.Message)
	}
	return out
}

// TestNoScopeEverHidesABlockingFinding is the invariant the whole feature rests
// on. A view that could drop the row that decided the verdict would be a way to
// be admitted by not looking, and no rendering flag may ever be that.
func TestNoScopeEverHidesABlockingFinding(t *testing.T) {
	t.Parallel()
	r := scopedResult()
	full := report.BuildWithOptions("test", r, report.Options{Scope: report.ScopeFull})
	var wantBlocking []string
	for _, f := range full.Evidence {
		if f.Blocking {
			wantBlocking = append(wantBlocking, f.Message)
		}
	}
	if len(wantBlocking) == 0 {
		t.Fatal("the fixture carries no blocking finding, so it guards nothing")
	}
	for _, scope := range []report.Scope{report.ScopeDiff, report.ScopeNew} {
		doc := report.BuildWithOptions("test", r, report.Options{Scope: scope})
		kept := messages(doc)
		for _, want := range wantBlocking {
			if !slices.Contains(kept, want) {
				t.Fatalf("--evidence %s dropped a blocking finding %q; kept %v", scope, want, kept)
			}
		}
	}
}

func TestDiffScopeKeepsWhatTheChangeIsAnswerableFor(t *testing.T) {
	t.Parallel()
	doc := report.BuildWithOptions("test", scopedResult(), report.Options{Scope: report.ScopeDiff})
	kept := messages(doc)
	for _, want := range []string{
		"new defect in a file the change wrote",
		"new defect the change caused elsewhere",
		"defect this change removed",
		"a finding with nowhere to sit",
	} {
		if !slices.Contains(kept, want) {
			t.Fatalf("--evidence diff dropped %q; kept %v", want, kept)
		}
	}
	for _, unwanted := range []string{
		"debt in a file nobody touched",
		"advisory note in a file nobody touched",
		// A sibling of a file the change wrote is the largest bucket of noise
		// on a large repository; the author never opened it.
		"debt beside a file the change wrote",
		// Debt on a line the change did not write, in a file it did edit, is
		// the bucket a legacy file produces in the hundreds. It is counted.
		"debt in a file the change wrote",
	} {
		if slices.Contains(kept, unwanted) {
			t.Fatalf("--evidence diff kept %q, which the change did not write and did not cause", unwanted)
		}
	}
	if got := doc.Summary.DebtInChangedFiles["changed.go"]; got != 1 {
		t.Fatalf("debt in changed.go = %d, want 1: the withheld row has to be counted somewhere", got)
	}
}

func TestNewScopeKeepsOnlyWhatTheChangeMoved(t *testing.T) {
	t.Parallel()
	doc := report.BuildWithOptions("test", scopedResult(), report.Options{Scope: report.ScopeNew})
	kept := messages(doc)
	if slices.Contains(kept, "debt in a file the change wrote") {
		t.Fatalf("--evidence new kept pre-existing debt: %v", kept)
	}
	if !slices.Contains(kept, "defect this change removed") {
		t.Fatalf("--evidence new dropped a fixed finding, which is the credit half: %v", kept)
	}
}

// TestASelectionAlwaysDeclaresWhatItWithheld keeps a narrowed document honest.
// A consumer must never have to guess whether it holds the whole enumeration.
func TestASelectionAlwaysDeclaresWhatItWithheld(t *testing.T) {
	t.Parallel()
	full := report.BuildWithOptions("test", scopedResult(), report.Options{Scope: report.ScopeFull})
	if full.EvidenceTruncated || full.EvidenceOmitted != 0 {
		t.Fatalf("the full document declares itself a selection: truncated=%t omitted=%d",
			full.EvidenceTruncated, full.EvidenceOmitted)
	}
	if full.EvidenceScope != string(report.ScopeFull) {
		t.Fatalf("evidenceScope = %q, want %q", full.EvidenceScope, report.ScopeFull)
	}
	narrowed := report.BuildWithOptions("test", scopedResult(), report.Options{Scope: report.ScopeDiff})
	if !narrowed.EvidenceTruncated {
		t.Fatal("a narrowed document does not declare itself a selection")
	}
	if want := len(full.Evidence) - len(narrowed.Evidence); narrowed.EvidenceOmitted != want {
		t.Fatalf("evidenceOmitted = %d, want %d", narrowed.EvidenceOmitted, want)
	}
	if narrowed.EvidenceScope != string(report.ScopeDiff) {
		t.Fatalf("evidenceScope = %q, want %q", narrowed.EvidenceScope, report.ScopeDiff)
	}
}

// TestTheCountsAreOfTheRunNotOfTheSelection is what lets a narrowed report still
// state the truth about the repository it judged.
func TestTheCountsAreOfTheRunNotOfTheSelection(t *testing.T) {
	t.Parallel()
	full := report.BuildWithOptions("test", scopedResult(), report.Options{Scope: report.ScopeFull})
	for _, scope := range []report.Scope{report.ScopeDiff, report.ScopeNew} {
		doc := report.BuildWithOptions("test", scopedResult(), report.Options{Scope: scope})
		if doc.Summary.Total != full.Summary.Total {
			t.Fatalf("--evidence %s reports %d findings in summary, want the run's %d",
				scope, doc.Summary.Total, full.Summary.Total)
		}
		if doc.Summary.Blocking != full.Summary.Blocking || doc.Summary.Preexisting != full.Summary.Preexisting {
			t.Fatalf("--evidence %s changed the summary: %+v vs %+v", scope, doc.Summary, full.Summary)
		}
		if doc.Verdict != full.Verdict {
			t.Fatalf("--evidence %s changed the verdict: %s vs %s", scope, doc.Verdict, full.Verdict)
		}
	}
}

// TestTheTextReportSaysWhatItIsNotShowing closes the gap between a short list
// and a clean run, which look identical to a reader who is told nothing.
func TestTheTextReportSaysWhatItIsNotShowing(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	if err := report.WriteTextWithOptions(&b, "test", scopedResult(),
		report.TextOptions{Scope: report.ScopeDiff}); err != nil {
		t.Fatalf("WriteTextWithOptions: %v", err)
	}
	out := b.String()
	if strings.Contains(out, "debt in a file nobody touched") {
		t.Fatalf("the text report printed a finding the scope withheld:\n%s", out)
	}
	if !strings.Contains(out, "not shown") || !strings.Contains(out, "--evidence full") {
		t.Fatalf("the text report does not say what it withheld or how to see it:\n%s", out)
	}
	if strings.Contains(out, "debt in a file the change wrote") {
		t.Fatalf("the text report listed debt on a line the change did not write:\n%s", out)
	}
	if !strings.Contains(out, "debt in edited files") || !strings.Contains(out, "changed.go 1") {
		t.Fatalf("the text report does not count the edited-file debt it withheld:\n%s", out)
	}
}
