package tool

import (
	"slices"
	"strings"
	"testing"
)

// TestGoFixArgsNeverRewriteTheTree guards the one property that matters more
// than any verdict: go fix applies its edits to the source tree unless it is
// asked for JSON or a diff, so an argument vector that lost -json would rewrite
// the repository under verification.
func TestGoFixArgsNeverRewriteTheTree(t *testing.T) {
	args := GoFixArgs([]string{"./internal/...", "./cmd/..."}, []string{"inline", "minmax"})

	if args[0] != "fix" || args[1] != "-json" {
		t.Fatalf("args = %v, want fix -json first", args)
	}
	for _, forbidden := range []string{"-fix", "-diff", "-w"} {
		if slices.Contains(args, forbidden) {
			t.Fatalf("args = %v, must never contain %s", args, forbidden)
		}
	}
	for _, want := range []string{"-inline", "-minmax", "./internal/...", "./cmd/..."} {
		if !slices.Contains(args, want) {
			t.Fatalf("args = %v, want %s", args, want)
		}
	}
}

func TestRunGoFixReadsDiagnosticsAndTheirFixes(t *testing.T) {
	runner := &stubRunner{result: Result{Stdout: `{
  "example.com/x": {
    "inline": [
      {
        "posn": "/tmp/x/a.go:12:4",
        "message": "call of x.Square should be inlined",
        "suggested_fixes": [
          {"message": "inline call of x.Square", "edits": [
            {"filename": "/tmp/x/a.go", "start": 120, "end": 131, "new": "Pow(v, 2)"}
          ]}
        ]
      }
    ]
  }
}
{}
`}}
	diags, err := RunGoFix(t.Context(), runner, ".", []string{"./..."}, []string{"inline"})
	if err != nil {
		t.Fatalf("RunGoFix: %v", err)
	}
	if len(diags) != 1 {
		t.Fatalf("diags = %+v", diags)
	}
	got := diags[0]
	if got.Analyzer != "inline" || got.Package != "example.com/x" ||
		got.File != "/tmp/x/a.go" || got.Line != 12 || got.Column != 4 {
		t.Fatalf("diagnostic = %+v", got)
	}
	if got.FixSummary != "inline call of x.Square" || got.Edits != 1 {
		t.Fatalf("suggested fix = %q with %d edit(s)", got.FixSummary, got.Edits)
	}
}

// TestRunGoFixReportsAnalyzerFailureAsToolFailure keeps an analyzer that could
// not run out of the evidence set: it says nothing about the code in front of
// it, so it has to reach the caller as an error and leave the claim
// INCONCLUSIVE.
func TestRunGoFixReportsAnalyzerFailureAsToolFailure(t *testing.T) {
	runner := &stubRunner{result: Result{Stdout: `{"example.com/x": {"inline": {"error": "no export data"}}}`}}
	_, err := RunGoFix(t.Context(), runner, ".", []string{"./..."}, []string{"inline"})
	if err == nil {
		t.Fatal("an analyzer error was read as an absence of findings")
	}
	if !strings.Contains(err.Error(), "no export data") {
		t.Fatalf("error = %v, want the analyzer's own reason", err)
	}
}

func TestRunGoFixTreatsUnparsableOutputWithNonZeroExitAsFailure(t *testing.T) {
	runner := &stubRunner{result: Result{ExitCode: 1, Stderr: "cannot load package"}}
	if _, err := RunGoFix(t.Context(), runner, ".", []string{"./..."}, []string{"inline"}); err == nil {
		t.Fatal("a failed go fix invocation was accepted")
	}
}

func TestParseFixAnalyzerFlagsKeepsOnlyAnalyzerSwitches(t *testing.T) {
	names, err := parseFixAnalyzerFlags(`[
  {"Name": "V", "Bool": true, "Usage": "print version and exit"},
  {"Name": "any", "Bool": true, "Usage": "enable any analysis"},
  {"Name": "buildtags", "Bool": true, "Usage": "deprecated alias for -buildtag"},
  {"Name": "inline", "Bool": true, "Usage": "enable inline analysis"},
  {"Name": "inline.lazy_edits", "Bool": true, "Usage": "compute edits lazily"}
]`)
	if err != nil {
		t.Fatalf("parseFixAnalyzerFlags: %v", err)
	}
	if !slices.Equal(names, []string{"any", "inline"}) {
		t.Fatalf("analyzers = %v", names)
	}
}

func TestCompareFixAnalyzersSeparatesMissingFromUnclassified(t *testing.T) {
	support := compareFixAnalyzers(
		[]string{"any", "inline", "brandnew"},
		[]string{"any", "inline", "gone"},
		[]string{"any", "inline", "gone", "omitzero"})
	if !slices.Equal(support.Missing, []string{"gone"}) {
		t.Fatalf("missing = %v", support.Missing)
	}
	if !slices.Equal(support.Unregistered, []string{"brandnew"}) {
		t.Fatalf("unregistered = %v", support.Unregistered)
	}
}
