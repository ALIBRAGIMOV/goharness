package verify_test

import (
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// localConfig is an incumbent golangci-lint configuration with two permissive
// choices: a wholesale test-file exclusion, and errcheck running without
// check-blank. Each is defensible alone; together they hide every discarded
// error in a test.
const localConfig = `version: "2"
linters:
  default: none
  enable:
    - errcheck
    - staticcheck
  exclusions:
    rules:
      - path: _test\.go
        linters:
          - errcheck
`

func shadowFixture(t *testing.T, withConfig bool) *fixture {
	t.Helper()
	useGolangci(t)
	provisionSnapshot(t)
	f := newFixtureIn(t, layout{})
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", uncheckedErrorLibraryTest)
	if withConfig {
		f.write(".golangci.yml", localConfig)
	}
	f.commit("a repository with its own lint configuration")
	return f
}

func entryByID(t *testing.T, shadow *verify.PolicyShadow, id string) verify.ShadowEntry {
	t.Helper()
	if shadow == nil {
		t.Fatalf("the run produced no policy shadow")
	}
	for _, e := range shadow.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no %s entry in %+v", id, shadow.Entries)
	return verify.ShadowEntry{}
}

// TestPolicyShadowIsReportedFromTheRepositoryOwnConfig asserts the sentence an
// audit owes a repository that runs its own linter configuration, generated
// from that file: your configuration excludes errcheck from test files, and
// this many of this run's findings live there.
func TestPolicyShadowIsReportedFromTheRepositoryOwnConfig(t *testing.T) {
	f := shadowFixture(t, true)
	result := run(t, f, verify.ModeAudit)

	shadow := result.PolicyShadow
	if shadow == nil || !shadow.Analysed || shadow.File != ".golangci.yml" {
		t.Fatalf("policy shadow = %+v", shadow)
	}
	exclusion := entryByID(t, shadow, tool.ShadowTestExclusion)
	if !slices.Contains(exclusion.RuleIDs, policy.RuleErrcheck) {
		t.Fatalf("test exclusion names %v, want %s", exclusion.RuleIDs, policy.RuleErrcheck)
	}
	if !exclusion.Attributed || exclusion.Findings == 0 {
		t.Fatalf("the exclusion shadow carries no count of what lives in it: %+v", exclusion)
	}
	// A count that cannot be exact is declared as such rather than printed.
	blank := entryByID(t, shadow, tool.ShadowCheckBlank)
	if blank.Attributed || blank.Note == "" {
		t.Fatalf("check-blank claimed an exact count: %+v", blank)
	}
	off := entryByID(t, shadow, tool.ShadowLintersOff)
	if !slices.Contains(off.RuleIDs, policy.GolangciRuleID("gosec")) {
		t.Fatalf("disabled linters = %v, want gosec among them", off.RuleIDs)
	}

	doc := report.Build("test", result)
	if doc.PolicyShadow == nil || len(doc.PolicyShadow.Entries) != len(shadow.Entries) {
		t.Fatalf("the document does not carry the section: %+v", doc.PolicyShadow)
	}
}

// TestPolicyShadowNeverChangesTheVerdict is the non-negotiable half. A
// repository's lint configuration is not a defect in its code, and a gate that
// rejected a change over someone's .golangci.yml would spend more trust than
// this section can earn. The same tree, with and without the configuration,
// must reach the same verdict, the same exit code and the same claims.
func TestPolicyShadowNeverChangesTheVerdict(t *testing.T) {
	withConfig := run(t, shadowFixture(t, true), verify.ModeAudit)
	without := run(t, shadowFixture(t, false), verify.ModeAudit)

	if withConfig.Decision.Verdict != without.Decision.Verdict {
		t.Fatalf("a lint configuration changed the verdict: %s then %s",
			without.Decision.Verdict, withConfig.Decision.Verdict)
	}
	if withConfig.Decision.Verdict.ExitCode() != without.Decision.Verdict.ExitCode() {
		t.Fatalf("a lint configuration changed the exit code")
	}
	if len(withConfig.Decision.Claims) != len(without.Decision.Claims) {
		t.Fatalf("a lint configuration changed the claim set")
	}
	for i, claim := range withConfig.Decision.Claims {
		if claim.State != without.Decision.Claims[i].State {
			t.Fatalf("claim %s = %s with a configuration and %s without",
				claim.Dimension, claim.State, without.Decision.Claims[i].State)
		}
	}
	for _, e := range withConfig.Evidence {
		for _, id := range []string{tool.ShadowLintersOff, tool.ShadowTestExclusion, tool.ShadowCheckBlank} {
			if e.RuleID == id {
				t.Fatalf("the shadow became evidence: %+v", e)
			}
		}
	}
}

// TestPolicyShadowIsAuditOnly keeps the section where it belongs. Verify judges
// a diff and has nothing to say about the repository's standing configuration.
func TestPolicyShadowIsAuditOnly(t *testing.T) {
	f := shadowFixture(t, true)
	f.write("lib/lib.go", renamedAnswerLibrary)
	result := run(t, f, verify.ModeVerify)
	if result.PolicyShadow != nil {
		t.Fatalf("verify reported a policy shadow: %+v", result.PolicyShadow)
	}
	if doc := report.Build("test", result); doc.PolicyShadow != nil {
		t.Fatalf("a verify document carries the section: %+v", doc.PolicyShadow)
	}
	requireVerdict(t, result, admission.VerdictAdmitted)
}

// TestPolicyShadowDeclaresWhatItCannotRead is the honest-absence case: a
// configuration in a form this scan does not read says so rather than being
// silently treated as empty.
func TestPolicyShadowDeclaresWhatItCannotRead(t *testing.T) {
	useGolangci(t)
	provisionSnapshot(t)
	f := newFixtureIn(t, layout{})
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write(".golangci.toml", "[linters]\ndisable-all = true\n")
	f.commit("a configuration in a form the scan does not read")

	shadow := run(t, f, verify.ModeAudit).PolicyShadow
	if shadow == nil || shadow.Analysed || shadow.Reason == "" {
		t.Fatalf("an unreadable configuration was not declared: %+v", shadow)
	}
}

// TestNoConfigMeansNoSection is the false-positive guard: a repository that
// carries no golangci configuration gets no block at all, not an empty one that
// reads as an answer.
func TestNoConfigMeansNoSection(t *testing.T) {
	f := shadowFixture(t, false)
	result := run(t, f, verify.ModeAudit)
	if result.PolicyShadow != nil {
		t.Fatalf("a repository with no configuration produced a section: %+v", result.PolicyShadow)
	}
	if doc := report.Build("test", result); doc.PolicyShadow != nil {
		t.Fatalf("the document carries an empty section: %+v", doc.PolicyShadow)
	}
}
