package verify_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/cli"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The ledger is the one mechanism in this harness that exists to accept
// findings, which makes it the one place where a mistake reads as the tool
// getting easier. Every case here asserts a bar that did not move: an
// uncommitted ledger has no effect, an entry for the mandatory core has no
// effect, and the only thing a committed ledger changes is that findings it
// names, and nothing else, stop blocking an audit.

// debtFixture is a repository with one baselineable defect, a provisioned
// vulnerability snapshot so the audit reaches a determinate verdict, and a
// commit to read a ledger from.
func debtFixture(t *testing.T, lay layout) *fixture {
	t.Helper()
	useGolangci(t)
	provisionSnapshot(t)
	f := newFixtureIn(t, lay)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("a repository that arrives with debt")
	return f
}

// ledgerFor renders a ledger acknowledging exactly the named findings, as a
// hand-written one would look.
func ledgerFor(revision string, items []evidence.Evidence, ruleID string) []byte {
	ledger := policy.DebtLedger{Schema: policy.DebtSchema, RecordedAt: revision}
	for _, e := range items {
		if ruleID != "" && e.RuleID != ruleID {
			continue
		}
		ledger.Entries = append(ledger.Entries, policy.DebtEntry{
			Fingerprint: e.Fingerprint, RuleID: e.RuleID, File: e.File,
		})
	}
	return policy.RenderDebtLedger(ledger)
}

// runBaseline drives the real command, because the guarantee under test is that
// recording happens after the run and outside it.
func runBaseline(t *testing.T, f *fixture) int {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Main(t.Context(),
		[]string{"audit", "--baseline", "--dir", f.verifyDir()},
		cli.Streams{Out: &out, Err: &errOut})
	if !strings.Contains(out.String()+errOut.String(), policy.DebtFileName) {
		t.Fatalf("audit --baseline said nothing about the ledger:\n%s\n%s", out.String(), errOut.String())
	}
	return code
}

func ledgerPath(f *fixture) string {
	return filepath.Join(f.moduleDir, policy.DebtFileName)
}

func baselineBlock(t *testing.T, result verify.Result) report.Baseline {
	t.Helper()
	doc := report.Build("test", result)
	if doc.Baseline == nil {
		t.Fatalf("the report carries no baseline block; ledger = %+v", result.Debt)
	}
	return *doc.Baseline
}

// TestBypassUncommittedDebtLedgerHasNoEffect closes the route by which a change
// baselines itself: writing the ledger it wants to be judged against.
func TestBypassUncommittedDebtLedgerHasNoEffect(t *testing.T) {
	f := debtFixture(t, layout{})

	first := run(t, f, verify.ModeAudit)
	requireVerdict(t, first, admission.VerdictRejected)
	if !slices.Contains(blockingRules(first.Evidence), policy.RuleErrcheck) {
		t.Fatalf("the fixture produced no baselineable debt: %v", ruleIDs(first.Evidence))
	}

	f.write(policy.DebtFileName, string(ledgerFor("HEAD", first.Evidence, "")))

	second := run(t, f, verify.ModeAudit)
	requireVerdict(t, second, admission.VerdictRejected)
	if second.Debt != nil {
		t.Fatalf("an uncommitted ledger was read: %+v", second.Debt)
	}
	if !slices.Contains(blockingRules(second.Evidence), policy.RuleErrcheck) {
		t.Fatalf("an uncommitted ledger silenced a finding: %v", blockingRules(second.Evidence))
	}
	// The other half: writing to the gate is itself reportable, so the attempt
	// leaves a record rather than merely failing.
	if !slices.Contains(blockingRules(second.Evidence), policy.RulePolicyEdit) {
		t.Fatalf("editing the ledger did not fire the policy guard: %v", blockingRules(second.Evidence))
	}
}

// TestBypassDebtLedgerCannotAcknowledgeASuppression pins the un-baselineable
// core: a hand-written entry for a mandatory rule is accepted by the parser and
// changes nothing at all.
func TestBypassDebtLedgerCannotAcknowledgeASuppression(t *testing.T) {
	useGolangci(t)
	provisionSnapshot(t)
	f := newFixtureIn(t, layout{})
	f.write("lib/lib.go", suppressedLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("a repository that arrives with a suppression")

	first := run(t, f, verify.ModeAudit)
	requireVerdict(t, first, admission.VerdictRejected)

	f.write(policy.DebtFileName, string(ledgerFor("HEAD", first.Evidence, policy.RuleSuppressNolint)))
	f.commit("acknowledge a suppression as debt")
	f.write("lib/second.go", cleanSecondLibrary)
	f.commit("a later commit, so the ledger is history rather than this diff")

	result := run(t, f, verify.ModeAudit)
	if result.Debt == nil || len(result.Debt.Entries) == 0 {
		t.Fatalf("the committed ledger was not read: %+v", result.Debt)
	}
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleSuppressNolint) {
		t.Fatalf("a ledger entry silenced a suppression: %v", blockingRules(result.Evidence))
	}
	if base := baselineBlock(t, result); base.Unbaselineable == 0 {
		t.Fatalf("the burn-down does not report the finding no ledger can accept: %+v", base)
	}
}

// TestDebtLedgerAdmitsOnlyBaselineableDebt is the pair the release turns on: the
// same recording makes a repository whose debt is baselineable admissible, and
// leaves one whose debt is not exactly where it was.
func TestDebtLedgerAdmitsOnlyBaselineableDebt(t *testing.T) {
	t.Run("baselineable debt is admitted", func(t *testing.T) {
		f := debtFixture(t, layout{})
		requireVerdict(t, run(t, f, verify.ModeAudit), admission.VerdictRejected)

		if code := runBaseline(t, f); code != cli.ExitRejected {
			t.Fatalf("audit --baseline exit = %d, want the audit's own %d", code, cli.ExitRejected)
		}
		f.commit("record the acknowledged debt")
		f.write("lib/second.go", cleanSecondLibrary)
		f.commit("a later commit, so the ledger is history rather than this diff")

		result := run(t, f, verify.ModeAudit)
		requireVerdict(t, result, admission.VerdictAdmitted)
		base := baselineBlock(t, result)
		if base.New != 0 || base.StillPresent == 0 || base.FixedSince != 0 {
			t.Fatalf("burn-down after recording = %+v, want every entry still present and nothing new", base)
		}
		if base.RecordedAt == policy.DebtRecordedUncommitted {
			t.Fatalf("the ledger names no revision: %+v", base)
		}
	})

	t.Run("a suppression is not", func(t *testing.T) {
		f := debtFixture(t, layout{})
		f.write("lib/suppressed.go", suppressedSecondLibrary)
		f.commit("add a suppression to the same repository")

		runBaseline(t, f)
		f.commit("record the acknowledged debt")
		f.write("lib/second.go", cleanSecondLibrary)
		f.commit("a later commit, so the ledger is history rather than this diff")

		result := run(t, f, verify.ModeAudit)
		requireVerdict(t, result, admission.VerdictRejected)
		if !slices.Contains(blockingRules(result.Evidence), policy.RuleSuppressNolint) {
			t.Fatalf("recording made a suppression stop blocking: %v", blockingRules(result.Evidence))
		}
		// The recorded file must not even contain the entry, so nobody reviewing it
		// is told a promise the gate does not keep.
		recorded, err := os.ReadFile(ledgerPath(f))
		if err != nil {
			t.Fatalf("reading the recorded ledger: %v", err)
		}
		if strings.Contains(string(recorded), policy.RuleSuppressNolint) {
			t.Fatalf("the recorded ledger names a rule no ledger can accept:\n%s", recorded)
		}
	})
}

// TestDebtLedgerBurnDownCountsWhatWasFixed is the false-positive guard for the
// ratchet: repaying acknowledged debt has to be visible and must not be
// mistaken for a change that introduced something.
func TestDebtLedgerBurnDownCountsWhatWasFixed(t *testing.T) {
	f := debtFixture(t, layout{})
	runBaseline(t, f)
	f.commit("record the acknowledged debt")
	f.write("lib/second.go", cleanSecondLibrary)
	f.commit("a later commit, so the ledger is history rather than this diff")

	before := run(t, f, verify.ModeAudit)
	requireVerdict(t, before, admission.VerdictAdmitted)
	recorded := baselineBlock(t, before)

	f.write("lib/lib.go", cleanLibrary)
	f.commit("repay one acknowledged finding")

	after := run(t, f, verify.ModeAudit)
	requireVerdict(t, after, admission.VerdictAdmitted)
	burnDown := baselineBlock(t, after)
	if burnDown.FixedSince == 0 {
		t.Fatalf("repaying debt did not show as fixed: %+v", burnDown)
	}
	if burnDown.New != 0 {
		t.Fatalf("repaying debt introduced %d new blocking finding(s): %+v", burnDown.New, burnDown)
	}
	if burnDown.StillPresent >= recorded.StillPresent {
		t.Fatalf("burn-down did not move: %+v then %+v", recorded, burnDown)
	}
	if burnDown.Entries != recorded.Entries {
		t.Fatalf("the ledger changed without being rewritten: %d then %d", recorded.Entries, burnDown.Entries)
	}
}

// TestDebtLedgerWorksWhereTheModuleIsNotTheGitRoot runs the whole loop in the
// layout the field report's subject had. The ledger is read and written at the
// module root, and every path defect this project has shipped lived in the gap
// between that and the repository root.
func TestDebtLedgerWorksWhereTheModuleIsNotTheGitRoot(t *testing.T) {
	f := debtFixture(t, subdirLayout())
	requireVerdict(t, run(t, f, verify.ModeAudit), admission.VerdictRejected)

	runBaseline(t, f)
	if _, err := os.Stat(ledgerPath(f)); err != nil {
		t.Fatalf("the ledger was not written at the module root: %v", err)
	}
	f.commit("record the acknowledged debt")
	f.write("lib/second.go", cleanSecondLibrary)
	f.commit("a later commit, so the ledger is history rather than this diff")

	result := run(t, f, verify.ModeAudit)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if base := baselineBlock(t, result); base.StillPresent == 0 {
		t.Fatalf("the ledger was read but acknowledged nothing: %+v", base)
	}
}

// TestVerifyIgnoresTheDebtLedger keeps the two mechanisms apart. Verify has a
// real base revision to compare against, and a mode that consulted both could
// be handed whichever answer suited the change.
func TestVerifyIgnoresTheDebtLedger(t *testing.T) {
	useGolangci(t)
	f := newFixtureIn(t, layout{})
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write(policy.DebtFileName, "schema: 1\nrecordedAt: HEAD\nentries:\n")
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.commit("introduce debt alongside an empty ledger")

	result := run(t, f, verify.ModeVerify)
	if result.Debt != nil {
		t.Fatalf("verify read a debt ledger: %+v", result.Debt)
	}
	doc := report.Build("test", result)
	if doc.Baseline != nil {
		t.Fatalf("verify emitted a baseline block: %+v", doc.Baseline)
	}
	requireVerdict(t, result, admission.VerdictRejected)
}
