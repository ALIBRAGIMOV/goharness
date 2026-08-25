package cli

import (
	"io"
	"os"
	"path/filepath"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// ledgerFileMode is the permission a recorded ledger is written with. It is a
// checked-in document like any other source file.
const ledgerFileMode = 0o600

// recordBaseline writes the acknowledged-debt ledger from a finished audit.
//
// It runs here, in the command layer, after verify.Run has returned. Writing it
// from inside the run would trip the worktree guard, and rightly so: a
// verification that modified the tree it was judging would have produced
// evidence about a tree that no longer exists. Recording is a separate act with
// a separate command, and the verdict it reports is the audit's own, unchanged.
func recordBaseline(w io.Writer, result verify.Result, code int) int {
	out := newPrinter(w)
	if result.Decision.Verdict == admission.VerdictInconclusive {
		out.line("goharness audit --baseline: nothing was recorded.")
		out.line("  The run was INCONCLUSIVE, so its finding set is not a complete enumeration,")
		out.line("  and a ledger recorded from an incomplete one would acknowledge debt that was")
		out.line("  never measured. Resolve the unproducible evidence above, then record.")
		return exitFor(out, code)
	}

	// A finding an existing ledger already acknowledges no longer blocks, so it
	// would fail the recordable test and silently drop out of the new file. It is
	// carried forward instead: re-recording is meant to add what is new and drop
	// what is fixed, never to forget what was already accepted.
	acknowledged := map[string]bool{}
	if result.Debt != nil {
		acknowledged = result.Debt.Fingerprints()
	}
	ledger := policy.DebtLedger{Schema: policy.DebtSchema, RecordedAt: recordedRevision(result)}
	skipped := 0
	for _, e := range result.Evidence {
		switch {
		case policy.IsUngrandfatherable(e.RuleID):
			if verify.Blocking(e) {
				skipped++
			}
		case verify.DebtRecordable(e) || acknowledged[e.Fingerprint]:
			ledger.Entries = append(ledger.Entries, policy.DebtEntry{
				Fingerprint: e.Fingerprint, RuleID: e.RuleID, File: e.File,
			})
		}
	}

	path := filepath.Join(result.Repository.Root, policy.DebtFileName)
	if err := os.WriteFile(path, policy.RenderDebtLedger(ledger), ledgerFileMode); err != nil {
		out.line("goharness audit --baseline: writing %s: %v", policy.DebtFileName, err)
		return ExitInconclusive
	}

	out.line("wrote %s: %d acknowledged finding(s) at %s",
		policy.DebtFileName, len(ledger.Entries), ledger.RecordedAt)
	if skipped > 0 {
		out.line("  %d blocking finding(s) were not recorded: their rules can never be", skipped)
		out.line("  acknowledged by any ledger. They still block, and fixing them is the only way")
		out.line("  past them. `goharness explain <RULE-ID>` says why for each.")
	}
	out.line("  Commit and review this file before it has any effect: an audit reads the copy")
	out.line("  at HEAD, never the working tree, so a change can never baseline itself.")
	out.line("  Editing it is an edit to the gate and is reported as GH-POLICY-001.")
	return exitFor(out, code)
}

// recordedRevision names the commit the ledger describes, or says outright that
// there was none. A ledger with no revision to name has nothing to be true of
// and, being uncommitted, will have no effect until one exists.
func recordedRevision(result verify.Result) string {
	if result.Repository.Head == "" {
		return policy.DebtRecordedUncommitted
	}
	return result.Repository.Head
}
