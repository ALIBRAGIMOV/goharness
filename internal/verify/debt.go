package verify

import (
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// applyDebtLedger marks the findings an acknowledged-debt ledger already
// records as pre-existing.
//
// That is the whole mechanism, and deliberately so. Pre-existing evidence
// already has a meaning the gate decides by, in Blocking: it stops blocking
// unless its rule is ungrandfatherable. Routing the ledger through that one
// path rather than inventing a second one means the un-baselineable core needs
// no defending here, a hand-written entry for a suppression has no effect
// whatever it says, and there is exactly one place in the harness where a
// finding can stop blocking on the strength of its age.
//
// A nil ledger leaves every finding exactly as it was, which is what every mode
// but audit gets.
func applyDebtLedger(ledger *policy.DebtLedger, items []evidence.Evidence) []evidence.Evidence {
	if ledger == nil {
		return items
	}
	acknowledged := ledger.Fingerprints()
	out := make([]evidence.Evidence, 0, len(items))
	for _, e := range items {
		if acknowledged[e.Fingerprint] {
			e.State = evidence.StatePreexisting
		}
		out = append(out, e)
	}
	return out
}

// DebtRecordable reports whether a finding may be written into a ledger.
//
// Two conditions, both narrowing. A rule in the ungrandfatherable core can
// never be acknowledged, because an entry for it would be a promise the gate
// does not keep. And only a finding that actually blocks is recorded: an
// advisory one is not standing in anyone's way, and recording it would mean
// that promoting its rule to required later found the debt already forgiven,
// which is grandfathering the bar rather than the findings.
func DebtRecordable(e evidence.Evidence) bool {
	return Blocking(e) && !policy.IsUngrandfatherable(e.RuleID)
}
