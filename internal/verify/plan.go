// Package verify owns the verification pipeline: scope resolution, the runnable
// execution DAG behind the admission plan, the bounded concurrent scheduler,
// and the assembly of quality claims into an admission decision.
package verify

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// Mode selects scope and depth. Modes never change the quality threshold.
type Mode string

// Verification modes.
const (
	ModeFast   Mode = "fast"
	ModeVerify Mode = "verify"
	ModeAudit  Mode = "audit"
)

// ParseMode maps a command name onto a mode. deep is accepted as a deprecated
// alias for audit.
func ParseMode(name string) (Mode, bool) {
	switch name {
	case string(ModeFast), string(ModeVerify), string(ModeAudit):
		return Mode(name), true
	case "deep":
		return ModeAudit, true
	}
	return "", false
}

// IsAdmissionGate reports whether a mode may declare a change complete. fast is
// a developer loop aid and never is one.
func (m Mode) IsAdmissionGate() bool {
	return m == ModeVerify || m == ModeAudit
}

// checkResult is what one check returns to the coordinator: evidence it
// produced, plus any obligation it could not discharge despite running.
type checkResult struct {
	evidence     []evidence.Evidence
	unproducible []admission.Unproducible
}

type runFunc func(ctx context.Context) (checkResult, error)

// Check is one node of the runnable execution DAG.
type Check struct {
	ID        string
	Tool      string
	DependsOn []string
	Produces  []admission.EvidenceKind
	run       runFunc
}

// ExecutionPlan is the deterministic runnable DAG for one phase of a run.
type ExecutionPlan struct {
	Mode     Mode
	Checks   []Check
	Packages []string
	Files    []string
	Tests    []string
	// LocalScope names the package directories the directory-local checks
	// examined, and is nil where they examined every directory in Packages. A
	// run that looked at less than its scope has to say so, or an ADMITTED
	// cannot be audited by the person who stands behind it.
	LocalScope []string
}

// CheckIDs lists the planned check IDs in execution order.
func (p ExecutionPlan) CheckIDs() []string {
	out := make([]string, 0, len(p.Checks))
	for _, c := range p.Checks {
		out = append(out, c.ID)
	}
	return out
}

// Tools lists the distinct tools the plan will invoke, sorted.
func (p ExecutionPlan) Tools() []string {
	var out []string
	for _, c := range p.Checks {
		if c.Tool != "" && !slices.Contains(out, c.Tool) {
			out = append(out, c.Tool)
		}
	}
	slices.Sort(out)
	return out
}

// ProgressEvent reports a check starting or finishing, so a terminal front end
// can show transient progress without the engine knowing anything about
// terminals.
type ProgressEvent struct {
	Phase   string
	Check   string
	Total   int
	Done    bool
	Elapsed time.Duration
}

// CheckFailure records a tool, environment, or infrastructure failure. It is
// never evidence of a code defect: it makes the claims it was meant to support
// INCONCLUSIVE.
type CheckFailure struct {
	CheckID string `json:"checkId"`
	Tool    string `json:"tool"`
	Reason  string `json:"reason"`
	Hint    string `json:"hint,omitempty"`
}

func sortChecks(checks []Check) {
	slices.SortFunc(checks, func(a, b Check) int { return strings.Compare(a.ID, b.ID) })
}

// scopeFor returns the reverse-dependency scope a mode applies to compilation
// and lint, and the narrower scope it applies to tests.
func scopeFor(mode Mode) (lint, tests change.Scope) {
	if mode == ModeFast {
		return change.ScopeDirectDependents, change.ScopeChangedOnly
	}
	return change.ScopeFullClosure, change.ScopeFullClosure
}
