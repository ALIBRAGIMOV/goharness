package verify_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache/toolcachetest"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// groupLibrary adds a use of the fixture module beside an existing package,
// so that the change is a new requirement and not a rewritten API.
const groupLibrary = `package lib

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Bounded runs a bounded group and returns the answer.
func Bounded(ctx context.Context) int {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return groupCtx.Err() })
	if err := group.Wait(); err != nil {
		return 0
	}
	return Answer()
}
`

const groupLibraryTest = `package lib

import (
	"context"
	"testing"
)

func TestBounded(t *testing.T) {
	if got := Bounded(context.Background()); got != 42 {
		t.Fatalf("Bounded() = %d, want 42", got)
	}
}
`

// TestVerifyWithoutADependencyChangeDoesNotScan is the false-positive guard for
// the dependency domain: a code-only change plans no vulnerability scan, so a
// machine without a snapshot still reaches a verdict on it.
func TestVerifyWithoutADependencyChangeDoesNotScan(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.anchor()
	f.write("lib/lib.go", renamedAnswerLibrary)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	if result.Risks.Has(admission.RiskDependency) {
		t.Fatalf("a code-only change activated the dependency domain: %+v", result.Risks)
	}
	for _, o := range result.Plan.Obligations {
		if o.Kind == admission.KindVulnerabilityScan {
			t.Fatalf("a code-only change planned a vulnerability scan: %+v", o)
		}
	}
}

// TestPreexistingVulnerabilityIsDebtInVerify holds the grandfathering line for
// the new scan: a vulnerability the base revision already carried is debt the
// change did not create, reported and not blocking.
func TestPreexistingVulnerabilityIsDebtInVerify(t *testing.T) {
	useGolangci(t)
	provisionSnapshot(t)
	f := vulnerableFixture(t)
	f.anchor()
	f.write("go.mod", vulnerableGoMod+"\n// the fixture pins this requirement on purpose\n")

	result := run(t, f, verify.ModeVerify)
	if slices.Contains(blockingRules(result.Evidence), policy.RuleGovulncheck) {
		t.Fatalf("a vulnerability the base already had blocks the change: %+v", result.Evidence)
	}
	var seen int
	for _, e := range result.Evidence {
		if e.RuleID != policy.RuleGovulncheck {
			continue
		}
		seen++
		if e.State != evidence.StatePreexisting {
			t.Fatalf("the vulnerability is %q, want %q", e.State, evidence.StatePreexisting)
		}
	}
	if seen == 0 {
		t.Fatalf("the scan did not run on a dependency change: %v\nunproducible: %+v",
			ruleIDs(result.Evidence), result.Unproducible)
	}
	requireVerdict(t, result, admission.VerdictAdmitted)
}

// TestNewDirectRequirementIsReported pins GH-DEP-001: a requirement that head's
// go.mod carries and base's did not is an advisory finding anchored on the
// go.mod line, whether or not a snapshot exists to scan it.
func TestNewDirectRequirementIsReported(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.anchor()
	f.write("go.mod", vulnerableGoMod)
	f.write("go.sum", toolcachetest.FixtureSums())
	f.write("lib/group.go", groupLibrary)
	f.write("lib/group_test.go", groupLibraryTest)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)
	claim := claimFor(t, result, admission.DimSecurity)
	if claim.State != admission.ClaimInconclusive ||
		!slices.Contains(claim.MissingEvidence, admission.KindVulnerabilityScan) {
		t.Fatalf("security claim = %s (%s), missing %v; want INCONCLUSIVE for the missing snapshot",
			claim.State, claim.Reason, claim.MissingEvidence)
	}
	idx := slices.IndexFunc(result.Evidence, func(e evidence.Evidence) bool {
		return e.RuleID == policy.RuleNewDependency
	})
	if idx < 0 {
		t.Fatalf("no %s finding: %v", policy.RuleNewDependency, ruleIDs(result.Evidence))
	}
	finding := result.Evidence[idx]
	if verify.Blocking(finding) {
		t.Fatalf("an advisory finding blocks: %+v", finding)
	}
	if finding.File != "go.mod" || finding.Line == 0 {
		t.Fatalf("the finding is not anchored on the go.mod line: %+v", finding)
	}
	if !strings.Contains(finding.Message, toolcachetest.FixtureModulePath) {
		t.Fatalf("the finding does not name the module: %q", finding.Message)
	}
}

// TestSQLMigrationRewriteIsRejected is the documented behaviour that never
// held: a rewritten migration activates the persistence domain by its path,
// and risk detection only ever saw the Go files of a change.
func TestSQLMigrationRewriteIsRejected(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("migrations/001_init.sql", "create table answers (id integer primary key);\n")
	f.commit("baseline with a deployed migration")
	f.anchor()
	f.write("migrations/001_init.sql", "create table answers (id bigint primary key);\n")

	result := run(t, f, verify.ModeVerify)
	if !result.Risks.Has(admission.RiskPersistence) {
		t.Fatalf("a migration edit did not activate the persistence domain: %+v", result.Risks)
	}
	requireVerdict(t, result, admission.VerdictRejected)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleMigrationRewrite) {
		t.Fatalf("blocking rules = %v, want %s", blockingRules(result.Evidence), policy.RuleMigrationRewrite)
	}
}
