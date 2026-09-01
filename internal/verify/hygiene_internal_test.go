package verify

import (
	"errors"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// TestPathHygieneRefusesEvidenceOutsideTheTree pins the guard directly, because
// the integration case that needs it can only observe its absence as a wrong
// state on a finding, and a reader of that failure has to work backwards.
func TestPathHygieneRefusesEvidenceOutsideTheTree(t *testing.T) {
	t.Parallel()
	for _, file := range []string{
		"/private/var/folders/x/T/goharness-base-1844525834/tree/internal/search/index.go",
		"../outside/lib.go",
		"..",
	} {
		err := pathHygiene("gofix", []evidence.Evidence{{RuleID: "GO-FIX-inline", File: file}})
		if err == nil {
			t.Fatalf("a finding at %q was accepted", file)
		}
		fault, ok := errors.AsType[harnessError](err)
		if !ok {
			t.Fatalf("the fault at %q is not attributed to goharness: %v", file, err)
		}
		if !strings.Contains(fault.Error(), "gofix") {
			t.Fatalf("the fault does not name the check that produced it: %v", fault)
		}
	}
}

// TestPathHygieneAcceptsEveryShapeTheHarnessProduces is the false-positive
// guard. Module-relative files, package directories used as anchors, and the
// rows that carry no location at all are all legitimate.
func TestPathHygieneAcceptsEveryShapeTheHarnessProduces(t *testing.T) {
	t.Parallel()
	err := pathHygiene("native", []evidence.Evidence{
		{RuleID: "GH-COMMENT-001", File: "internal/search/index.go"},
		{RuleID: "GH-LEAK-001", File: "internal/httpserver"},
		{RuleID: "GH-MOD-001", File: "go.mod"},
		{RuleID: "GH-TEST-FAIL", Package: "example.com/x/lib"},
		{RuleID: "GH-BENCH-001"},
	})
	if err != nil {
		t.Fatalf("a legitimate evidence set was refused: %v", err)
	}
}

// TestOneLeakSiteIsOneFinding pins the collapse.
//
// The leak run reports a site once per test package that reached it, so one leaking
// helper produced thirty-six identical rows on a production run and the report
// told its reader to fix each of them. The site is the unit of repair.
func TestOneLeakSiteIsOneFinding(t *testing.T) {
	t.Parallel()
	site := &leakSite{
		file: "internal/metrics/sender.go", line: 182, pkg: "example.com/x/httpserver",
		funcs:    map[string]bool{"stat.(*Sender).loop": true, "database/sql.(*DB).opener": true},
		packages: map[string]bool{"a": true, "b": true, "c": true},
	}
	msg := site.message()
	// Sorted, because the order the profile prints them in is the order the runtime
	// produced them and it moves between runs.
	if !strings.Contains(msg, "database/sql.(*DB).opener, stat.(*Sender).loop") {
		t.Fatalf("the leaked functions are not in a stable order: %q", msg)
	}
	if !strings.Contains(msg, "observed in 3 test packages") {
		t.Fatalf("the message does not say how widely the site was reached: %q", msg)
	}
	if single := (&leakSite{funcs: map[string]bool{"f": true},
		packages: map[string]bool{"a": true}}).message(); strings.Contains(single, "observed in") {
		t.Fatalf("a site reached once counts itself: %q", single)
	}
}

// TestAPackageMeasuredByDirectoryIsStillPlaced covers the producers that
// identify a package by the directory they measured rather than by its import
// path. Both readings have to be tried, or a maintainability delta for the very
// package the change edited comes out as untouched.
func TestAPackageMeasuredByDirectoryIsStillPlaced(t *testing.T) {
	t.Parallel()
	scope := diffScope{
		files: map[string]bool{"internal/verify/engine.go": true},
		dirs:  map[string]bool{"internal/verify": true},
		whole: map[string]bool{},
	}
	target := &target{}
	measured := evidence.Evidence{RuleID: "GH-MNT-003", Package: "internal/verify"}
	if got := target.originOf(measured, scope); got != evidence.OriginChangedPackage {
		t.Fatalf("a package measured by directory is %q, want %q",
			got, evidence.OriginChangedPackage)
	}
	elsewhere := evidence.Evidence{RuleID: "GH-MNT-003", Package: "internal/report"}
	if got := target.originOf(elsewhere, scope); got != evidence.OriginUntouched {
		t.Fatalf("an unrelated package is %q, want %q", got, evidence.OriginUntouched)
	}
}
