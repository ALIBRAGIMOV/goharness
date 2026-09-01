package verify_test

import (
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The base revision runs a test package only where head's own run of it said
// something. A base test result is consumed by exactly one thing, the
// comparison that decides whether a head failure or leak already existed, so
// running the whole closure at base paid for the most expensive check twice
// to learn nothing the verdict uses. These tests pin both halves: the base
// still runs where it has to, and runs nothing where it does not.

const boundedWorker = `package worker

// Bounded reports whether n items fit the worker's queue.
func Bounded(n int) bool {
	queue := make(chan int, 4)
	return n <= cap(queue)
}
`

const boundedWorkerTest = `package worker

import "testing"

func TestBoundedStopsAtTheQueueCapacity(t *testing.T) {
	if !Bounded(4) {
		t.Fatal("four items fit the queue")
	}
	if Bounded(5) {
		t.Fatal("five items do not fit the queue")
	}
}
`

func TestTestFailingAtBaseAndHeadIsPreexisting(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", wrongAnswerLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline whose own test already fails")
	f.anchor()
	f.write("lib/second.go", cleanSecondLibrary)

	result := run(t, f, verify.ModeVerify)
	if slices.Contains(blockingRules(result.Evidence), policy.RuleTestFailure) {
		t.Fatalf("a test that failed before the change blocks it: %+v", result.Evidence)
	}
	var failures int
	for _, e := range result.Evidence {
		if e.RuleID != policy.RuleTestFailure {
			continue
		}
		failures++
		if e.State != evidence.StatePreexisting {
			t.Fatalf("the failure is %q, want %q; the base did not run the package that failed at head",
				e.State, evidence.StatePreexisting)
		}
	}
	if failures == 0 {
		t.Fatalf("head's failing test produced no row: %v", ruleIDs(result.Evidence))
	}
	if want := []string{fixtureModule + "/lib"}; !slices.Equal(result.BaseTestPackages, want) {
		t.Fatalf("base test packages = %v, want %v", result.BaseTestPackages, want)
	}
}

func TestBaseTestsRunOnlyWhereHeadTestsSaidSomething(t *testing.T) {
	useGolangci(t)
	t.Run("a passing suite runs no base tests", func(t *testing.T) {
		f := newFixture(t)
		f.write("lib/lib.go", cleanLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("clean baseline")
		f.anchor()
		f.write("lib/lib.go", renamedAnswerLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictAdmitted)
		if len(result.BaseTestPackages) != 0 {
			t.Fatalf("the base ran tests nothing could consume: %v", result.BaseTestPackages)
		}
	})
	t.Run("a failing suite runs the failing package at base", func(t *testing.T) {
		f := newFixture(t)
		f.write("lib/lib.go", cleanLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("clean baseline")
		f.anchor()
		f.write("lib/lib.go", wrongAnswerLibrary)

		result := run(t, f, verify.ModeVerify)
		requireVerdict(t, result, admission.VerdictRejected)
		if want := []string{fixtureModule + "/lib"}; !slices.Equal(result.BaseTestPackages, want) {
			t.Fatalf("base test packages = %v, want %v", result.BaseTestPackages, want)
		}
		for _, e := range result.Evidence {
			if e.RuleID == policy.RuleTestFailure && e.State != evidence.StateNew {
				t.Fatalf("a failure the change introduced is %q", e.State)
			}
		}
	})
}

// TestLeakPresentAtBaseAndHeadIsPreexisting is the base side of goroutine-leak
// evidence. Until the base ran the detector, every leak in the closure was new
// and blocked, including one in a helper the change never opened: a production
// run rejected a merge request for four leaks in a package it did not touch.
// The guard that a leak the change introduces still blocks is
// TestLeakedGoroutineRejectsTheChange.
func TestLeakPresentAtBaseAndHeadIsPreexisting(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("worker/worker.go", leakyWorker)
	f.write("worker/worker_test.go", leakingWorkerTest)
	f.commit("baseline that already leaks")
	f.anchor()
	f.write("worker/limits.go", boundedWorker)
	f.write("worker/limits_test.go", boundedWorkerTest)

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	var leaks int
	for _, e := range result.Evidence {
		if e.RuleID != policy.RuleGoroutineLeak {
			continue
		}
		leaks++
		if e.State != evidence.StatePreexisting {
			t.Fatalf("a leak the base already had is %q, want %q", e.State, evidence.StatePreexisting)
		}
	}
	if leaks == 0 {
		t.Fatalf("the leak was not observed at head: %v", ruleIDs(result.Evidence))
	}
	if want := []string{fixtureModule + "/worker"}; !slices.Equal(result.BaseTestPackages, want) {
		t.Fatalf("base test packages = %v, want %v", result.BaseTestPackages, want)
	}
}
