package verify_test

import (
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// TestReportsAreByteIdenticalAcrossRuns is the determinism guarantee, checked
// where it is actually made rather than in a document.
//
// A verdict that moves between two runs over one unchanged tree is worse than a
// wrong verdict, because nothing built on top of it can be trusted either. The
// fixture is deliberately not clean: ordering, fingerprints and occurrence
// numbering only have anything to prove when there is evidence to order.
func TestReportsAreByteIdenticalAcrossRuns(t *testing.T) {
	useGolangci(t)
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())
	f := newFixture(t)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", ineffectiveLibraryTest)
	f.write("worker/worker.go", leakyWorker)
	f.commit("baseline with debt, a weak test, and a goroutine")
	f.write("lib/lib.go", debtPlusAdditionLibrary)
	f.write("worker/worker_test.go", stoppedWorkerTest)
	f.commit("a change that touches tests and concurrency")

	first := runWith(t, f, verify.Options{Mode: verify.ModeVerify, NoCache: true})
	second := runWith(t, f, verify.Options{Mode: verify.ModeVerify, NoCache: true})

	if got, want := deterministic(t, second), deterministic(t, first); got != want {
		t.Fatalf("two runs over one tree disagreed:\nsecond:\n%s\nfirst:\n%s", got, want)
	}
	if len(first.Evidence) == 0 {
		t.Fatal("the fixture produced no evidence, so determinism was not exercised")
	}
}
