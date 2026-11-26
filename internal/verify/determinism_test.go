package verify_test

import (
	"fmt"
	"strings"
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

// TestReportsAreByteIdenticalAcrossWorkingDirectories is the invocation
// invariance property: evidence is a function of the repository, the revision,
// the policy and the database, and of nothing else.
//
// A scanner that resolves the Go version it judges the standard library
// against by shelling out with neither a directory nor an environment reads the
// harness's own working directory, so two audits of one commit can reach two
// different security verdicts depending on where the operator stood. Nothing in
// either report would say so, and both would look equally authoritative.
func TestReportsAreByteIdenticalAcrossWorkingDirectories(t *testing.T) {
	useGolangci(t)
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())

	build := func(t *testing.T, lay layout) string {
		t.Helper()
		f := newFixtureIn(t, lay)
		f.write("lib/lib.go", uncheckedErrorLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("baseline with debt")
		f.write("lib/lib.go", debtPlusAdditionLibrary)
		f.commit("a change that adds no findings")
		return deterministic(t, runWith(t, f, verify.Options{Mode: verify.ModeVerify, NoCache: true}))
	}

	// Cells are grouped by repository shape before they are compared. Two
	// layouts with different module prefixes are different repositories, down to
	// the commit hashes, so requiring their reports to match would be asserting
	// something untrue. The property under test is narrower: one repository,
	// one revision, more than one place to stand.
	byShape := map[string][]string{}
	for _, lay := range layouts() {
		t.Run(lay.name, func(t *testing.T) {
			byShape[lay.prefix] = append(byShape[lay.prefix], build(t, lay))
		})
	}
	for prefix, reports := range byShape {
		for i := 1; i < len(reports); i++ {
			if reports[i] != reports[0] {
				t.Fatalf("module prefix %q: invocation %d produced a different report than the first\n%s",
					prefix, i, firstDifference(reports[0], reports[i]))
			}
		}
	}
}

// TestHostileEnvironmentCannotMoveTheReport covers the settings that change what
// a check concludes without changing a line of code under it. GOTOOLCHAIN names
// a release that does not exist, GOFLAGS adds a build tag, and the working
// directory is somewhere else entirely; the verdict must not notice.
func TestHostileEnvironmentCannotMoveTheReport(t *testing.T) {
	useGolangci(t)
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())

	build := func(t *testing.T, hostile bool) string {
		t.Helper()
		f := newFixtureIn(t, subdirLayout())
		f.write("lib/lib.go", uncheckedErrorLibrary)
		f.write("lib/lib_test.go", cleanLibraryTest)
		f.commit("baseline with debt")
		f.write("lib/lib.go", debtPlusAdditionLibrary)
		f.commit("a change that adds no findings")
		if hostile {
			t.Setenv("GOFLAGS", "-tags=nonsense")
			t.Setenv("GOTOOLCHAIN", "go1.99.0")
		}
		return deterministic(t, runWith(t, f, verify.Options{Mode: verify.ModeVerify, NoCache: true}))
	}

	var calm, hostile string
	t.Run("calm", func(t *testing.T) { calm = build(t, false) })
	t.Run("hostile", func(t *testing.T) { hostile = build(t, true) })
	if calm != hostile {
		t.Fatalf("a hostile environment moved the report\n%s", firstDifference(calm, hostile))
	}
}

// firstDifference names the first line two reports disagree on, because a diff
// of two documents this size is unreadable and the first divergence is almost
// always the whole story.
func firstDifference(a, b string) string {
	aLines, bLines := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range max(len(aLines), len(bLines)) {
		var left, right string
		if i < len(aLines) {
			left = aLines[i]
		}
		if i < len(bLines) {
			right = bLines[i]
		}
		if left != right {
			return fmt.Sprintf("line %d:\n  first:  %s\n  second: %s", i+1, left, right)
		}
	}
	return "the documents are equal"
}
