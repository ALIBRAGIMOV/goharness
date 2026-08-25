package verify

import (
	"errors"
	"strings"
	"testing"
)

// TestAHarnessFaultIsNeverAttributedToTheRepositoryOrItsTools holds the
// taxonomy line a production audit crossed.
//
// The run reported "1 changed Go file was compiled by nothing", an assertion
// about the repository that was false; the true statement was that the harness
// had failed to resolve a path. An agent told its file is compiled by nothing
// goes hunting for a build-constraint problem that does not exist, and this
// run's operator did exactly that. A fault inside goharness leaves through a
// channel that says so and names goharness as its owner.
func TestAHarnessFaultIsNeverAttributedToTheRepositoryOrItsTools(t *testing.T) {
	t.Parallel()
	fault := harnessError{err: errors.New("could not resolve backend/lib.go")}
	owner, reason := attribute("go/build", "change-visibility", fault)
	if owner != "goharness" {
		t.Fatalf("a harness fault was attributed to %q", owner)
	}
	if !strings.Contains(reason, "goharness itself failed") || !strings.Contains(reason, "failures[]") {
		t.Fatalf("the gap does not say who failed or where to look: %q", reason)
	}
}

// TestAToolFailureKeepsItsTool is the false-positive guard: the split must not
// start blaming goharness for the external programs it drives.
func TestAToolFailureKeepsItsTool(t *testing.T) {
	t.Parallel()
	owner, reason := attribute("golangci-lint", "lint", errors.New("exit status 3"))
	if owner != "golangci-lint" {
		t.Fatalf("a tool failure was attributed to %q", owner)
	}
	if !strings.Contains(reason, "lint failed") {
		t.Fatalf("the gap does not name the check that failed: %q", reason)
	}
}
