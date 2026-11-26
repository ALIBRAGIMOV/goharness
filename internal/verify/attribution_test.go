package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestAHarnessFaultIsNeverAttributedToTheRepositoryOrItsTools holds the line
// between a tool fault and a fact about the code.
//
// "1 changed Go file was compiled by nothing" is an assertion about the
// repository, and it is false when the truth is that the harness failed to
// resolve a path. An agent told its file is compiled by nothing goes hunting
// for a build-constraint problem that does not exist. A fault inside goharness
// leaves through a channel that says so and names goharness as its owner.
func TestAHarnessFaultIsNeverAttributedToTheRepositoryOrItsTools(t *testing.T) {
	t.Parallel()
	fault := harnessError{err: errors.New("could not resolve backend/lib.go")}
	who := attribute("go/build", "change-visibility", fault)
	if who.tool != "goharness" {
		t.Fatalf("a harness fault was attributed to %q", who.tool)
	}
	if !strings.Contains(who.reason, "goharness itself failed") || !strings.Contains(who.reason, "failures[]") {
		t.Fatalf("the gap does not say who failed or where to look: %q", who.reason)
	}
}

// TestAToolFailureKeepsItsTool is the false-positive guard: the split must not
// start blaming goharness for the external programs it drives.
func TestAToolFailureKeepsItsTool(t *testing.T) {
	t.Parallel()
	who := attribute("golangci-lint", "lint", errors.New("exit status 3"))
	if who.tool != "golangci-lint" {
		t.Fatalf("a tool failure was attributed to %q", who.tool)
	}
	if !strings.Contains(who.reason, "lint failed") {
		t.Fatalf("the gap does not name the check that failed: %q", who.reason)
	}
	if who.detail != "exit status 3" {
		t.Fatalf("the failure text was rewritten: %q", who.detail)
	}
}

// TestARunDeadlineIsTheRunsOwnFault pins the attribution that two releases'
// worth of CI reports got wrong: "go test -race: context deadline exceeded"
// with no hint reads as a broken toolchain, when the only thing that ran out
// was goharness's own --timeout.
func TestARunDeadlineIsTheRunsOwnFault(t *testing.T) {
	t.Parallel()
	expired := fmt.Errorf("go: %w", context.DeadlineExceeded)
	who := attribute("go test -race", "race-test", expired)
	if who.tool != "goharness" {
		t.Fatalf("an expired deadline was attributed to %q", who.tool)
	}
	for _, text := range []string{who.reason, who.detail} {
		if !strings.Contains(text, "--timeout") || !strings.Contains(text, "race-test") {
			t.Fatalf("the reason does not name the deadline and the check it cut short: %q", text)
		}
	}
	if !strings.Contains(who.remedy, "--timeout") {
		t.Fatalf("the remedy does not say what to raise: %q", who.remedy)
	}
}

// TestAnInterruptedCheckIsNotAToolFailure is the same line for Ctrl+C: a
// check that stopped because the operator stopped it has nothing to say about
// the tool it was driving.
func TestAnInterruptedCheckIsNotAToolFailure(t *testing.T) {
	t.Parallel()
	who := attribute("golangci-lint", "golangci-lint", fmt.Errorf("golangci-lint: %w", context.Canceled))
	if who.tool != "goharness" {
		t.Fatalf("an interrupted check was attributed to %q", who.tool)
	}
	if !strings.Contains(who.reason, "interrupted") {
		t.Fatalf("the reason does not say the run was interrupted: %q", who.reason)
	}
}
