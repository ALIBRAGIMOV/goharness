package analyze_test

import (
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

func TestDeprecatedForwarderWithoutInlineDirectiveIsReported(t *testing.T) {
	t.Parallel()
	const src = `package lib

// Pow returns base raised to exp.
func Pow(base, exp int) int {
	return base * exp
}

// Square returns x squared.
//
// Deprecated: call Pow instead.
func Square(x int) int {
	return Pow(x, 2)
}

// Announce writes a line.
//
// Deprecated: call Log instead.
//go:fix inline
func Announce(msg string) {
	Log(msg)
}

// Log writes a line.
func Log(msg string) {
	_ = msg
}

// Checked keeps a decision of its own, so inlining it is not mechanical.
//
// Deprecated: call Pow instead.
func Checked(x int) int {
	if x < 0 {
		return 0
	}
	return Pow(x, 2)
}

// Dict builds a value through an unexported constructor, which a caller in
// another package could not write for itself.
//
// Deprecated: use Pow instead.
func Dict(x int) int {
	return newValue(x)
}

func newValue(x int) int {
	return x
}

// square is unexported, so it has no caller its author does not control.
//
// Deprecated: call Pow instead.
func square(x int) int {
	return Pow(x, 2)
}
`
	found := findingsFor(scan(t, "lib/lib.go", src), policy.RuleDeprecatedNoInline)
	if len(found) != 1 {
		t.Fatalf("findings = %d, want only the exported undirected forwarder: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Message, "Square") {
		t.Fatalf("the finding does not name the declaration: %q", found[0].Message)
	}
	if !found[0].Advisory {
		t.Fatal("a new rule must enter as advisory")
	}
}

func TestDeprecatedConstWithoutInlineDirectiveIsReported(t *testing.T) {
	t.Parallel()
	const src = `package lib

// Limit is the current bound.
const Limit = 64

// OldLimit is the previous bound.
//
// Deprecated: use Limit.
const OldLimit = Limit

// LegacyLimit is the bound before that.
//
// Deprecated: use Limit.
//go:fix inline
const LegacyLimit = Limit
`
	found := findingsFor(scan(t, "lib/lib.go", src), policy.RuleDeprecatedNoInline)
	if len(found) != 1 {
		t.Fatalf("findings = %d, want only the undirected constant: %+v", len(found), found)
	}
	if !strings.Contains(found[0].Message, "OldLimit") {
		t.Fatalf("the finding does not name the constant: %q", found[0].Message)
	}
}

// TestUndeprecatedForwarderStaysASimplicityFinding keeps the two rules apart:
// the simplicity scanner asks why a wrapper exists, this one asks why a
// deprecation was left as manual work, and neither may answer for the other.
func TestUndeprecatedForwarderStaysASimplicityFinding(t *testing.T) {
	t.Parallel()
	const src = `package lib

// Pow returns base raised to exp.
func Pow(base, exp int) int {
	return base * exp
}

// Power forwards its arguments unchanged.
func Power(base, exp int) int {
	return Pow(base, exp)
}
`
	found := scan(t, "lib/lib.go", src)
	if len(findingsFor(found, policy.RuleDeprecatedNoInline)) != 0 {
		t.Fatalf("a wrapper nobody deprecated was reported as a migration: %+v", found)
	}
	if len(findingsFor(found, policy.RuleForwardingLayer)) != 1 {
		t.Fatalf("forwarding findings = %+v", found)
	}
}
