package policy

import "strings"

// Remedy classes for unchecked-error findings. One rule, four entirely
// different products: a discarded write to a domain store and a discarded
// fmt.Fprintln to stderr are the same linter finding and not remotely the same
// defect, and an operator handed 461 undifferentiated rows has to rebuild this
// grouping by hand before any of it can be triaged.
const (
	RemedyResourceClose = "resource-close"
	RemedyCleanup       = "cleanup"
	RemedyEncode        = "encode"
	RemedyDiagnostic    = "diagnostic"
	RemedyDomainWrite   = "domain-write"
)

// ErrcheckRemedy classifies one unchecked-error finding by the callee its
// message names, and gives the consequence class that follows from it.
//
// The default is deliberately the frightening one. A call this function does not
// recognise is presumed to be a domain write whose failure now goes unreported,
// because that is the case where being wrong is expensive: mistaking a lost
// domain write for a close is how a data-loss defect gets triaged as idiom, and
// mistaking a close for a domain write costs a reader one glance.
//
// The callee is read from the message rather than from the AST because the
// linter already resolved it. Rebuilding that with a second type-check would add
// a whole analysis pass to learn something the text in hand already says.
func ErrcheckRemedy(message string) (remedyClass string, consequence Consequence) {
	callee, qualifier := calleeOf(message)
	switch {
	case callee == "":
		return RemedyDomainWrite, ConsequenceSilentLoss
	case strings.HasSuffix(callee, "Close"):
		return RemedyResourceClose, ConsequenceStructural
	case callee == "Rollback" || callee == "Remove" || callee == "RemoveAll":
		return RemedyCleanup, ConsequenceStructural
	case callee == "Marshal" || callee == "MarshalIndent" || callee == "Encode":
		return RemedyEncode, ConsequenceHygiene
	case isPrintCall(callee, qualifier):
		return RemedyDiagnostic, ConsequenceHygiene
	default:
		return RemedyDomainWrite, ConsequenceSilentLoss
	}
}

// isPrintCall recognises the formatted-output family. A bare Write counts only
// when it is aimed at a standard stream: everything else that spells Write is a
// write to a file, a connection, or a store, and losing the error on one of
// those is the defect this classification exists to keep visible.
func isPrintCall(callee, qualifier string) bool {
	switch callee {
	case "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln":
		return true
	case "Write", "WriteString":
		return strings.Contains(qualifier, "Stdout") || strings.Contains(qualifier, "Stderr")
	default:
		return false
	}
}

// calleeOf pulls the called function out of an errcheck message, which names it
// between backticks: "Error return value of `x.Close` is not checked". The
// qualifier is everything before the final dot, which is what says whether a
// Write went to a standard stream.
func calleeOf(message string) (callee, qualifier string) {
	_, rest, found := strings.Cut(message, "`")
	if !found {
		return "", ""
	}
	name, _, found := strings.Cut(rest, "`")
	if !found {
		return "", ""
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), "()")
	if pkg, symbol, ok := strings.CutLast(name, "."); ok {
		return symbol, pkg
	}
	return name, ""
}
