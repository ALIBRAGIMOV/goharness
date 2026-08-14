package analyze

import (
	"go/ast"
	"slices"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// scanNetwork reports calls that cross the network without a deadline, without
// the caller's cancellation, or without a retry bound.
func (s *scanner) scanNetwork() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			s.checkClientTimeout(node)
		case *ast.CallExpr:
			s.checkRequestContext(node)
		case *ast.ForStmt:
			s.checkRetryBound(node)
		}
		return true
	})
}

func (s *scanner) checkClientTimeout(lit *ast.CompositeLit) {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Client" {
		return
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return
	}
	for _, elt := range lit.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			continue
		}
		if key, isIdent := kv.Key.(*ast.Ident); isIdent && key.Name == "Timeout" {
			return
		}
	}
	s.add(lit.Pos(), policy.RuleClientTimeout,
		"http.Client is constructed without a Timeout, so a single unresponsive peer holds the caller indefinitely",
		evidence.SeverityError, false)
}

// contextlessHTTPCalls are the net/http entry points with no context parameter.
func contextlessHTTPCalls() []string {
	return []string{"NewRequest", "Get", "Post", "PostForm", "Head"}
}

func (s *scanner) checkRequestContext(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !slices.Contains(contextlessHTTPCalls(), sel.Sel.Name) {
		return
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return
	}
	s.add(call.Pos(), policy.RuleRequestContext,
		"http."+sel.Sel.Name+" cannot carry a context, so the caller's deadline and cancellation never reach the transport",
		evidence.SeverityError, false)
}

// checkRetryBound reports a condition-free loop that sleeps and calls out: the
// classic unbounded retry. A loop with a condition or a range already has a
// bound, so only the bare form is reported, and only as advisory because the
// bound may live in a helper the scanner cannot see.
func (s *scanner) checkRetryBound(loop *ast.ForStmt) {
	if loop.Cond != nil || loop.Init != nil {
		return
	}
	sleeps, calls := false, false
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isQualifiedCall(call, "time", "Sleep") {
			sleeps = true
			return true
		}
		if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel {
			switch sel.Sel.Name {
			case "Do", "Get", "Post", "Dial", "DialContext", "Send", "Invoke":
				calls = true
			}
		}
		return true
	})
	if !sleeps || !calls {
		return
	}
	s.add(loop.Pos(), policy.RuleUnboundedRetry,
		"retry loop has no attempt counter or deadline, so a peer outage becomes an indefinite hold",
		evidence.SeverityWarning, true)
}
