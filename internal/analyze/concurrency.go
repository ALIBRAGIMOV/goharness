package analyze

import (
	"go/ast"
	"go/token"
	"slices"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// scanConcurrency reports goroutines whose termination is not discoverable at
// the launch site.
//
// The rule only fires when the enclosing function already holds a
// context.Context and the launched work ignores it along with every other stop
// signal. That combination is unambiguous: the means to stop the goroutine was
// in scope and was not used. Where no context is available the situation is
// genuinely ambiguous, and an ambiguous required finding is worse than none.
func (s *scanner) scanConcurrency() {
	for _, decl := range s.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !hasContextParam(fn.Type) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			goStmt, isGo := n.(*ast.GoStmt)
			if !isGo {
				return true
			}
			if hasLifecycleSignal(goStmt) {
				return true
			}
			s.add(goStmt.Pos(), policy.RuleGoroutineLifetime,
				"goroutine ignores the context its caller holds and shows no other stop signal, so nothing can end or await it",
				evidence.SeverityError, false)
			return true
		})
	}
}

func hasContextParam(sig *ast.FuncType) bool {
	if sig == nil || sig.Params == nil {
		return false
	}
	return slices.ContainsFunc(sig.Params.List, func(field *ast.Field) bool {
		return isContextType(field.Type)
	})
}

func isContextType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Context" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "context"
}

// lifecycleNames are the identifiers and method names that make a goroutine's
// end visible: a context, a done channel, a wait group, or a group runner.
func lifecycleNames() []string {
	return []string{
		"ctx", "cancel", "done", "quit", "stop", "shutdown",
		"wg", "waitGroup", "group", "eg", "sem", "ticker", "timer",
	}
}

func lifecycleMethods() []string {
	return []string{"Done", "Wait", "Err", "Stop", "Close", "Release", "Acquire"}
}

func hasLifecycleSignal(goStmt *ast.GoStmt) bool {
	found := false
	ast.Inspect(goStmt, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.Ident:
			if slices.Contains(lifecycleNames(), node.Name) {
				found = true
			}
		case *ast.SelectorExpr:
			if slices.Contains(lifecycleMethods(), node.Sel.Name) {
				found = true
			}
		case *ast.SelectStmt:
			found = true
		case *ast.UnaryExpr:
			if node.Op == token.ARROW {
				found = true
			}
		}
		return !found
	})
	return found
}

// scanBoundedResources reports constructs whose resource use scales with input
// rather than with a declared bound.
func (s *scanner) scanBoundedResources() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		body, ok := loopBody(n)
		if !ok {
			return true
		}
		s.checkLoopSpawns(n, body)
		s.checkLoopTimers(body)
		return true
	})
	s.checkVariableChannelBuffers()
}

func loopBody(n ast.Node) (*ast.BlockStmt, bool) {
	switch loop := n.(type) {
	case *ast.ForStmt:
		return loop.Body, true
	case *ast.RangeStmt:
		return loop.Body, true
	}
	return nil, false
}

func (s *scanner) checkLoopSpawns(loop ast.Node, body *ast.BlockStmt) {
	if body == nil || hasBoundingConstruct(loop) {
		return
	}
	for _, stmt := range body.List {
		goStmt, ok := stmt.(*ast.GoStmt)
		if !ok {
			continue
		}
		s.add(goStmt.Pos(), policy.RuleGoroutineInLoop,
			"goroutine is spawned once per iteration with no semaphore, group limit, or token channel, so concurrency scales with input size",
			evidence.SeverityError, false)
	}
}

// hasBoundingConstruct reports whether the loop carries a visible concurrency
// bound: a semaphore acquisition, an explicit group limit, or a token channel
// send that blocks when full.
func hasBoundingConstruct(loop ast.Node) bool {
	found := false
	ast.Inspect(loop, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.SendStmt:
			found = true
		case *ast.SelectorExpr:
			switch node.Sel.Name {
			case "Acquire", "SetLimit", "TryAcquire":
				found = true
			}
		}
		return !found
	})
	return found
}

func (s *scanner) checkLoopTimers(body *ast.BlockStmt) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isQualifiedCall(call, "time", "After") {
			return true
		}
		s.add(call.Pos(), policy.RuleTimerInLoop,
			"time.After allocates a timer that survives until it fires, so calling it in a loop accumulates timers",
			evidence.SeverityError, false)
		return true
	})
}

func (s *scanner) checkVariableChannelBuffers() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		builtin, isIdent := call.Fun.(*ast.Ident)
		if !isIdent || builtin.Name != "make" {
			return true
		}
		if _, isChan := call.Args[0].(*ast.ChanType); !isChan {
			return true
		}
		if s.isStaticSize(call.Args[1]) {
			return true
		}
		s.add(call.Pos(), policy.RuleVariableChanBuf,
			"channel buffer is sized from a variable, so queued memory grows with input unless a bound applies elsewhere",
			evidence.SeverityWarning, true)
		return true
	})
}

// isStaticSize reports whether a buffer size is fixed at compile time. A
// literal is; so is an identifier that resolves to a constant declared in this
// package. Anything else may come from input and is reported.
func (s *scanner) isStaticSize(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.BinaryExpr:
		return s.isStaticSize(e.X) && s.isStaticSize(e.Y)
	case *ast.ParenExpr:
		return s.isStaticSize(e.X)
	case *ast.Ident:
		return s.decls.isConstant(e.Name)
	}
	return false
}

func isQualifiedCall(call *ast.CallExpr, pkg, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == pkg
}
