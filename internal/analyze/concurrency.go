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
	if body == nil || hasBoundingConstruct(loop) || s.hasStaticIterationBound(loop) {
		return
	}
	for _, stmt := range body.List {
		goStmt, ok := stmt.(*ast.GoStmt)
		if !ok {
			continue
		}
		if s.isPoolConsumer(goStmt) {
			continue
		}
		s.add(goStmt.Pos(), policy.RuleGoroutineInLoop,
			"goroutine is spawned once per iteration with no semaphore, group limit, or token channel, so concurrency scales with input size",
			evidence.SeverityError, false)
	}
}

// hasStaticIterationBound reports whether the loop runs a number of times that
// is fixed before it starts.
//
// A fixed-size worker pool is the property this rule defends, and since Go 1.22
// `for range workerCount` is the most direct way the language offers to write
// one. Reading only the body made the rule fire on exactly that shape, so the
// way to silence it was to add a semaphore the code did not need: the rule paid
// for decoration and punished the honest form. A loop whose count is a
// constant, a named constant, or a configuration field is bounded by
// construction, and the bound is visible at the launch site, which is all the
// rule ever asked for.
func (s *scanner) hasStaticIterationBound(loop ast.Node) bool {
	switch l := loop.(type) {
	case *ast.RangeStmt:
		// A range over a container is bounded by its input; only range-over-int
		// carries a count the reader can see. Key and Value are nil in the
		// `for range n` form this recognises.
		return l.Key == nil && l.Value == nil && s.isBoundedCount(l.X)
	case *ast.ForStmt:
		return s.hasStaticCountedBound(l)
	}
	return false
}

// hasStaticCountedBound reads the classic three-clause loop, where both ends
// have to be fixed for the count to be.
//
// Taking either operand of the condition would be enough to accept
// `for i := n; i > 0; i--`, which runs as many times as n says and is exactly
// the unbounded case: the literal is the wrong end of it. So the loop variable
// is identified from the init clause, its starting value has to be fixed, and
// the other operand is the bound.
func (s *scanner) hasStaticCountedBound(loop *ast.ForStmt) bool {
	cond, ok := loop.Cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch cond.Op {
	case token.LSS, token.LEQ, token.GTR, token.GEQ, token.NEQ:
	default:
		return false
	}
	name, start, ok := loopVariable(loop.Init)
	if !ok || !s.isBoundedCount(start) {
		return false
	}
	switch {
	case isIdentNamed(cond.X, name):
		return s.isBoundedCount(cond.Y)
	case isIdentNamed(cond.Y, name):
		return s.isBoundedCount(cond.X)
	}
	return false
}

// loopVariable reads `i := 0` from a loop's init clause.
func loopVariable(init ast.Stmt) (name string, start ast.Expr, ok bool) {
	assign, isAssign := init.(*ast.AssignStmt)
	if !isAssign || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", nil, false
	}
	ident, isIdent := assign.Lhs[0].(*ast.Ident)
	if !isIdent {
		return "", nil, false
	}
	return ident.Name, assign.Rhs[0], true
}

func isIdentNamed(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// isBoundedCount reports whether an expression names a count fixed by the
// program rather than by its input.
//
// A struct or config field selector counts: a pool sized from a validated
// configuration field is the ordinary way a service declares its concurrency,
// and the alternative is to reject the pattern every real worker pool uses. A
// bare variable does not count, because it may hold the length of whatever
// arrived over the network, and that is the case the rule exists for.
func (s *scanner) isBoundedCount(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Kind == token.INT
	case *ast.ParenExpr:
		return s.isBoundedCount(e.X)
	case *ast.BinaryExpr:
		return s.isBoundedCount(e.X) && s.isBoundedCount(e.Y)
	case *ast.Ident:
		return s.decls.isConstant(e.Name)
	case *ast.SelectorExpr:
		// The field's own name is the only evidence available without type
		// information. Ranging over a field this unit declares as a slice, map or
		// channel spawns one goroutine per element of something the caller filled,
		// which is the case the rule exists for; every other field is taken at its
		// word as a configured count.
		return !s.decls.isContainer(e.Sel.Name)
	}
	return false
}

// isPoolConsumer reports whether a spawned body ranges over a channel, which
// makes it a consumer of work that something else bounds. The count of such
// goroutines is a pool size, not a per-item spawn, so the concern this rule
// carries does not apply however the loop above it is written.
//
// The channel has to be recognisable as one: a range over a map or a slice has
// the same shape and carries none of the argument, so a name this unit never
// declares as a channel, or declares as more than one thing, is not accepted.
func (s *scanner) isPoolConsumer(goStmt *ast.GoStmt) bool {
	found := false
	ast.Inspect(goStmt, func(n ast.Node) bool {
		if found {
			return false
		}
		if rng, ok := n.(*ast.RangeStmt); ok && rng.Value == nil {
			if ident, isIdent := rng.X.(*ast.Ident); isIdent && s.decls.isChannel(ident.Name) {
				found = true
			}
		}
		return !found
	})
	return found
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
