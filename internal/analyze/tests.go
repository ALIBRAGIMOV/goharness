package analyze

import (
	"go/ast"
	"go/printer"
	"go/token"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

func (s *scanner) scanTests() {
	for _, decl := range s.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isTestFunc(fn) {
			continue
		}
		s.checkTestFunc(fn)
	}
}

func isTestFunc(fn *ast.FuncDecl) bool {
	// TestMain is the package harness, not a test: it observes nothing itself.
	if fn.Recv != nil || fn.Name.Name == "TestMain" || !strings.HasPrefix(fn.Name.Name, "Test") {
		return false
	}
	if fn.Name.Name != "Test" && !isUpperOrUnderscore(rune(fn.Name.Name[len("Test")])) {
		return false
	}
	return len(fn.Type.Params.List) == 1
}

func isUpperOrUnderscore(r rune) bool {
	return r == '_' || (r >= 'A' && r <= 'Z')
}

func (s *scanner) checkTestFunc(fn *ast.FuncDecl) {
	if len(fn.Body.List) == 0 {
		s.add(fn.Pos(), policy.RuleTestEmpty,
			"test "+fn.Name.Name+" has an empty body and proves nothing",
			evidence.SeverityError, false)
		return
	}
	if pos, ok := unconditionalSkip(fn.Body.List[0]); ok {
		s.add(pos, policy.RuleTestSkipped,
			"test "+fn.Name.Name+" skips unconditionally, so its subject is never exercised",
			evidence.SeverityError, false)
	}
	if !s.observesAnything(fn.Body) {
		s.add(fn.Pos(), policy.RuleTestNoAssertion,
			"test "+fn.Name.Name+" contains no assertion, error check, state observation, or panic expectation",
			evidence.SeverityError, false)
	}
	s.checkTautologies(fn)
	s.checkIgnoredErrors(fn)
}

func unconditionalSkip(stmt ast.Stmt) (token.Pos, bool) {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return token.NoPos, false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return token.NoPos, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return token.NoPos, false
	}
	switch sel.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
		return call.Pos(), true
	}
	return token.NoPos, false
}

// observesAnything reports whether the test can fail for a reason other than a
// panic in the code under test: a testing failure call, a testify assertion, a
// comparison in a conditional, or an explicit recover.
func (s *scanner) observesAnything(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			if isFailureCall(node) || isTestifyCall(node) || isRecoverCall(node) {
				found = true
			}
		case *ast.IfStmt:
			if containsComparison(node.Cond) {
				found = true
			}
		case *ast.SwitchStmt:
			if node.Tag != nil || hasComparisonCase(node) {
				found = true
			}
		}
		return !found
	})
	return found
}

func isFailureCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Error", "Errorf", "Fatal", "Fatalf", "Fail", "FailNow":
		return true
	}
	return false
}

func isTestifyCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name {
	case "assert", "require":
		return true
	}
	return false
}

func isRecoverCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "recover"
}

func containsComparison(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		switch bin.Op {
		case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
			found = true
			return false
		}
		return true
	})
	return found
}

func hasComparisonCase(sw *ast.SwitchStmt) bool {
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if slices.ContainsFunc(clause.List, containsComparison) {
			return true
		}
	}
	return false
}

func (s *scanner) checkTautologies(fn *ast.FuncDecl) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op != token.EQL && node.Op != token.NEQ {
				return true
			}
			if isConstantExpr(node.X) && s.render(node.X) == s.render(node.Y) {
				s.add(node.Pos(), policy.RuleTestTautology,
					"comparison of two identical constant expressions can never fail",
					evidence.SeverityError, false)
			}
		case *ast.CallExpr:
			if !isTestifyCall(node) || len(node.Args) < 3 {
				return true
			}
			if isConstantExpr(node.Args[1]) && s.render(node.Args[1]) == s.render(node.Args[2]) {
				s.add(node.Pos(), policy.RuleTestTautology,
					"assertion compares two identical constant expressions and can never fail",
					evidence.SeverityError, false)
			}
		}
		return true
	})
}

func isConstantExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.UnaryExpr:
		return isConstantExpr(e.X)
	case *ast.BinaryExpr:
		return isConstantExpr(e.X) && isConstantExpr(e.Y)
	case *ast.ParenExpr:
		return isConstantExpr(e.X)
	case *ast.Ident:
		return e.Name == "true" || e.Name == "false" || e.Name == "nil"
	}
	return false
}

func (s *scanner) render(expr ast.Expr) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, s.fset, expr); err != nil {
		return ""
	}
	return sb.String()
}

// checkIgnoredErrors flags a blank identifier in the final assignment position
// only when the discarded result is provably the error interface. Where the
// callee cannot be resolved against this package's declarations the type is
// unknown, and an unknown type is never reported: a scanner that invents
// findings about its own subject is worse than one that stays quiet.
func (s *scanner) checkIgnoredErrors(fn *ast.FuncDecl) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}
		last, isIdent := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
		if !isIdent || last.Name != "_" {
			return true
		}
		results, resolved := s.decls.resultTypes(call)
		if !resolved || len(results) != len(assign.Lhs) {
			return true
		}
		if !isErrorType(results[len(results)-1]) {
			return true
		}
		s.add(assign.Pos(), policy.RuleTestIgnoredError,
			"error result is discarded into the blank identifier; a setup failure would go unnoticed",
			evidence.SeverityWarning, true)
		return true
	})
}
