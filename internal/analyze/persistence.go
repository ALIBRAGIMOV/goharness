package analyze

import (
	"go/ast"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// scanPersistence reports transactions that are opened but never resolved.
//
// The check is per function: a Begin whose function body contains no Commit and
// no Rollback leaves the transaction open on every path. Handing the
// transaction to another function counts as resolution, because the scanner
// cannot follow it and must not guess.
func (s *scanner) scanPersistence() {
	for _, decl := range s.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		begins := transactionBegins(fn.Body)
		if len(begins) == 0 || resolvesTransaction(fn.Body) {
			continue
		}
		for _, begin := range begins {
			s.add(begin.Pos(), policy.RuleTxNotResolved,
				"transaction is opened here but the function neither commits nor rolls it back, so it holds locks until the server times it out",
				evidence.SeverityError, false)
		}
	}
}

func transactionBegins(body *ast.BlockStmt) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		if sel.Sel.Name == "Begin" || sel.Sel.Name == "BeginTx" {
			out = append(out, call)
		}
		return true
	})
	return out
}

func resolvesTransaction(body *ast.BlockStmt) bool {
	resolved := false
	ast.Inspect(body, func(n ast.Node) bool {
		if resolved {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Commit", "Rollback":
			resolved = true
		}
		return !resolved
	})
	if resolved {
		return true
	}
	return passesTransactionOn(body)
}

// passesTransactionOn reports whether the transaction value is handed to
// another function, which owns resolution from that point on.
func passesTransactionOn(body *ast.BlockStmt) bool {
	names := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || (sel.Sel.Name != "Begin" && sel.Sel.Name != "BeginTx") {
			return true
		}
		if ident, isIdent := assign.Lhs[0].(*ast.Ident); isIdent {
			names[ident.Name] = true
		}
		return true
	})
	if len(names) == 0 {
		return false
	}

	passed := false
	ast.Inspect(body, func(n ast.Node) bool {
		if passed {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if ident, isIdent := arg.(*ast.Ident); isIdent && names[ident.Name] {
				passed = true
				return false
			}
		}
		return true
	})
	return passed
}
