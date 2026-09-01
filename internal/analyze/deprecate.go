package analyze

import (
	"go/ast"
	"go/token"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// fixInlineDirective is what turns a deprecation into a migration every caller
// can perform with one command.
const fixInlineDirective = "//go:fix inline"

// scanDeprecations reports a deprecated declaration whose replacement the
// toolchain could substitute at every call site, but which carries no
// //go:fix inline directive.
//
// The notice tells a reader to stop using the symbol; the directive tells
// `go fix` to do it for them. Without it the shim outlives the release it was
// written for, because migrating stays manual work nobody schedules.
//
// Both ends have to be exported. An unexported declaration has no caller its
// author does not control, and an unexported body would offer callers outside
// the package a replacement they cannot name: the corpus found exactly that
// shape, a deprecated function whose one call reached an unexported
// constructor. Advisory because a scanner cannot see whether the author means
// the substitution to be automatic.
func (s *scanner) scanDeprecations() {
	for _, decl := range s.file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			s.reportDeprecatedFunc(d)
		case *ast.GenDecl:
			s.reportDeprecatedConst(d)
		}
	}
}

func (s *scanner) reportDeprecatedFunc(fn *ast.FuncDecl) {
	if fn.Body == nil || len(fn.Body.List) != 1 || !migratable(fn.Doc) || !ast.IsExported(fn.Name.Name) {
		return
	}
	call, ok := soleCall(fn.Body.List[0])
	if !ok || !exportedCallee(call) {
		return
	}
	s.add(fn.Pos(), policy.RuleDeprecatedNoInline,
		"deprecated func "+fn.Name.Name+" forwards to "+calleeName(call)+
			" but carries no "+fixInlineDirective+" directive, so every caller migrates by hand",
		evidence.SeverityWarning, true)
}

func (s *scanner) reportDeprecatedConst(decl *ast.GenDecl) {
	if decl.Tok != token.CONST {
		return
	}
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
			continue
		}
		doc := value.Doc
		if doc == nil && len(decl.Specs) == 1 {
			doc = decl.Doc
		}
		if !migratable(doc) || !ast.IsExported(value.Names[0].Name) || !inlinableValue(value.Values[0]) {
			continue
		}
		s.add(value.Pos(), policy.RuleDeprecatedNoInline,
			"deprecated const "+value.Names[0].Name+" carries no "+fixInlineDirective+
				" directive, so every caller migrates by hand",
			evidence.SeverityWarning, true)
	}
}

// migratable reports a deprecation notice that does not already carry the
// directive.
func migratable(doc *ast.CommentGroup) bool {
	return deprecated(doc) && !hasFixInline(doc)
}

// hasFixInline reads the directive the way the go command does: through
// ast.ParseDirective, so spacing and a trailing comment do not hide it and a
// line that merely mentions the words is not mistaken for it.
func hasFixInline(doc *ast.CommentGroup) bool {
	if doc == nil {
		return false
	}
	for _, line := range doc.List {
		directive, ok := ast.ParseDirective(line.Slash, line.Text)
		if !ok || directive.Tool != "go" || directive.Name != "fix" {
			continue
		}
		args, err := directive.ParseArgs()
		if err == nil && len(args) > 0 && args[0].Arg == "inline" {
			return true
		}
	}
	return false
}

// soleCall matches a body that is exactly one call, whether its result is
// returned or discarded. Both shapes inline cleanly; anything longer is a shim
// with logic in it, and moving that into every caller is not a mechanical edit.
func soleCall(stmt ast.Stmt) (*ast.CallExpr, bool) {
	switch node := stmt.(type) {
	case *ast.ReturnStmt:
		return soleReturnedCall(node)
	case *ast.ExprStmt:
		call, ok := node.X.(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		return namedFunctionCall(call)
	default:
		return nil, false
	}
}

// exportedCallee reports a call whose target a caller in another package could
// write itself, which is the precondition for inlining to help one.
func exportedCallee(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return ast.IsExported(fun.Name)
	case *ast.SelectorExpr:
		return ast.IsExported(fun.Sel.Name)
	default:
		return false
	}
}

// inlinableValue reports the constant expressions worth substituting: a
// literal, or a constant a caller elsewhere can name.
func inlinableValue(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return ast.IsExported(value.Name)
	case *ast.SelectorExpr:
		return ast.IsExported(value.Sel.Name)
	default:
		return false
	}
}
