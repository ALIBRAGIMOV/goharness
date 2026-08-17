package analyze

import (
	"go/ast"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// The scanners here look for structure a change added without needing it. They
// are the two shapes that show up over and over in generated code: a function
// that exists only to call another one, and an interface written for a single
// implementation. Both are advisory. Either can be the right call in code a
// scanner cannot see the reason for, so they are put in front of a reviewer
// rather than used to reject a change.

// scanForwarding reports a function whose whole body hands its arguments to
// another function unchanged. The layer adds a name and nothing else, and every
// caller now reads two functions to learn what one does.
func (s *scanner) scanForwarding() {
	for _, decl := range s.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || len(fn.Body.List) != 1 || fn.Type.Results == nil {
			continue
		}
		call, ok := soleReturnedCall(fn.Body.List[0])
		if !ok || !argumentsMatchParameters(fn.Type.Params, call.Args) || deprecated(fn.Doc) {
			continue
		}
		s.add(fn.Pos(), policy.RuleForwardingLayer,
			"func "+fn.Name.Name+" passes its arguments straight to "+calleeName(call)+" and adds nothing",
			evidence.SeverityWarning, true)
	}
}

// soleReturnedCall matches a body that is exactly `return f(...)`.
//
// A conversion parses as a call too, so `return string(b)` and `return
// append(dst, src)` reach here looking exactly like a forwarding layer. They are
// not one: there is no other function to read, and no layer to remove.
func soleReturnedCall(stmt ast.Stmt) (*ast.CallExpr, bool) {
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil, false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	return namedFunctionCall(call)
}

// namedFunctionCall keeps calls to functions someone wrote and rejects the call
// expressions that are really conversions or builtins.
func namedFunctionCall(call *ast.CallExpr) (*ast.CallExpr, bool) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return call, !predeclared(fun.Name)
	case *ast.SelectorExpr:
		return call, true
	default:
		return nil, false
	}
}

// predeclared reports the universe-scope identifiers that turn a call
// expression into a conversion or a builtin rather than a call to a function
// someone wrote.
func predeclared(name string) bool {
	return slices.Contains(predeclaredIdentifiers(), name)
}

func predeclaredIdentifiers() []string {
	return []string{
		"append", "cap", "clear", "complex", "copy", "imag", "len", "make",
		"max", "min", "new", "real",
		"any", "bool", "byte", "complex64", "complex128", "error", "float32",
		"float64", "int", "int8", "int16", "int32", "int64", "rune", "string",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
	}
}

// deprecated reports the convention that says a shim exists on purpose: a
// function kept only to forward to its replacement is doing its job.
func deprecated(doc *ast.CommentGroup) bool {
	if doc == nil {
		return false
	}
	for _, line := range doc.List {
		if strings.Contains(line.Text, "Deprecated:") {
			return true
		}
	}
	return false
}

// argumentsMatchParameters reports whether the call passes exactly the
// enclosing function's parameters, in order and unaltered. A conversion, a
// reordering, or an extra argument all mean the wrapper is doing something.
func argumentsMatchParameters(params *ast.FieldList, args []ast.Expr) bool {
	var names []string
	if params != nil {
		for _, field := range params.List {
			for _, name := range field.Names {
				names = append(names, name.Name)
			}
		}
	}
	if len(names) == 0 || len(names) != len(args) {
		return false
	}
	for i, arg := range args {
		ident, ok := arg.(*ast.Ident)
		if !ok || ident.Name != names[i] {
			return false
		}
	}
	return true
}

func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	default:
		return "another function"
	}
}

// soleImplementationFindings reports unexported interfaces that exactly one
// type in their own package satisfies.
//
// An interface with one implementation and no second caller to serve is a
// description of a type that already exists. Exported interfaces are left
// alone: those are a package's contract with the outside, and a test seam is a
// legitimate reason for one. The comparison is by method name, which is what
// keeps this cheap enough to run without type information, and the finding is
// advisory because a scanner cannot see an author's plans.
func soleImplementationFindings(u *unit) []Finding {
	methodsByType := u.methodNamesByReceiver()
	var out []Finding
	for i, file := range u.files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				name, methods, ok := unexportedInterface(spec)
				if !ok {
					continue
				}
				if implementers(methodsByType, methods) != 1 {
					continue
				}
				out = append(out, Finding{
					RuleID:   policy.RuleSoleImplementation,
					File:     u.relPaths[i],
					Line:     u.fset.Position(spec.Pos()).Line,
					Message:  "interface " + name + " describes exactly one type in this package",
					Severity: evidence.SeverityWarning,
					Advisory: true,
				})
			}
		}
	}
	return out
}

// unexportedInterface matches an unexported interface type with at least one
// method, which is the only shape this rule speaks about.
func unexportedInterface(spec ast.Spec) (name string, methods []string, ok bool) {
	typeSpec, isType := spec.(*ast.TypeSpec)
	if !isType || typeSpec.Name.IsExported() {
		return "", nil, false
	}
	iface, isInterface := typeSpec.Type.(*ast.InterfaceType)
	if !isInterface || iface.Methods == nil {
		return "", nil, false
	}
	for _, field := range iface.Methods.List {
		if _, isFunc := field.Type.(*ast.FuncType); !isFunc || len(field.Names) != 1 {
			// An embedded interface or a type constraint puts the method set
			// somewhere this scan cannot follow, so the type is left alone.
			return "", nil, false
		}
		methods = append(methods, field.Names[0].Name)
	}
	if len(methods) == 0 {
		return "", nil, false
	}
	return typeSpec.Name.Name, methods, true
}

// methodNamesByReceiver indexes every method declared in the package by the
// type it hangs off, with pointer and value receivers folded together.
func (u *unit) methodNamesByReceiver() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, file := range u.files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			receiver := receiverTypeName(fn.Recv.List[0].Type)
			if receiver == "" {
				continue
			}
			if out[receiver] == nil {
				out[receiver] = map[string]bool{}
			}
			out[receiver][fn.Name.Name] = true
		}
	}
	return out
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	default:
		return ""
	}
}

func implementers(methodsByType map[string]map[string]bool, required []string) int {
	count := 0
	for _, have := range methodsByType {
		satisfied := true
		for _, method := range required {
			if !have[method] {
				satisfied = false
				break
			}
		}
		if satisfied {
			count++
		}
	}
	return count
}
