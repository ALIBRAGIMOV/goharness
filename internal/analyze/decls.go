package analyze

import (
	"go/ast"
	"go/token"
	"strings"
)

// declIndex resolves a call expression back to a declaration in the same
// package. It exists so that heuristics which need a result type (does this
// call return an error?) can answer "unknown" instead of guessing.
type declIndex struct {
	// funcs holds package-level functions by name.
	funcs map[string]*ast.FuncDecl
	// methods holds methods by name; a name mapping to more than one method is
	// recorded as ambiguous and never resolved.
	methods   map[string]*ast.FuncDecl
	ambiguous map[string]bool
	// imports holds the local name of every imported package in any file of the
	// unit, so a qualified call can be recognised as unresolvable.
	imports map[string]bool
	// constants holds package-level constant names, so a size or bound written
	// as a named constant is recognised as fixed at compile time.
	constants map[string]bool
	// containers holds every name this unit declares anywhere with a slice, map,
	// channel, function or interface type. One such declaration is enough: a name
	// that means a collection somewhere in the package is not read as a count.
	containers map[string]bool
	// channels and nonChannels record where a name was declared with a channel
	// type and where it was declared with anything else, so a name used for both
	// in one package resolves to neither.
	channels    map[string]bool
	nonChannels map[string]bool
}

// isConstant reports whether a name is a package-level constant of this unit.
func (idx declIndex) isConstant(name string) bool {
	return idx.constants[name]
}

// isContainer reports whether this unit declares the name anywhere with a type
// that holds elements rather than a count.
//
// Only a positive answer is meaningful. A named type may well be an integer,
// and a name this unit never declares belongs to another package, so both are
// left to the caller's default rather than guessed at here.
func (idx declIndex) isContainer(name string) bool {
	return idx.containers[name]
}

// isChannel reports whether this unit declares the name as a channel and never
// as anything else.
func (idx declIndex) isChannel(name string) bool {
	return idx.channels[name] && !idx.nonChannels[name]
}

func indexDeclarations(files []*ast.File) declIndex {
	idx := declIndex{
		funcs:       map[string]*ast.FuncDecl{},
		methods:     map[string]*ast.FuncDecl{},
		ambiguous:   map[string]bool{},
		imports:     map[string]bool{},
		constants:   map[string]bool{},
		containers:  map[string]bool{},
		channels:    map[string]bool{},
		nonChannels: map[string]bool{},
	}
	for _, file := range files {
		idx.indexDeclaredTypes(file)
		for _, spec := range file.Imports {
			idx.imports[importLocalName(spec)] = true
		}
		for _, decl := range file.Decls {
			if gen, isGen := decl.(*ast.GenDecl); isGen {
				idx.indexConstants(gen)
				continue
			}
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			if fn.Recv == nil {
				if _, exists := idx.funcs[fn.Name.Name]; exists {
					idx.ambiguous[fn.Name.Name] = true
				}
				idx.funcs[fn.Name.Name] = fn
				continue
			}
			if _, exists := idx.methods[fn.Name.Name]; exists {
				idx.ambiguous[fn.Name.Name] = true
			}
			idx.methods[fn.Name.Name] = fn
		}
	}
	return idx
}

// indexDeclaredTypes records the shape of every name the file declares with an
// explicit type: struct fields, parameters, results and typed variables alike.
// A heuristic that has to tell a worker count from a work queue needs this much
// and no more, so a name whose type is a named or imported one is recorded
// nowhere and stays unknown.
func (idx declIndex) indexDeclaredTypes(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.Field:
			for _, name := range decl.Names {
				idx.recordType(name.Name, decl.Type)
			}
		case *ast.ValueSpec:
			if decl.Type == nil {
				return true
			}
			for _, name := range decl.Names {
				idx.recordType(name.Name, decl.Type)
			}
		}
		return true
	})
}

func (idx declIndex) recordType(name string, typ ast.Expr) {
	switch t := typ.(type) {
	case *ast.ChanType:
		idx.channels[name] = true
		idx.containers[name] = true
	case *ast.ArrayType:
		// An array has a fixed length and is a legitimate bound; a slice, which is
		// the same node with no length, is exactly the input-sized thing the
		// bounded-spawn rule exists to catch.
		idx.nonChannels[name] = true
		if t.Len == nil {
			idx.containers[name] = true
		}
	case *ast.MapType, *ast.FuncType, *ast.InterfaceType:
		idx.nonChannels[name] = true
		idx.containers[name] = true
	default:
		idx.nonChannels[name] = true
	}
}

func (idx declIndex) indexConstants(decl *ast.GenDecl) {
	if decl.Tok != token.CONST {
		return
	}
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range value.Names {
			idx.constants[name.Name] = true
		}
	}
}

func importLocalName(spec *ast.ImportSpec) string {
	if spec.Name != nil {
		return spec.Name.Name
	}
	path := strings.Trim(spec.Path.Value, `"`)
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// resultTypes returns the flattened result type expressions of the function a
// call targets, and whether the target could be resolved at all. Anything
// reached through an imported package, an ambiguous method name, or a value of
// unknown type resolves to false: the caller must then stay silent rather than
// guess.
func (idx declIndex) resultTypes(call *ast.CallExpr) ([]ast.Expr, bool) {
	fn, ok := idx.resolve(call.Fun)
	if !ok {
		return nil, false
	}
	if fn.Type == nil || fn.Type.Results == nil {
		return nil, true
	}
	var out []ast.Expr
	for _, field := range fn.Type.Results.List {
		count := max(len(field.Names), 1)
		for range count {
			out = append(out, field.Type)
		}
	}
	return out, true
}

func (idx declIndex) resolve(fun ast.Expr) (*ast.FuncDecl, bool) {
	switch target := fun.(type) {
	case *ast.Ident:
		if idx.ambiguous[target.Name] {
			return nil, false
		}
		fn, ok := idx.funcs[target.Name]
		return fn, ok
	case *ast.SelectorExpr:
		if pkg, isIdent := target.X.(*ast.Ident); isIdent && idx.imports[pkg.Name] {
			return nil, false
		}
		if idx.ambiguous[target.Sel.Name] {
			return nil, false
		}
		fn, ok := idx.methods[target.Sel.Name]
		return fn, ok
	default:
		return nil, false
	}
}

// isErrorType reports whether a type expression is the predeclared error
// interface. Only the unqualified spelling counts; a named alias cannot be
// resolved without type information.
func isErrorType(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "error"
}
