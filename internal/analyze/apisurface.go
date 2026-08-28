package analyze

import (
	"context"
	"fmt"
	"go/types"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// Exported is one exported symbol: its rendered type, and where it is declared.
//
// The position is what makes a removal addressable. A row that names only the
// import path cannot be opened, cannot be reached by a scoped exception, and
// cannot be placed against the diff, which is how ten deliberate API removals
// arrived in a report with nowhere to click.
type Exported struct {
	Type string
	File string
	Line int
}

// ExportSurface maps every exported symbol of the given packages to its
// rendered type and declaration site. Type information is loaded only for the
// packages whose API actually changed, so the cost stays proportional to the
// diff rather than to the module.
func ExportSurface(ctx context.Context, root string, patterns []string) (map[string]Exported, error) {
	if len(patterns) == 0 {
		return map[string]Exported{}, nil
	}
	cfg := &packages.Config{
		Context: ctx,
		Dir:     root,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax,
		// The loader shells out to the go command, so it needs the same sanitised
		// environment as every other subprocess. Inheriting the caller's would let
		// GOFLAGS add a build tag and change which declarations this surface
		// contains, and GOTOOLCHAIN send verification off to download a release.
		Env: tool.VerificationEnv(nil),
	}
	loaded, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages for export-surface comparison: %w", err)
	}
	surface := map[string]Exported{}
	for _, pkg := range loaded {
		if pkg.Types == nil || pkg.Types.Scope() == nil {
			continue
		}
		collectExports(root, pkg, surface)
	}
	return surface, nil
}

// declaredAt renders a symbol's position relative to the tree it was loaded
// from. A position the loader did not record, and one outside the tree, both
// yield no location rather than a path a reader cannot use.
func declaredAt(root string, pkg *packages.Package, obj types.Object) (file string, line int) {
	if !obj.Pos().IsValid() || pkg.Fset == nil {
		return "", 0
	}
	pos := pkg.Fset.Position(obj.Pos())
	rel, err := filepath.Rel(root, pos.Filename)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", 0
	}
	return filepath.ToSlash(rel), pos.Line
}

func collectExports(root string, pkg *packages.Package, surface map[string]Exported) {
	scope := pkg.Types.Scope()
	qualifier := func(other *types.Package) string {
		if other == pkg.Types {
			return ""
		}
		return other.Path()
	}
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		file, line := declaredAt(root, pkg, obj)
		surface[pkg.PkgPath+"."+name] = Exported{
			Type: types.TypeString(obj.Type(), qualifier), File: file, Line: line,
		}
		if named, ok := obj.Type().(*types.Named); ok {
			collectMethods(root, pkg, name, named, qualifier, surface)
		}
	}
}

func collectMethods(
	root string, pkg *packages.Package, typeName string,
	named *types.Named, qualifier types.Qualifier, surface map[string]Exported,
) {
	for method := range named.Methods() {
		if !method.Exported() {
			continue
		}
		file, line := declaredAt(root, pkg, method)
		surface[pkg.PkgPath+"."+typeName+"."+method.Name()] = Exported{
			Type: types.TypeString(method.Type(), qualifier), File: file, Line: line,
		}
	}
}

// APIBreakFindings reports exported symbols the change removed or re-signed.
// Additions are compatible and are not reported.
//
// A removal is located where the symbol used to be declared, which is a position
// in the base tree; a re-signature is located where it is declared now. Both are
// real files a reader can open, and both let the row be placed against the diff
// like every other one. The identity is the symbol rather than the location, so
// a declaration that merely moves keeps the finding it had.
func APIBreakFindings(base, head map[string]Exported) []Finding {
	var out []Finding
	for _, key := range slices.Sorted(maps.Keys(base)) {
		headSymbol, present := head[key]
		baseSymbol := base[key]
		pkgPath, symbol := splitSymbol(key)
		switch {
		case !present:
			out = append(out, Finding{
				RuleID: policy.RuleAPIBreak,
				File:   baseSymbol.File, Line: baseSymbol.Line,
				Identity: policy.RuleAPIBreak + " removed " + key,
				Message: "exported symbol " + symbol + " was removed from " + pkgPath +
					"; keeping it as a shim marked " + fixInlineDirective +
					" would let every caller migrate with go fix instead of by hand",
				Severity: evidence.SeverityError,
			})
		case headSymbol.Type != baseSymbol.Type:
			out = append(out, Finding{
				RuleID: policy.RuleAPIBreak,
				File:   headSymbol.File, Line: headSymbol.Line,
				Identity: policy.RuleAPIBreak + " resigned " + key,
				Message: "exported symbol " + symbol + " in " + pkgPath +
					" changed type from " + baseSymbol.Type + " to " + headSymbol.Type,
				Severity: evidence.SeverityError,
			})
		}
	}
	sortFindings(out)
	return out
}

func splitSymbol(key string) (pkgPath, symbol string) {
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return "", key
	}
	prefix, name := key[:i], key[i+1:]
	// A method key is pkg.Type.Method; fold the type back into the symbol.
	if j := strings.LastIndex(prefix, "."); j >= 0 && len(prefix) > j+1 && isUpper(prefix[j+1]) {
		return prefix[:j], prefix[j+1:] + "." + name
	}
	return prefix, name
}

func isUpper(b byte) bool {
	return b >= 'A' && b <= 'Z'
}
