package analyze

import (
	"context"
	"fmt"
	"go/types"
	"maps"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// ExportSurface maps every exported symbol of the given packages to its
// rendered type. Type information is loaded only for the packages whose API
// actually changed, so the cost stays proportional to the diff rather than to
// the module.
func ExportSurface(ctx context.Context, root string, patterns []string) (map[string]string, error) {
	if len(patterns) == 0 {
		return map[string]string{}, nil
	}
	cfg := &packages.Config{
		Context: ctx,
		Dir:     root,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax,
	}
	loaded, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages for export-surface comparison: %w", err)
	}
	surface := map[string]string{}
	for _, pkg := range loaded {
		if pkg.Types == nil || pkg.Types.Scope() == nil {
			continue
		}
		collectExports(pkg, surface)
	}
	return surface, nil
}

func collectExports(pkg *packages.Package, surface map[string]string) {
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
		surface[pkg.PkgPath+"."+name] = types.TypeString(obj.Type(), qualifier)
		if named, ok := obj.Type().(*types.Named); ok {
			collectMethods(pkg.PkgPath, name, named, qualifier, surface)
		}
	}
}

func collectMethods(pkgPath, typeName string, named *types.Named, qualifier types.Qualifier, surface map[string]string) {
	for method := range named.Methods() {
		if !method.Exported() {
			continue
		}
		key := pkgPath + "." + typeName + "." + method.Name()
		surface[key] = types.TypeString(method.Type(), qualifier)
	}
}

// APIBreakFindings reports exported symbols the change removed or re-signed.
// Additions are compatible and are not reported.
func APIBreakFindings(base, head map[string]string) []Finding {
	var out []Finding
	for _, key := range slices.Sorted(maps.Keys(base)) {
		headType, present := head[key]
		pkgPath, symbol := splitSymbol(key)
		switch {
		case !present:
			out = append(out, Finding{
				RuleID:   policy.RuleAPIBreak,
				File:     pkgPath,
				Message:  "exported symbol " + symbol + " was removed from " + pkgPath,
				Severity: evidence.SeverityError,
			})
		case headType != base[key]:
			out = append(out, Finding{
				RuleID:   policy.RuleAPIBreak,
				File:     pkgPath,
				Message:  "exported symbol " + symbol + " in " + pkgPath + " changed type from " + base[key] + " to " + headType,
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
