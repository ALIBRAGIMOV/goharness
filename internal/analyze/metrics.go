package analyze

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// Mechanical budgets for the simplicity dimension. They are absolute: past
// these points a function cannot be reasoned about or covered completely,
// whatever its history.
const (
	MaxComplexity     = 25
	MaxNesting        = 5
	AdvisoryLines     = 80
	MaxComplexityRise = 10
)

// FunctionMetric is the mechanical shape of one function.
type FunctionMetric struct {
	Key        string
	Package    string
	File       string
	Name       string
	Line       int
	Complexity int
	Nesting    int
	Lines      int
}

// PackageMetric is the mechanical shape of one package.
type PackageMetric struct {
	Path               string
	FanOut             int
	ExportedSymbols    int
	DocumentedExported int
}

// DocCoverage returns the documented fraction of exported symbols, or one when
// the package exports nothing.
func (m PackageMetric) DocCoverage() float64 {
	if m.ExportedSymbols == 0 {
		return 1
	}
	return float64(m.DocumentedExported) / float64(m.ExportedSymbols)
}

// Metrics is a whole snapshot's mechanical shape, keyed so that the same
// function and package can be found in another snapshot.
type Metrics struct {
	Functions map[string]FunctionMetric
	Packages  map[string]PackageMetric
}

// Metrics measures every function and package in the parsed scope.
func (s *ParsedScope) Metrics(ctx context.Context) (Metrics, error) {
	m := Metrics{
		Functions: map[string]FunctionMetric{},
		Packages:  map[string]PackageMetric{},
	}
	for _, u := range s.units {
		if err := ctx.Err(); err != nil {
			return Metrics{}, err
		}
		u.measure(&m)
	}
	return m, nil
}

// ComputeMetrics parses the given files and measures every function and package
// in them.
func ComputeMetrics(ctx context.Context, root string, relFiles []string) (Metrics, error) {
	scope, err := Parse(ctx, root, relFiles)
	if err != nil {
		return Metrics{}, err
	}
	return scope.Metrics(ctx)
}

func (u *unit) measure(m *Metrics) {
	pkg := PackageMetric{Path: u.dir}
	imports := map[string]bool{}

	for i, file := range u.files {
		rel := u.relPaths[i]
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		for _, spec := range file.Imports {
			imports[strings.Trim(spec.Path.Value, `"`)] = true
		}
		countExported(file, &pkg)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			metric := measureFunc(u.fset, u.dir, rel, fn)
			m.Functions[metric.Key] = metric
		}
	}
	pkg.FanOut = len(imports)
	m.Packages[u.dir] = pkg
}

func countExported(file *ast.File, pkg *PackageMetric) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if !d.Name.IsExported() {
				continue
			}
			pkg.ExportedSymbols++
			if d.Doc != nil {
				pkg.DocumentedExported++
			}
		case *ast.GenDecl:
			countExportedSpecs(d, pkg)
		}
	}
}

func countExportedSpecs(decl *ast.GenDecl, pkg *PackageMetric) {
	for _, spec := range decl.Specs {
		var documented bool
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if !s.Name.IsExported() {
				continue
			}
			documented = s.Doc != nil || decl.Doc != nil
		case *ast.ValueSpec:
			if !slices.ContainsFunc(s.Names, func(n *ast.Ident) bool { return n.IsExported() }) {
				continue
			}
			documented = s.Doc != nil || decl.Doc != nil
		default:
			continue
		}
		pkg.ExportedSymbols++
		if documented {
			pkg.DocumentedExported++
		}
	}
}

func measureFunc(fset *token.FileSet, dir, rel string, fn *ast.FuncDecl) FunctionMetric {
	start := fset.Position(fn.Pos())
	end := fset.Position(fn.End())
	return FunctionMetric{
		Key:        FunctionKey(dir, fn),
		Package:    dir,
		File:       rel,
		Name:       funcDisplayName(fn),
		Line:       start.Line,
		Complexity: cyclomaticComplexity(fn.Body),
		Nesting:    nestingDepth(fn.Body),
		Lines:      end.Line - start.Line + 1,
	}
}

// FunctionKey identifies a function across snapshots. It deliberately excludes
// the file name: moving a function between files in the same package must not
// look like a deletion plus an addition.
func FunctionKey(dir string, fn *ast.FuncDecl) string {
	return dir + ":" + funcDisplayName(fn)
}

func funcDisplayName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + typeName(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func typeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return "*" + typeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return typeName(t.X)
	case *ast.IndexListExpr:
		return typeName(t.X)
	case *ast.SelectorExpr:
		return typeName(t.X) + "." + t.Sel.Name
	}
	return "?"
}

func cyclomaticComplexity(body *ast.BlockStmt) int {
	complexity := 1
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CommClause:
			complexity++
		case *ast.CaseClause:
			if len(node.List) > 0 {
				complexity += len(node.List)
			}
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				complexity++
			}
		}
		return true
	})
	return complexity
}

func nestingDepth(body *ast.BlockStmt) int {
	var walk func(n ast.Node, depth int) int
	walk = func(n ast.Node, depth int) int {
		deepest := depth
		ast.Inspect(n, func(child ast.Node) bool {
			if child == n {
				return true
			}
			if !introducesNesting(child) {
				return true
			}
			if d := walk(child, depth+1); d > deepest {
				deepest = d
			}
			return false
		})
		return deepest
	}
	return walk(body, 0)
}

func introducesNesting(n ast.Node) bool {
	switch n.(type) {
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
		*ast.TypeSwitchStmt, *ast.SelectStmt:
		return true
	}
	return false
}

// SimplicityFindings reports functions that exceed the absolute budgets.
func SimplicityFindings(m Metrics) []Finding {
	var out []Finding
	for _, key := range slices.Sorted(maps.Keys(m.Functions)) {
		fn := m.Functions[key]
		if fn.Complexity > MaxComplexity {
			out = append(out, Finding{
				RuleID: policy.RuleComplexity, File: fn.File, Line: fn.Line,
				Message: fmt.Sprintf("%s has cyclomatic complexity %d, over the budget of %d",
					fn.Name, fn.Complexity, MaxComplexity),
				Severity: evidence.SeverityError,
			})
		}
		if fn.Nesting > MaxNesting {
			out = append(out, Finding{
				RuleID: policy.RuleNesting, File: fn.File, Line: fn.Line,
				Message: fmt.Sprintf("%s nests %d levels deep, over the budget of %d",
					fn.Name, fn.Nesting, MaxNesting),
				Severity: evidence.SeverityError,
			})
		}
		if fn.Lines > AdvisoryLines {
			out = append(out, Finding{
				RuleID: policy.RuleFunctionLength, File: fn.File, Line: fn.Line,
				Message:  fmt.Sprintf("%s spans %d lines", fn.Name, fn.Lines),
				Severity: evidence.SeverityInfo, Advisory: true,
			})
		}
	}
	sortFindings(out)
	return out
}

// MaintainabilityFindings compares two snapshots. A function that gets sharply
// more complex, a package that documents less of its exported surface, and a
// package that grows its fan-out are all degradations the change introduced.
//
// generated names the files whose contents a tool wrote, and no delta is
// computed across them. A function in generated code is identified by a name the
// generator chose, and regenerating after a type is deleted renumbers every name
// after it: a production run was told that easyjson...Record23 rose from
// complexity 9 to 31, when what actually happened is that the name now belongs to
// a different decoder. A delta between two functions that are not the same
// function is not a measurement, and declining to make it is not leniency.
func MaintainabilityFindings(base, head Metrics, generated map[string]bool) []Finding {
	var out []Finding
	for _, key := range slices.Sorted(maps.Keys(head.Functions)) {
		headFn := head.Functions[key]
		baseFn, existed := base.Functions[key]
		if !existed || generated[headFn.File] {
			continue
		}
		rise := headFn.Complexity - baseFn.Complexity
		if rise >= MaxComplexityRise {
			out = append(out, Finding{
				RuleID: policy.RuleComplexityDelta, File: headFn.File, Line: headFn.Line,
				Message: fmt.Sprintf("%s complexity rose from %d to %d in this change",
					headFn.Name, baseFn.Complexity, headFn.Complexity),
				Severity: evidence.SeverityError,
			})
		}
	}
	for _, dir := range slices.Sorted(maps.Keys(head.Packages)) {
		headPkg := head.Packages[dir]
		basePkg, existed := base.Packages[dir]
		if !existed {
			continue
		}
		if headPkg.DocCoverage() < basePkg.DocCoverage() {
			out = append(out, Finding{
				RuleID: policy.RuleDocCoverageDelta, Package: dir,
				Message: fmt.Sprintf("exported documentation coverage fell from %.0f%% to %.0f%%",
					basePkg.DocCoverage()*100, headPkg.DocCoverage()*100),
				Severity: evidence.SeverityWarning, Advisory: true,
			})
		}
		if headPkg.FanOut > basePkg.FanOut {
			out = append(out, Finding{
				RuleID: policy.RuleFanOutDelta, Package: dir,
				Message: fmt.Sprintf("package fan-out rose from %d to %d imports",
					basePkg.FanOut, headPkg.FanOut),
				Severity: evidence.SeverityInfo, Advisory: true,
			})
		}
	}
	sortFindings(out)
	return out
}
