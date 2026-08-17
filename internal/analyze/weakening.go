package analyze

import (
	"context"
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// TestShape is the observable strength of one test function: how many times it
// can fail, whether it runs at all, and the numeric bounds it asserts.
type TestShape struct {
	Key        string
	Package    string
	File       string
	Name       string
	Line       int
	Assertions int
	Skips      bool
	Tolerances []float64
}

// TestShapes measures every test function in the given files.
func TestShapes(ctx context.Context, root string, relFiles []string) (map[string]TestShape, error) {
	testFiles := make([]string, 0, len(relFiles))
	for _, rel := range relFiles {
		if strings.HasSuffix(rel, "_test.go") {
			testFiles = append(testFiles, rel)
		}
	}
	units, err := parseUnits(ctx, root, testFiles)
	if err != nil {
		return nil, err
	}
	shapes := map[string]TestShape{}
	for _, u := range units {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u.collectTestShapes(shapes)
	}
	return shapes, nil
}

func (u *unit) collectTestShapes(shapes map[string]TestShape) {
	for i, file := range u.files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !isTestFunc(fn) {
				continue
			}
			shape := TestShape{
				Key:        u.dir + ":" + fn.Name.Name,
				Package:    u.dir,
				File:       u.relPaths[i],
				Name:       fn.Name.Name,
				Line:       u.fset.Position(fn.Pos()).Line,
				Assertions: countAssertions(fn.Body),
				Skips:      containsSkip(fn.Body),
				Tolerances: numericBounds(fn.Body),
			}
			shapes[shape.Key] = shape
		}
	}
}

func countAssertions(body *ast.BlockStmt) int {
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isFailureCall(node) || isTestifyCall(node) {
				count++
			}
		case *ast.IfStmt:
			if containsComparison(node.Cond) {
				count++
			}
		}
		return true
	})
	return count
}

func containsSkip(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		switch sel.Sel.Name {
		case "Skip", "Skipf", "SkipNow":
			found = true
		}
		return !found
	})
	return found
}

// numericBounds collects the float literals a test compares against, sorted, so
// that a widened tolerance is visible as a larger bound at the same index.
func numericBounds(body *ast.BlockStmt) []float64 {
	var out []float64
	ast.Inspect(body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || !isComparisonOp(bin.Op.String()) {
			return true
		}
		for _, side := range []ast.Expr{bin.X, bin.Y} {
			lit, isLit := side.(*ast.BasicLit)
			if !isLit {
				continue
			}
			if value, err := strconv.ParseFloat(lit.Value, 64); err == nil {
				out = append(out, value)
			}
		}
		return true
	})
	slices.Sort(out)
	return out
}

func isComparisonOp(op string) bool {
	switch op {
	case "<", ">", "<=", ">=":
		return true
	}
	return false
}

// WeakeningFindings compares test strength between two snapshots. Removing the
// ability of a test to fail, while what it observed is still there, is the
// cheapest way to make a suite lie, so the hard signals are required.
//
// A test that vanishes is reported only where its package lost observable
// failures overall. Renaming or rewriting a test moves its assertions rather
// than removing them, and a gate that called that weakening would turn every
// honest test refactor into a rejection; what matters is whether the suite came
// out of the change able to fail as often as it went in.
func WeakeningFindings(base, head map[string]TestShape, packageSurvives func(dir string) bool) []Finding {
	baseStrength, headStrength := packageAssertions(base), packageAssertions(head)
	var out []Finding
	for _, key := range slices.Sorted(maps.Keys(base)) {
		baseShape := base[key]
		headShape, present := head[key]
		if !present {
			lost := headStrength[baseShape.Package] < baseStrength[baseShape.Package]
			if lost && packageSurvives != nil && packageSurvives(baseShape.Package) {
				out = append(out, Finding{
					RuleID: policy.RuleTestDeleted, File: baseShape.File, Line: baseShape.Line,
					Message: fmt.Sprintf(
						"test %s was deleted and its package fell from %d observable failure(s) to %d",
						baseShape.Name, baseStrength[baseShape.Package], headStrength[baseShape.Package]),
					Severity: evidence.SeverityError,
				})
			}
			continue
		}
		out = append(out, compareShapes(baseShape, headShape)...)
	}
	sortFindings(out)
	return out
}

// packageAssertions totals how many times each package's tests can fail.
func packageAssertions(shapes map[string]TestShape) map[string]int {
	out := map[string]int{}
	for _, shape := range shapes {
		out[shape.Package] += shape.Assertions
	}
	return out
}

func compareShapes(base, head TestShape) []Finding {
	var out []Finding
	if head.Assertions < base.Assertions {
		out = append(out, Finding{
			RuleID: policy.RuleAssertionRemoved, File: head.File, Line: head.Line,
			Message: fmt.Sprintf("test %s dropped from %d observable failure(s) to %d",
				head.Name, base.Assertions, head.Assertions),
			Severity: evidence.SeverityError,
		})
	}
	if head.Skips && !base.Skips {
		out = append(out, Finding{
			RuleID: policy.RuleSkipAdded, File: head.File, Line: head.Line,
			Message:  "test " + head.Name + " now skips, so it reports success for work that no longer runs",
			Severity: evidence.SeverityError,
		})
	}
	if widened, from, to := widenedBound(base.Tolerances, head.Tolerances); widened {
		out = append(out, Finding{
			RuleID: policy.RuleToleranceWidened, File: head.File, Line: head.Line,
			Message: fmt.Sprintf("test %s widened a numeric bound from %g to %g",
				head.Name, from, to),
			Severity: evidence.SeverityWarning, Advisory: true,
		})
	}
	return out
}

func widenedBound(base, head []float64) (widened bool, from, to float64) {
	if len(base) != len(head) {
		return false, 0, 0
	}
	for i := range base {
		if head[i] > base[i] {
			return true, base[i], head[i]
		}
	}
	return false, 0, 0
}
