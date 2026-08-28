package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// CloneMinStatements is the size below which two identically shaped functions
// carry no signal: short accessors and constructors legitimately look alike.
const CloneMinStatements = 12

type cloneSite struct {
	file string
	line int
	name string
}

// Clones reports functions whose statement shape is identical to another
// function in scope, ignoring identifiers and literals. It is advisory: whether
// two identical shapes should be one function or deliberately separate is a
// design decision the scanner cannot make.
//
// Duplication is a property of the scope rather than of one package, so the
// shapes are collected across every unit before any of them is judged.
//
// generated names the files whose contents a tool wrote. They are passed over:
// a generator producing the same shape twice is not a design decision anybody
// will revisit, and the names it chose move when it runs again, so the same
// duplication reads as introduced and repaired in a single report.
func (s *ParsedScope) Clones(ctx context.Context, generated map[string]bool) ([]Finding, error) {
	byShape := map[string][]cloneSite{}
	for _, u := range s.units {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u.collectShapes(byShape, generated)
	}
	return groupClones(byShape), nil
}

// CloneFindings parses the given files and reports the functions among them
// that share a statement shape.
func CloneFindings(ctx context.Context, root string, relFiles []string) ([]Finding, error) {
	scope, err := Parse(ctx, root, relFiles)
	if err != nil {
		return nil, err
	}
	return scope.Clones(ctx, nil)
}

// groupClones turns the collected shapes into findings, reporting every site
// but the first of each shape against that first one.
func groupClones(byShape map[string][]cloneSite) []Finding {
	var out []Finding
	for _, shape := range slices.Sorted(maps.Keys(byShape)) {
		sites := byShape[shape]
		if len(sites) < 2 {
			continue
		}
		slices.SortFunc(sites, func(a, b cloneSite) int {
			if a.file != b.file {
				if a.file < b.file {
					return -1
				}
				return 1
			}
			return a.line - b.line
		})
		first := sites[0]
		for _, site := range sites[1:] {
			out = append(out, Finding{
				RuleID: policy.RuleClone, File: site.file, Line: site.line,
				Message: fmt.Sprintf("%s has the same statement shape as %s at %s:%d",
					site.name, first.name, first.file, first.line),
				Severity: evidence.SeverityInfo, Advisory: true,
			})
		}
	}
	sortFindings(out)
	return out
}

// collectShapes skips test files. An arrange-act-assert body legitimately
// repeats its shape across cases, so a clone report there is noise rather than
// a design signal. This scanner is the only duplication check the harness runs,
// so the exemption has to live here rather than in a linter configuration.
func (u *unit) collectShapes(byShape map[string][]cloneSite, generated map[string]bool) {
	for i, file := range u.files {
		if strings.HasSuffix(u.relPaths[i], "_test.go") || generated[u.relPaths[i]] {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || countStatements(fn.Body) < CloneMinStatements {
				continue
			}
			shape := shapeHash(fn.Body)
			byShape[shape] = append(byShape[shape], cloneSite{
				file: u.relPaths[i],
				line: u.fset.Position(fn.Pos()).Line,
				name: funcDisplayName(fn),
			})
		}
	}
}

func countStatements(body *ast.BlockStmt) int {
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(ast.Stmt); ok {
			count++
		}
		return true
	})
	return count
}

// shapeHash reduces a body to its control and operator structure. Identifiers
// and literal values are erased, so two copies that differ only in naming hash
// the same, while two functions with different logic do not.
func shapeHash(body *ast.BlockStmt) string {
	var shape strings.Builder
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		shape.WriteString(nodeShape(n))
		return true
	})
	sum := sha256.Sum256([]byte(shape.String()))
	return hex.EncodeToString(sum[:8])
}

func nodeShape(n ast.Node) string {
	switch node := n.(type) {
	case *ast.Ident, *ast.BasicLit:
		return "x;"
	case *ast.BinaryExpr:
		return "b" + node.Op.String() + ";"
	case *ast.UnaryExpr:
		return "u" + node.Op.String() + ";"
	case *ast.AssignStmt:
		return "a" + node.Tok.String() + strconv.Itoa(len(node.Lhs)) + ";"
	case *ast.BranchStmt:
		return "br" + node.Tok.String() + ";"
	default:
		return fmt.Sprintf("%T;", n)
	}
}
