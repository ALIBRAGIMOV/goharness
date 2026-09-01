package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
)

// FunctionTarget names one function the mutation engine may mutate.
type FunctionTarget struct {
	Package string
	File    string
	Name    string
	Line    int
}

// Mutant is one deliberate defect injected into a copy of a source file. The
// worktree is never touched: Source is written to a temporary file and applied
// through a go build overlay.
type Mutant struct {
	File        string
	Package     string
	Line        int
	Operator    string
	Description string
	Source      []byte
}

// ChangedFunctions returns the functions whose body differs between two
// snapshots, plus the functions the change introduced. This is the mutation
// engine's subject set: mutating unchanged code would measure the whole suite
// rather than the change.
func ChangedFunctions(ctx context.Context, base, head fs.FS, relFiles []string) ([]FunctionTarget, error) {
	baseBodies, err := functionBodies(ctx, base, relFiles)
	if err != nil {
		return nil, err
	}
	headBodies, err := functionBodies(ctx, head, relFiles)
	if err != nil {
		return nil, err
	}
	var out []FunctionTarget
	for _, key := range slices.Sorted(maps.Keys(headBodies)) {
		head := headBodies[key]
		if base, existed := baseBodies[key]; existed && base.hash == head.hash {
			continue
		}
		out = append(out, head.target)
	}
	return out, nil
}

type functionBody struct {
	hash   string
	target FunctionTarget
}

func functionBodies(ctx context.Context, tree fs.FS, relFiles []string) (map[string]functionBody, error) {
	out := map[string]functionBody{}
	for _, rel := range relFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, err := fs.ReadFile(tree, rel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("reading %s: %w", rel, err)
		}
		fset := token.NewFileSet()
		file, ok := parseFile(fset, rel, src)
		if !ok {
			continue
		}
		dir := path.Dir(rel)
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			sum := sha256.Sum256(src[start:end])
			out[FunctionKey(dir, fn)] = functionBody{
				hash: hex.EncodeToString(sum[:8]),
				target: FunctionTarget{
					Package: dir,
					File:    rel,
					Name:    funcDisplayName(fn),
					Line:    fset.Position(fn.Pos()).Line,
				},
			}
		}
	}
	return out, nil
}

// GenerateMutants produces deterministic mutants for the given targets, ordered
// by file then byte offset and capped at limit. Each mutant is a complete file
// with exactly one edit.
//
// The cap is spread across the changed files rather than spent on the first of
// them. Taking the first limit mutants in path order samples the change only
// when the change is one file: a nineteen-file branch produced sixteen mutants
// that all came from its alphabetically first package, so the evidence spoke
// about that package and said nothing at all about the other eighteen.
func GenerateMutants(ctx context.Context, tree fs.FS, targets []FunctionTarget, limit int) ([]Mutant, error) {
	byFile := map[string][]FunctionTarget{}
	for _, t := range targets {
		byFile[t.File] = append(byFile[t.File], t)
	}
	var perFile [][]Mutant
	total := 0
	for _, rel := range slices.Sorted(maps.Keys(byFile)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fileMutants, err := mutateFile(tree, rel, byFile[rel])
		if err != nil {
			return nil, err
		}
		if len(fileMutants) > 0 {
			perFile = append(perFile, fileMutants)
			total += len(fileMutants)
		}
	}
	return spreadMutants(perFile, total, limit), nil
}

// spreadMutants takes one mutant from each file in turn until the budget is
// spent, then restores the file-and-offset order the caller is promised. The
// per-file slices arrive in path order and each is already in offset order, so
// a stable sort on file and line reproduces it exactly.
func spreadMutants(perFile [][]Mutant, total, limit int) []Mutant {
	if limit <= 0 || total < limit {
		limit = total
	}
	if limit == 0 {
		return nil
	}
	out := make([]Mutant, 0, limit)
	for round := 0; len(out) < limit; round++ {
		taken := 0
		for _, file := range perFile {
			if round >= len(file) {
				continue
			}
			out = append(out, file[round])
			taken++
			if len(out) == limit {
				break
			}
		}
		if taken == 0 {
			break
		}
	}
	slices.SortStableFunc(out, func(a, b Mutant) int {
		if a.File != b.File {
			return strings.Compare(a.File, b.File)
		}
		return a.Line - b.Line
	})
	return out
}

// parseSource reports whether the source parsed.
func parseSource(fset *token.FileSet, rel string, src []byte) (*ast.File, bool) {
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, false
	}
	return file, true
}

type edit struct {
	offset      int
	length      int
	replacement string
	operator    string
	description string
	line        int
}

func mutateFile(tree fs.FS, rel string, targets []FunctionTarget) ([]Mutant, error) {
	src, err := fs.ReadFile(tree, rel)
	if err != nil {
		return nil, fmt.Errorf("reading %s for mutation: %w", rel, err)
	}
	fset := token.NewFileSet()
	file, parsed := parseSource(fset, rel, src)
	if !parsed {
		// Unparsable source has no mutants; the compile check owns that failure.
		return nil, nil
	}
	wanted := map[string]bool{}
	for _, t := range targets {
		wanted[t.Name] = true
	}

	var edits []edit
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !wanted[funcDisplayName(fn)] {
			continue
		}
		edits = append(edits, collectEdits(fset, fn)...)
	}
	slices.SortStableFunc(edits, func(a, b edit) int { return a.offset - b.offset })

	out := make([]Mutant, 0, len(edits))
	for _, e := range edits {
		mutated := make([]byte, 0, len(src)+len(e.replacement))
		mutated = append(mutated, src[:e.offset]...)
		mutated = append(mutated, e.replacement...)
		mutated = append(mutated, src[e.offset+e.length:]...)
		out = append(out, Mutant{
			File: rel, Package: path.Dir(rel), Line: e.line,
			Operator: e.operator, Description: e.description, Source: mutated,
		})
	}
	return out, nil
}

func collectEdits(fset *token.FileSet, fn *ast.FuncDecl) []edit {
	var edits []edit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if flipped, ok := flipRelational(node.Op); ok {
				pos := fset.Position(node.OpPos)
				edits = append(edits, edit{
					offset: pos.Offset, length: len(node.Op.String()), replacement: flipped,
					operator:    "relational",
					description: "relational operator " + node.Op.String() + " replaced with " + flipped,
					line:        pos.Line,
				})
			}
		case *ast.Ident:
			if node.Name != "true" && node.Name != "false" {
				return true
			}
			pos := fset.Position(node.Pos())
			replacement := "false"
			if node.Name == "false" {
				replacement = "true"
			}
			edits = append(edits, edit{
				offset: pos.Offset, length: len(node.Name), replacement: replacement,
				operator:    "boolean",
				description: "boolean literal " + node.Name + " replaced with " + replacement,
				line:        pos.Line,
			})
		case *ast.ReturnStmt:
			edits = append(edits, errorReturnEdits(fset, node)...)
		}
		return true
	})
	return edits
}

func errorReturnEdits(fset *token.FileSet, ret *ast.ReturnStmt) []edit {
	var edits []edit
	for _, result := range ret.Results {
		ident, ok := result.(*ast.Ident)
		if !ok || ident.Name != "err" {
			continue
		}
		pos := fset.Position(ident.Pos())
		edits = append(edits, edit{
			offset: pos.Offset, length: len(ident.Name), replacement: "nil",
			operator:    "error-return",
			description: "returned error replaced with nil",
			line:        pos.Line,
		})
	}
	return edits
}

func flipRelational(op token.Token) (string, bool) {
	switch op {
	case token.LSS:
		return ">=", true
	case token.LEQ:
		return ">", true
	case token.GTR:
		return "<=", true
	case token.GEQ:
		return "<", true
	case token.EQL:
		return "!=", true
	case token.NEQ:
		return "==", true
	}
	return "", false
}
