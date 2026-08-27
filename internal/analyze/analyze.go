// Package analyze implements the harness's native source scanners: suppression
// directives, comment hygiene, test effectiveness, concurrency and resource
// lifetimes, persistence, architecture, and the maintainability metrics that
// feed the base/head delta. Every scanner works on parsed syntax so that string
// literals containing the same text are never mistaken for comments.
package analyze

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// Finding is one native scanner result, positioned in a module-relative file.
type Finding struct {
	RuleID   string
	File     string
	Line     int
	Column   int
	Message  string
	Severity evidence.Severity
	Advisory bool
}

// Options selects which risk-specific scanner families run. The zero value
// runs only the always-on families, so a caller with no active risk domain
// passes it unchanged.
type Options struct {
	Concurrency  bool
	Network      bool
	Persistence  bool
	Architecture ArchitectureRules
}

// ArchitectureRules are the layout constraints the architecture scanner
// enforces. Banned package names always apply; forbidden imports come from
// project configuration, so the harness never invents an architecture.
type ArchitectureRules struct {
	ModulePath       string
	ForbiddenImports []ImportRule
}

// ImportRule forbids one package prefix from importing another.
type ImportRule struct {
	From   string
	Deny   string
	Reason string
}

// unit is one parsed package directory: every file the caller put in scope for
// that directory, plus the declaration index the scanners resolve against.
type unit struct {
	dir      string
	fset     *token.FileSet
	files    []*ast.File
	relPaths []string
	decls    declIndex
}

// ParsedScope is one parse of a file set, grouped by package directory so that
// a scanner can resolve a call against declarations in sibling files.
//
// It exists so that the scanners which answer different questions about the
// same syntax read and parse it once between them rather than once each. The
// parsed trees are never written to, so the scanners may run concurrently over
// one scope; a caller that needs a different file set builds a different scope
// rather than mutating this one.
type ParsedScope struct {
	units []*unit
}

// Parse reads and parses every given file once.
func Parse(ctx context.Context, root string, relFiles []string) (*ParsedScope, error) {
	units, err := parseUnits(ctx, root, relFiles)
	if err != nil {
		return nil, err
	}
	return &ParsedScope{units: units}, nil
}

// Restrict returns a view of this scope holding only the units in the given
// package directories, or the scope itself when dirs is nil.
//
// The units are shared rather than copied. The parsed trees are never written
// to, which is what already lets several scanners read one scope at once, and
// what lets one parse serve both a directory-local scanner and one that has to
// see everything.
func (s *ParsedScope) Restrict(dirs []string) *ParsedScope {
	if dirs == nil {
		return s
	}
	keep := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		keep[dir] = true
	}
	units := make([]*unit, 0, len(dirs))
	for _, u := range s.units {
		if keep[u.dir] {
			units = append(units, u)
		}
	}
	return &ParsedScope{units: units}
}

// Scan runs every enabled scanner family over the parsed scope.
func (s *ParsedScope) Scan(ctx context.Context, opts Options) ([]Finding, error) {
	var out []Finding
	for _, u := range s.units {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out = append(out, u.scan(opts)...)
	}
	sortFindings(out)
	return out, nil
}

// Scan parses the given files and runs every enabled scanner family over them.
func Scan(ctx context.Context, root string, relFiles []string, opts Options) ([]Finding, error) {
	scope, err := Parse(ctx, root, relFiles)
	if err != nil {
		return nil, err
	}
	return scope.Scan(ctx, opts)
}

// ScanFile runs the always-on scanners over one file's source, resolving calls
// against that file alone.
func ScanFile(relPath string, src []byte) ([]Finding, error) {
	return ScanFileWithOptions(relPath, src, Options{})
}

// ScanFileWithOptions is ScanFile with an explicit scanner selection.
func ScanFileWithOptions(relPath string, src []byte, opts Options) ([]Finding, error) {
	fset := token.NewFileSet()
	file, parsed := parseFile(fset, relPath, src)
	if !parsed {
		return nil, nil
	}
	u := &unit{
		dir:      path.Dir(relPath),
		fset:     fset,
		files:    []*ast.File{file},
		relPaths: []string{relPath},
	}
	u.decls = indexDeclarations(u.files)
	findings := u.scan(opts)
	sortFindings(findings)
	return findings, nil
}

func parseUnits(ctx context.Context, root string, relFiles []string) ([]*unit, error) {
	byDir := map[string][]string{}
	for _, rel := range relFiles {
		dir := path.Dir(rel)
		byDir[dir] = append(byDir[dir], rel)
	}
	dirs := slices.Sorted(maps.Keys(byDir))

	units := make([]*unit, 0, len(dirs))
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u := &unit{dir: dir, fset: token.NewFileSet()}
		for _, rel := range slices.Sorted(slices.Values(byDir[dir])) {
			src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", rel, err)
			}
			file, ok := parseFile(u.fset, rel, src)
			if !ok {
				continue
			}
			u.files = append(u.files, file)
			u.relPaths = append(u.relPaths, rel)
		}
		if len(u.files) == 0 {
			continue
		}
		u.decls = indexDeclarations(u.files)
		units = append(units, u)
	}
	return units, nil
}

func (u *unit) scan(opts Options) []Finding {
	var out []Finding
	for i, file := range u.files {
		s := &scanner{
			fset: u.fset, file: file, rel: u.relPaths[i], decls: u.decls,
			opts: opts, firstFileOfPackage: u.relPaths[0],
		}
		s.scanComments()
		s.scanDocSizes()
		s.scanRestatements()
		s.scanArchitecture()
		s.scanForwarding()
		s.scanDeprecations()
		if opts.Concurrency {
			s.scanConcurrency()
		}
		if opts.Concurrency || opts.Network {
			s.scanBoundedResources()
		}
		if opts.Network {
			s.scanNetwork()
		}
		if opts.Persistence {
			s.scanPersistence()
		}
		if strings.HasSuffix(u.relPaths[i], "_test.go") {
			s.scanTests()
		}
		out = append(out, s.findings...)
	}
	return append(out, soleImplementationFindings(u)...)
}

// parseFile reports whether the source parsed. A file that does not parse is
// the compile check's finding, so the native scanners stay silent on it.
func parseFile(fset *token.FileSet, relPath string, src []byte) (*ast.File, bool) {
	file, err := parser.ParseFile(fset, relPath, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, false
	}
	return file, true
}

type scanner struct {
	fset  *token.FileSet
	file  *ast.File
	rel   string
	decls declIndex
	opts  Options
	// firstFileOfPackage lets a package-scoped rule report once per package
	// instead of once per file.
	firstFileOfPackage string
	findings           []Finding
}

func (s *scanner) add(pos token.Pos, ruleID, message string, severity evidence.Severity, advisory bool) {
	p := s.fset.Position(pos)
	s.findings = append(s.findings, Finding{
		RuleID:   ruleID,
		File:     s.rel,
		Line:     p.Line,
		Column:   p.Column,
		Message:  message,
		Severity: severity,
		Advisory: advisory,
	})
}

func sortFindings(f []Finding) {
	slices.SortStableFunc(f, func(a, b Finding) int {
		if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
			return c
		}
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return a.Column - b.Column
	})
}
