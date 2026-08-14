package change

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Package is one loaded Go package, reduced to what scoping needs.
type Package struct {
	PkgPath string
	Name    string
	Dir     string
	GoFiles []string
	Imports []string
	Errors  []PackageError
}

// PackageError is a load or type-check error attached to a package.
type PackageError struct {
	File    string
	Line    int
	Column  int
	Message string
}

// PackageGraph is the loaded module with a precomputed reverse-dependency
// index.
type PackageGraph struct {
	Root     string
	packages map[string]Package
	reverse  map[string][]string
	byDir    map[string]string
}

// graphLoadMode deliberately stops short of NeedTypes. Scoping needs names,
// files, and the import edges; type checking the whole module on every run
// costs more than every other check combined and only duplicates what go build
// already reports precisely. Loader errors still surface as compile evidence,
// and go build remains the authority on type errors.
const graphLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedModule

// LoadGraph loads every package in the module rooted at dir.
func LoadGraph(ctx context.Context, dir string) (PackageGraph, error) {
	cfg := &packages.Config{
		Context: ctx,
		Mode:    graphLoadMode,
		Dir:     dir,
		Tests:   false,
	}
	loaded, err := packages.Load(cfg, "./...")
	if err != nil {
		return PackageGraph{}, fmt.Errorf("loading package graph: %w", err)
	}
	g := PackageGraph{
		Root:     dir,
		packages: map[string]Package{},
		reverse:  map[string][]string{},
		byDir:    map[string]string{},
	}
	// Only the matched root packages belong to the module. Dependencies are
	// reachable through Imports but must never enter scope, or full-scope runs
	// would lint and test the standard library.
	for _, p := range loaded {
		if p.PkgPath == "" {
			continue
		}
		g.packages[p.PkgPath] = reducePackage(p)
	}
	for path, p := range g.packages {
		if p.Dir != "" {
			g.byDir[p.Dir] = path
		}
		for _, imp := range p.Imports {
			if _, ok := g.packages[imp]; ok {
				g.reverse[imp] = append(g.reverse[imp], path)
			}
		}
	}
	for k := range g.reverse {
		slices.Sort(g.reverse[k])
	}
	return g, nil
}

func reducePackage(p *packages.Package) Package {
	out := Package{PkgPath: p.PkgPath, Name: p.Name}
	files := slices.Clone(p.GoFiles)
	if len(files) > 0 {
		out.Dir = filepath.Dir(files[0])
	}
	sort.Strings(files)
	out.GoFiles = files
	for _, imp := range p.Imports {
		out.Imports = append(out.Imports, imp.PkgPath)
	}
	sort.Strings(out.Imports)
	for _, e := range p.Errors {
		file, line, col := splitPos(e.Pos)
		out.Errors = append(out.Errors, PackageError{
			File: file, Line: line, Column: col, Message: e.Msg,
		})
	}
	return out
}

func splitPos(pos string) (file string, line, col int) {
	parts := strings.Split(pos, ":")
	if len(parts) < 3 {
		return pos, 0, 0
	}
	line = atoi(parts[len(parts)-2])
	col = atoi(parts[len(parts)-1])
	return strings.Join(parts[:len(parts)-2], ":"), line, col
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// Packages returns every loaded package path, sorted.
func (g PackageGraph) Packages() []string {
	out := make([]string, 0, len(g.packages))
	for p := range g.packages {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Errors returns every load and type-check error in the graph, sorted.
func (g PackageGraph) Errors() []PackageError {
	var out []PackageError
	for _, path := range g.Packages() {
		out = append(out, g.packages[path].Errors...)
	}
	return out
}

// PackageForFile maps a repository-relative file path to its package by
// directory, which also resolves _test.go files that the loader excludes.
func (g PackageGraph) PackageForFile(relFile string) (string, bool) {
	dir := filepath.Join(g.Root, filepath.Dir(filepath.FromSlash(relFile)))
	path, ok := g.byDir[dir]
	return path, ok
}

// Scope describes how far reverse dependencies are followed.
type Scope int

// Reverse-dependency scopes.
const (
	ScopeChangedOnly Scope = iota
	ScopeDirectDependents
	ScopeFullClosure
)

// Affected returns the packages a set of seed packages can affect under the
// given scope, sorted and including the seeds themselves.
func (g PackageGraph) Affected(seeds []string, scope Scope) []string {
	selected := map[string]bool{}
	var queue []string
	for _, s := range seeds {
		if _, ok := g.packages[s]; ok && !selected[s] {
			selected[s] = true
			queue = append(queue, s)
		}
	}
	if scope == ScopeChangedOnly {
		return sortedKeys(selected)
	}
	frontier := queue
	for depth := 0; len(frontier) > 0; depth++ {
		var next []string
		for _, p := range frontier {
			for _, dep := range g.reverse[p] {
				if selected[dep] {
					continue
				}
				selected[dep] = true
				next = append(next, dep)
			}
		}
		if scope == ScopeDirectDependents {
			break
		}
		frontier = next
	}
	return sortedKeys(selected)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SeedPackages maps changed Go files onto the packages that contain them.
func (g PackageGraph) SeedPackages(relFiles []string) []string {
	set := map[string]bool{}
	for _, f := range relFiles {
		if path, ok := g.PackageForFile(f); ok {
			set[path] = true
		}
	}
	return sortedKeys(set)
}

// FilesFor returns every Go file in the directories of the given packages,
// module-relative and sorted. Reading the directory rather than the loader's
// file list keeps _test.go files in scope; testdata directories stay out of
// scope because they are never package directories.
func (g PackageGraph) FilesFor(pkgPaths []string) ([]string, error) {
	set := map[string]bool{}
	for _, p := range pkgPaths {
		pkg, ok := g.packages[p]
		if !ok || pkg.Dir == "" {
			continue
		}
		entries, err := os.ReadDir(pkg.Dir)
		if err != nil {
			return nil, fmt.Errorf("listing package directory %s: %w", pkg.Dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			rel, relErr := filepath.Rel(g.Root, filepath.Join(pkg.Dir, e.Name()))
			if relErr != nil {
				continue
			}
			set[filepath.ToSlash(rel)] = true
		}
	}
	return sortedKeys(set), nil
}

// DirAndName returns a package's absolute directory and its package name.
func (g PackageGraph) DirAndName(pkgPath string) (dir, name string, ok bool) {
	pkg, found := g.packages[pkgPath]
	if !found || pkg.Dir == "" {
		return "", "", false
	}
	return pkg.Dir, pkg.Name, true
}

// HasMainPackage reports whether any of the given packages produces an
// executable, which decides whether go build needs an output directory.
func (g PackageGraph) HasMainPackage(pkgPaths []string) bool {
	for _, p := range pkgPaths {
		if pkg, ok := g.packages[p]; ok && pkg.Name == "main" {
			return true
		}
	}
	return false
}

// PatternsFor turns package paths into go tool command-line patterns.
func (g PackageGraph) PatternsFor(pkgPaths []string) []string {
	out := make([]string, 0, len(pkgPaths))
	for _, p := range pkgPaths {
		if _, ok := g.packages[p]; ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// RelDirsFor turns package paths into "./dir" patterns rooted at the module,
// the form external linters accept most reliably.
func (g PackageGraph) RelDirsFor(pkgPaths []string) []string {
	set := map[string]bool{}
	for _, p := range pkgPaths {
		pkg, ok := g.packages[p]
		if !ok || pkg.Dir == "" {
			continue
		}
		rel, err := filepath.Rel(g.Root, pkg.Dir)
		if err != nil {
			continue
		}
		set["./"+filepath.ToSlash(rel)] = true
	}
	return sortedKeys(set)
}
