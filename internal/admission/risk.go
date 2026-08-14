package admission

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// RiskDomain is a class of change that carries its own evidence obligations.
type RiskDomain string

// The six risk domains.
const (
	RiskConcurrency RiskDomain = "concurrency"
	RiskNetwork     RiskDomain = "network"
	RiskPersistence RiskDomain = "persistence"
	RiskPublicAPI   RiskDomain = "public-api"
	RiskTests       RiskDomain = "tests"
	RiskHotPath     RiskDomain = "hot-path"
)

// RiskDomains returns every domain in report order.
func RiskDomains() []RiskDomain {
	return []RiskDomain{
		RiskConcurrency, RiskNetwork, RiskPersistence,
		RiskPublicAPI, RiskTests, RiskHotPath,
	}
}

// RiskProfile is the set of domains a change touches, with the reason each was
// activated so a reviewer can see why extra checks ran.
type RiskProfile struct {
	Active  []RiskDomain
	Reasons map[RiskDomain][]string
}

// Has reports whether a domain is active.
func (p RiskProfile) Has(domain RiskDomain) bool {
	return slices.Contains(p.Active, domain)
}

// HasAny reports whether any of the given domains is active.
func (p RiskProfile) HasAny(domains ...RiskDomain) bool {
	return slices.ContainsFunc(domains, p.Has)
}

func (p *RiskProfile) activate(domain RiskDomain, reason string) {
	if p.Reasons == nil {
		p.Reasons = map[RiskDomain][]string{}
	}
	if !slices.Contains(p.Active, domain) {
		p.Active = append(p.Active, domain)
	}
	if !slices.Contains(p.Reasons[domain], reason) {
		p.Reasons[domain] = append(p.Reasons[domain], reason)
	}
}

func (p *RiskProfile) normalize() {
	order := RiskDomains()
	slices.SortStableFunc(p.Active, func(a, b RiskDomain) int {
		return slices.Index(order, a) - slices.Index(order, b)
	})
	for domain := range p.Reasons {
		slices.Sort(p.Reasons[domain])
	}
}

// DetectionInput is what risk detection reads: the changed files, the files of
// the packages in scope (to find benchmarks), and the tree to read them from.
type DetectionInput struct {
	Root         string
	ChangedFiles []string
	ScopeFiles   []string
	Contract     TaskContract
	AllActive    bool
}

// DetectRisks derives the risk profile from the change. Detection errs toward
// activation: a false activation costs extra checks, a false non-activation
// costs trust.
func DetectRisks(ctx context.Context, in DetectionInput) (RiskProfile, error) {
	var profile RiskProfile
	if in.AllActive {
		for _, domain := range RiskDomains() {
			profile.activate(domain, "repository audit treats every risk domain as active")
		}
		profile.normalize()
		return profile, nil
	}
	for _, domain := range in.Contract.DeclaredRisks {
		profile.activate(domain, "declared by the task contract")
	}

	for _, rel := range in.ChangedFiles {
		if err := ctx.Err(); err != nil {
			return RiskProfile{}, err
		}
		if strings.HasSuffix(rel, "_test.go") {
			profile.activate(RiskTests, "test file changed: "+rel)
		}
		if isMigrationPath(rel) {
			profile.activate(RiskPersistence, "migration file changed: "+rel)
		}
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		if err := detectInFile(in.Root, rel, &profile); err != nil {
			return RiskProfile{}, err
		}
	}
	if err := detectBenchmarks(ctx, in, &profile); err != nil {
		return RiskProfile{}, err
	}
	profile.normalize()
	return profile, nil
}

func isMigrationPath(rel string) bool {
	for part := range strings.SplitSeq(rel, "/") {
		if part == "migrations" || part == "migration" {
			return true
		}
	}
	return false
}

func detectInFile(root, rel string, profile *RiskProfile) error {
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s for risk detection: %w", rel, err)
	}
	file, parsed := parseForRisk(rel, src)
	if !parsed {
		// A file that does not parse is the compile check's finding; risk
		// detection stays silent rather than guessing at its contents.
		return nil
	}

	for _, spec := range file.Imports {
		importPath := strings.Trim(spec.Path.Value, `"`)
		switch {
		case isConcurrencyImport(importPath):
			profile.activate(RiskConcurrency, "changed file imports "+importPath+": "+rel)
		case isNetworkImport(importPath):
			profile.activate(RiskNetwork, "changed file imports "+importPath+": "+rel)
		case isPersistenceImport(importPath):
			profile.activate(RiskPersistence, "changed file imports "+importPath+": "+rel)
		}
	}

	if hasConcurrencySyntax(file) {
		profile.activate(RiskConcurrency, "changed file uses goroutines or channels: "+rel)
	}
	if isPublicPackagePath(rel) && hasExportedDecl(file) {
		profile.activate(RiskPublicAPI, "changed file declares exported API: "+rel)
	}
	return nil
}

// parseForRisk reports whether the source parsed well enough to inspect.
func parseForRisk(rel string, src []byte) (*ast.File, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, false
	}
	return file, true
}

func isConcurrencyImport(p string) bool {
	return p == "sync" || p == "sync/atomic" || p == "golang.org/x/sync/errgroup" ||
		p == "golang.org/x/sync/semaphore"
}

func isNetworkImport(p string) bool {
	switch {
	case p == "net", strings.HasPrefix(p, "net/"):
		return p != "net/url"
	case strings.HasPrefix(p, "google.golang.org/grpc"):
		return true
	case strings.HasPrefix(p, "github.com/gorilla/"), strings.HasPrefix(p, "github.com/gin-gonic/"):
		return true
	}
	return false
}

func isPersistenceImport(p string) bool {
	switch {
	case p == "database/sql", strings.HasPrefix(p, "database/sql/"):
		return true
	case strings.HasPrefix(p, "gorm.io/"), strings.HasPrefix(p, "github.com/jmoiron/sqlx"):
		return true
	case strings.HasPrefix(p, "github.com/lib/pq"), strings.HasPrefix(p, "github.com/jackc/pgx"):
		return true
	case strings.HasPrefix(p, "github.com/go-sql-driver/"), strings.HasPrefix(p, "go.mongodb.org/"):
		return true
	}
	return false
}

func hasConcurrencySyntax(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.GoStmt, *ast.SelectStmt, *ast.SendStmt, *ast.ChanType:
			found = true
		case *ast.UnaryExpr:
			if node.Op == token.ARROW {
				found = true
			}
		}
		return !found
	})
	return found
}

func hasExportedDecl(file *ast.File) bool {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				return true
			}
		case *ast.GenDecl:
			if slices.ContainsFunc(d.Specs, exportedSpec) {
				return true
			}
		}
	}
	return false
}

func exportedSpec(spec ast.Spec) bool {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return s.Name.IsExported()
	case *ast.ValueSpec:
		return slices.ContainsFunc(s.Names, func(n *ast.Ident) bool { return n.IsExported() })
	}
	return false
}

// isPublicPackagePath reports whether a file belongs to a package that other
// modules can import: not under internal, not a main package directory by
// convention, and not a test file.
func isPublicPackagePath(rel string) bool {
	if strings.HasSuffix(rel, "_test.go") {
		return false
	}
	return !slices.Contains(strings.Split(path.Dir(rel), "/"), "internal")
}

func detectBenchmarks(ctx context.Context, in DetectionInput, profile *RiskProfile) error {
	changedDirs := map[string]bool{}
	for _, rel := range in.ChangedFiles {
		if strings.HasSuffix(rel, ".go") {
			changedDirs[path.Dir(rel)] = true
		}
	}
	for _, rel := range slices.Sorted(slices.Values(in.ScopeFiles)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasSuffix(rel, "_test.go") || !changedDirs[path.Dir(rel)] {
			continue
		}
		src, err := os.ReadFile(filepath.Join(in.Root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		file, parsed := parseForRisk(rel, src)
		if !parsed {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Benchmark") {
				profile.activate(RiskHotPath, "benchmark in an affected package: "+rel)
				break
			}
		}
	}
	return nil
}

// ReasonsFor returns the activation reasons for a domain, sorted.
func (p RiskProfile) ReasonsFor(domain RiskDomain) []string {
	return slices.Clone(p.Reasons[domain])
}

// AllReasons returns every activation reason keyed by domain, for the report.
func (p RiskProfile) AllReasons() map[string][]string {
	out := make(map[string][]string, len(p.Reasons))
	for domain, reasons := range p.Reasons {
		out[string(domain)] = slices.Clone(reasons)
	}
	return out
}
