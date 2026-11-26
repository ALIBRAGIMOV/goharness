package analyze_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

const surfacePackage = `package api

// Store holds one value.
type Store struct{ n int }

// Put records a value.
func (s *Store) Put(v int) { s.n = v }

// Reset answers the store it was called on.
func (s *Store) Reset() *Store { return s }

func (s *Store) reachable() int { return s.n }

// Limit is the ceiling Put will accept.
const Limit = 10

func hidden() int { return 1 }
`

// surfaceModule writes a module whose only package is api, and answers its root.
func surfaceModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, src string) {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("go.mod", "module example.test/surface\n\ngo 1.26\n")
	write("api/api.go", surfacePackage)
	return root
}

// sourceLine answers the text the symbol's recorded position points at, which
// is the only way to tell a real declaration site from a plausible number.
func sourceLine(t *testing.T, root string, sym analyze.Exported) string {
	t.Helper()
	if sym.File == "" || sym.Line == 0 {
		t.Fatalf("symbol carries no declaration site: %+v", sym)
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(sym.File)))
	if err != nil {
		t.Fatalf("reading %s: %v", sym.File, err)
	}
	lines := strings.Split(string(data), "\n")
	if sym.Line > len(lines) {
		t.Fatalf("%s:%d is past the end of the file", sym.File, sym.Line)
	}
	return lines[sym.Line-1]
}

func TestExportSurfaceLocatesEverySymbolItReports(t *testing.T) {
	t.Parallel()
	root := surfaceModule(t)
	surface, err := analyze.ExportSurface(t.Context(), root, []string{"./..."})
	if err != nil {
		t.Fatalf("ExportSurface: %v", err)
	}

	const pkg = "example.test/surface/api."
	for key, want := range map[string]string{
		pkg + "Store":       "type Store struct",
		pkg + "Store.Put":   "func (s *Store) Put",
		pkg + "Store.Reset": "func (s *Store) Reset",
		pkg + "Limit":       "const Limit",
	} {
		sym, ok := surface[key]
		if !ok {
			t.Fatalf("%s missing from the surface of %d symbols", key, len(surface))
		}
		if got := sourceLine(t, root, sym); !strings.Contains(got, want) {
			t.Errorf("%s points at %s:%d, which reads %q, not %q",
				key, sym.File, sym.Line, got, want)
		}
	}
	for _, key := range []string{pkg + "hidden", pkg + "Store.reachable"} {
		if _, ok := surface[key]; ok {
			t.Errorf("%s is unexported and does not belong in an export surface", key)
		}
	}
}

// TestExportSurfaceQualifiesOnlyForeignTypes pins the rendering the comparison
// keys on: a method that answers its own package's type must render the same
// way in every package, or moving the declaration would read as a re-signature.
func TestExportSurfaceQualifiesOnlyForeignTypes(t *testing.T) {
	t.Parallel()
	root := surfaceModule(t)
	surface, err := analyze.ExportSurface(t.Context(), root, []string{"./..."})
	if err != nil {
		t.Fatalf("ExportSurface: %v", err)
	}
	reset, ok := surface["example.test/surface/api.Store.Reset"]
	if !ok {
		t.Fatal("Store.Reset missing from the surface")
	}
	if reset.Type != "func() *Store" {
		t.Errorf("Store.Reset renders as %q, want %q", reset.Type, "func() *Store")
	}
}

// TestExportSurfaceWithoutPatternsAsksTheLoaderNothing uses a root that does
// not exist: an empty pattern list that still reached the go command would
// fail there rather than answer an empty surface.
func TestExportSurfaceWithoutPatternsAsksTheLoaderNothing(t *testing.T) {
	t.Parallel()
	absent := filepath.Join(t.TempDir(), "absent")
	surface, err := analyze.ExportSurface(t.Context(), absent, nil)
	if err != nil {
		t.Fatalf("ExportSurface with no patterns: %v", err)
	}
	if len(surface) != 0 {
		t.Errorf("no patterns produced %d symbols", len(surface))
	}
}

func TestExportSurfaceReportsALoaderThatCouldNotRun(t *testing.T) {
	t.Parallel()
	absent := filepath.Join(t.TempDir(), "absent")
	if _, err := analyze.ExportSurface(t.Context(), absent, []string{"./..."}); err == nil {
		t.Fatal("loading packages from a directory that does not exist reported no error")
	}
}

// TestAPIBreakFindingsPlaceEachRowWhereItCanBeOpened holds the placement
// property: a removal is located at the declaration the base tree carried, a
// re-signature where the symbol lives now, and neither identity mentions a line,
// so a declaration that only moves keeps its finding.
func TestAPIBreakFindingsPlaceEachRowWhereItCanBeOpened(t *testing.T) {
	t.Parallel()
	base := map[string]analyze.Exported{
		"example.test/api.Gone":     {Type: "func()", File: "api/api.go", Line: 12},
		"example.test/api.Resigned": {Type: "func(int)", File: "api/api.go", Line: 20},
		"example.test/api.Kept":     {Type: "func()", File: "api/api.go", Line: 30},
	}
	head := map[string]analyze.Exported{
		"example.test/api.Resigned": {Type: "func(string)", File: "api/moved.go", Line: 7},
		"example.test/api.Kept":     {Type: "func()", File: "api/moved.go", Line: 31},
	}

	got := analyze.APIBreakFindings(base, head)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	byIdentity := map[string]analyze.Finding{}
	for _, f := range got {
		if f.RuleID != policy.RuleAPIBreak {
			t.Errorf("finding carries rule %s, want %s", f.RuleID, policy.RuleAPIBreak)
		}
		byIdentity[f.Identity] = f
	}
	assertLocated(t, byIdentity, policy.RuleAPIBreak+" removed example.test/api.Gone",
		"api/api.go", 12)
	assertLocated(t, byIdentity, policy.RuleAPIBreak+" resigned example.test/api.Resigned",
		"api/moved.go", 7)
}

func assertLocated(t *testing.T, byIdentity map[string]analyze.Finding, identity, file string, line int) {
	t.Helper()
	f, ok := byIdentity[identity]
	if !ok {
		t.Fatalf("no finding with identity %q among %d", identity, len(byIdentity))
	}
	if f.File != file || f.Line != line {
		t.Errorf("%q is located at %s:%d, want %s:%d", identity, f.File, f.Line, file, line)
	}
}

func TestAPIBreakFindingsIgnoreAdditions(t *testing.T) {
	t.Parallel()
	base := map[string]analyze.Exported{
		"example.test/api.Kept": {Type: "func()", File: "api/api.go", Line: 3},
	}
	head := map[string]analyze.Exported{
		"example.test/api.Kept":  {Type: "func()", File: "api/api.go", Line: 3},
		"example.test/api.Added": {Type: "func(int)", File: "api/api.go", Line: 9},
	}
	if got := analyze.APIBreakFindings(base, head); len(got) != 0 {
		t.Fatalf("adding a symbol produced %d findings: %+v", len(got), got)
	}
}
