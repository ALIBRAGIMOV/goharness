package change

import (
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestGraphIsIndependentOfNeedDeps proves that not loading the dependency
// closure leaves the graph identical.
//
// Scoping is decided entirely from this graph, so a load mode that changed one
// edge would change which packages are compiled, linted and tested, and
// therefore the report. The property is asserted on the harness's own module
// rather than on a fixture because the interesting case is a real import graph
// with standard library and third-party edges mixed together.
func TestGraphIsIndependentOfNeedDeps(t *testing.T) {
	t.Parallel()
	moduleRoot := filepath.Join("..", "..")

	lean, err := loadGraphWith(t.Context(), moduleRoot, graphLoadMode)
	if err != nil {
		t.Fatalf("loading without NeedDeps: %v", err)
	}
	full, err := loadGraphWith(t.Context(), moduleRoot, graphLoadMode|packages.NeedDeps)
	if err != nil {
		t.Fatalf("loading with NeedDeps: %v", err)
	}

	leanPkgs, fullPkgs := lean.Packages(), full.Packages()
	if len(leanPkgs) < 10 {
		t.Fatalf("only %d packages loaded; the module did not resolve", len(leanPkgs))
	}
	if !slices.Equal(leanPkgs, fullPkgs) {
		t.Fatalf("package sets differ:\nlean: %v\nfull: %v", leanPkgs, fullPkgs)
	}

	for _, seed := range leanPkgs {
		for _, scope := range []Scope{ScopeChangedOnly, ScopeDirectDependents, ScopeFullClosure} {
			leanAffected := lean.Affected([]string{seed}, scope)
			fullAffected := full.Affected([]string{seed}, scope)
			if !slices.Equal(leanAffected, fullAffected) {
				t.Fatalf("Affected(%s, scope %d) differs:\nlean: %v\nfull: %v",
					seed, scope, leanAffected, fullAffected)
			}
		}
		if !slices.Equal(lean.packages[seed].Imports, full.packages[seed].Imports) {
			t.Fatalf("imports of %s differ:\nlean: %v\nfull: %v",
				seed, lean.packages[seed].Imports, full.packages[seed].Imports)
		}
	}

	leanFiles, err := lean.FilesFor(leanPkgs)
	if err != nil {
		t.Fatalf("FilesFor without NeedDeps: %v", err)
	}
	fullFiles, err := full.FilesFor(fullPkgs)
	if err != nil {
		t.Fatalf("FilesFor with NeedDeps: %v", err)
	}
	if !slices.Equal(leanFiles, fullFiles) {
		t.Fatalf("file sets differ: %d lean files, %d full files", len(leanFiles), len(fullFiles))
	}
}
