package admission

import (
	"os"
	"path/filepath"
	"testing"
)

// The domains a change activates by the paths it touches, not by the Go it
// contains. A migration rewrite and a go.mod edit are the two changes that can
// break production without a single Go line changing, and both were invisible
// while detection was handed only the Go files.
func TestDetectRisksActivatesDomainsFromNonGoPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/m\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := DetectRisks(t.Context(), DetectionInput{
		Root:         root,
		ChangedFiles: []string{"go.mod", "migrations/002_add_index.sql", "docs/README.md"},
	})
	if err != nil {
		t.Fatalf("DetectRisks: %v", err)
	}
	for _, want := range []RiskDomain{RiskDependency, RiskPersistence} {
		if !profile.Has(want) {
			t.Fatalf("%s is not active: %+v", want, profile)
		}
	}
	for _, domain := range []RiskDomain{RiskConcurrency, RiskNetwork, RiskPublicAPI, RiskTests} {
		if profile.Has(domain) {
			t.Fatalf("%s was activated by files that carry no such risk: %+v", domain, profile)
		}
	}
}

func TestIsDependencyFile(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"go.mod":                   true,
		"go.sum":                   true,
		"go.work":                  true,
		"go.work.sum":              true,
		"vendor/modules.txt":       true,
		"backend/go.mod":           true,
		"tools/vendor/modules.txt": true,
		"go.mod.bak":               false,
		"modules.txt":              false,
		"internal/gomod/parser.go": false,
		"docs/go.mod.md":           false,
		"vendor/golang.org/x/a.go": false,
		"vendor/modules.txt.orig":  false,
		"testdata/go.mod.golden":   false,
	}
	for rel, want := range cases {
		if got := isDependencyFile(rel); got != want {
			t.Errorf("isDependencyFile(%q) = %v, want %v", rel, got, want)
		}
	}
}
