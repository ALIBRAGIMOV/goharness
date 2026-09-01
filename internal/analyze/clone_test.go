package analyze_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// cloneShape is long enough to clear CloneMinStatements. The two copies differ
// only in the name and the literals, which is exactly what the shape hash is
// meant to see through.
const cloneShape = `package p

func %s(in []int) int {
	total := 0
	seen := 0
	for _, v := range in {
		if v > %d {
			total += v
			seen++
			continue
		}
		total -= v
	}
	if seen == 0 {
		return %d
	}
	return total / seen
}
`

func cloneScope(t *testing.T) (*analyze.ParsedScope, []string) {
	t.Helper()
	root := t.TempDir()
	files := []string{"pkg/first.go", "pkg/second.go"}
	for i, rel := range files {
		src := fmt.Sprintf(cloneShape, []string{"Alpha", "Beta"}[i], i+1, i+7)
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("creating %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}
	scope, err := analyze.Parse(t.Context(), os.DirFS(root), files)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return scope, files
}

func TestClonesReportTheSecondSiteOfARepeatedShape(t *testing.T) {
	t.Parallel()
	scope, _ := cloneScope(t)
	got, err := scope.Clones(t.Context(), nil)
	if err != nil {
		t.Fatalf("Clones: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d clone findings, want 1: %+v", len(got), got)
	}
	if got[0].RuleID != policy.RuleClone || got[0].File != "pkg/second.go" {
		t.Errorf("clone reported as %s at %s, want %s at pkg/second.go",
			got[0].RuleID, got[0].File, policy.RuleClone)
	}
	if !got[0].Advisory {
		t.Error("a clone is a design question the scanner cannot settle, so it must stay advisory")
	}
}

// TestClonesPassOverGeneratedFiles holds the half of the generated-code rule
// that duplication owns: a generator emitting one shape twice is not a design
// decision anybody will revisit.
func TestClonesPassOverGeneratedFiles(t *testing.T) {
	t.Parallel()
	scope, _ := cloneScope(t)
	got, err := scope.Clones(t.Context(), map[string]bool{"pkg/second.go": true})
	if err != nil {
		t.Fatalf("Clones: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a generated file produced %d clone findings: %+v", len(got), got)
	}
}

func TestClonesStopWhenTheContextIsCancelled(t *testing.T) {
	t.Parallel()
	scope, _ := cloneScope(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := scope.Clones(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Clones on a cancelled context answered %d findings and error %v", len(got), err)
	}
	if got != nil {
		t.Errorf("a cancelled scan answered %d findings; it establishes nothing", len(got))
	}
}
