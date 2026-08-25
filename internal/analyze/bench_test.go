package analyze_test

import (
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
)

// harnessFiles is every Go file of this module, which is the realistic scope
// for the three scanners that share a parse: a few hundred files across a dozen
// package directories, with test files mixed in.
func harnessFiles(tb testing.TB) (root string, rel []string) {
	tb.Helper()
	root = filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "testdata" || name == ".git" || name == ".tools" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		r, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = append(rel, filepath.ToSlash(r))
		return nil
	})
	if err != nil {
		tb.Fatalf("walking %s: %v", root, err)
	}
	if len(rel) < 50 {
		tb.Fatalf("only %d Go files found; the walk did not reach the module", len(rel))
	}
	return root, rel
}

// TestSharedParseAnswersExactlyAsSeparateParsesDo is the correctness half of
// the single-parse change. Speed is only allowed to move the clock, so the
// three scanners have to produce identical results whether they parsed the
// scope once between them or three times over.
func TestSharedParseAnswersExactlyAsSeparateParsesDo(t *testing.T) {
	t.Parallel()
	root, files := harnessFiles(t)
	opts := analyze.Options{Concurrency: true, Network: true, Persistence: true}

	separateScan, err := analyze.Scan(t.Context(), root, files, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	separateMetrics, err := analyze.ComputeMetrics(t.Context(), root, files)
	if err != nil {
		t.Fatalf("ComputeMetrics: %v", err)
	}
	separateClones, err := analyze.CloneFindings(t.Context(), root, files)
	if err != nil {
		t.Fatalf("CloneFindings: %v", err)
	}

	scope, err := analyze.Parse(t.Context(), root, files)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sharedScan, err := scope.Scan(t.Context(), opts)
	if err != nil {
		t.Fatalf("scope.Scan: %v", err)
	}
	sharedMetrics, err := scope.Metrics(t.Context())
	if err != nil {
		t.Fatalf("scope.Metrics: %v", err)
	}
	sharedClones, err := scope.Clones(t.Context())
	if err != nil {
		t.Fatalf("scope.Clones: %v", err)
	}

	if !reflect.DeepEqual(separateScan, sharedScan) {
		t.Fatalf("scan differs: %d separate findings, %d shared", len(separateScan), len(sharedScan))
	}
	if !reflect.DeepEqual(separateMetrics, sharedMetrics) {
		t.Fatal("metrics differ between a shared parse and separate parses")
	}
	if !reflect.DeepEqual(separateClones, sharedClones) {
		t.Fatalf("clones differ: %d separate findings, %d shared", len(separateClones), len(sharedClones))
	}
}

// TestSharedParseSurvivesConcurrentReaders holds the property the coordinator
// relies on: the three checks run as concurrent goroutines over one scope, so
// reading it from several at once must be safe. Run under -race this is the
// only thing standing between the shared parse and a data race.
func TestSharedParseSurvivesConcurrentReaders(t *testing.T) {
	t.Parallel()
	root, files := harnessFiles(t)
	scope, err := analyze.Parse(t.Context(), root, files)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	type result struct {
		scan, clones []analyze.Finding
		metrics      analyze.Metrics
		err          error
	}
	results := make(chan result, 3)
	go func() {
		findings, scanErr := scope.Scan(t.Context(), analyze.Options{Concurrency: true})
		results <- result{scan: findings, err: scanErr}
	}()
	go func() {
		metrics, metricsErr := scope.Metrics(t.Context())
		results <- result{metrics: metrics, err: metricsErr}
	}()
	go func() {
		findings, cloneErr := scope.Clones(t.Context())
		results <- result{clones: findings, err: cloneErr}
	}()
	for range 3 {
		if r := <-results; r.err != nil {
			t.Fatalf("concurrent read: %v", r.err)
		}
	}
}

// BenchmarkSeparateParses is the cost the three scanners paid before they
// shared a parse: every judged file read and parsed once per scanner.
func BenchmarkSeparateParses(b *testing.B) {
	root, files := harnessFiles(b)
	opts := analyze.Options{Concurrency: true, Network: true, Persistence: true}
	for b.Loop() {
		if _, err := analyze.Scan(b.Context(), root, files, opts); err != nil {
			b.Fatal(err)
		}
		if _, err := analyze.ComputeMetrics(b.Context(), root, files); err != nil {
			b.Fatal(err)
		}
		if _, err := analyze.CloneFindings(b.Context(), root, files); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSharedParse is the same three answers from one parse.
func BenchmarkSharedParse(b *testing.B) {
	root, files := harnessFiles(b)
	opts := analyze.Options{Concurrency: true, Network: true, Persistence: true}
	for b.Loop() {
		scope, err := analyze.Parse(b.Context(), root, files)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := scope.Scan(b.Context(), opts); err != nil {
			b.Fatal(err)
		}
		if _, err := scope.Metrics(b.Context()); err != nil {
			b.Fatal(err)
		}
		if _, err := scope.Clones(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}
