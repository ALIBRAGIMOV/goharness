package analyze_test

import (
	"fmt"
	"io/fs"
	"os"
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

	separateScan, err := analyze.Scan(t.Context(), os.DirFS(root), files, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	separateMetrics, err := analyze.ComputeMetrics(t.Context(), os.DirFS(root), files)
	if err != nil {
		t.Fatalf("ComputeMetrics: %v", err)
	}
	separateClones, err := analyze.CloneFindings(t.Context(), os.DirFS(root), files)
	if err != nil {
		t.Fatalf("CloneFindings: %v", err)
	}

	scope, err := analyze.Parse(t.Context(), os.DirFS(root), files)
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
	sharedClones, err := scope.Clones(t.Context(), nil)
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
	scope, err := analyze.Parse(t.Context(), os.DirFS(root), files)
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
		findings, cloneErr := scope.Clones(t.Context(), nil)
		results <- result{clones: findings, err: cloneErr}
	}()
	for range 3 {
		if r := <-results; r.err != nil {
			t.Fatalf("concurrent read: %v", r.err)
		}
	}
}

// The generated benchmark corpus. Its size is fixed because the number it
// produces has to be about the scanners rather than about the repository: the
// base and head runs of a comparison each walk the tree they live in, so a
// corpus taken from the module measures how much source that revision holds.
// This harness reported a ten percent allocation regression against its own
// parent commit, and the whole of it was ten files that did not exist yet.
const (
	corpusPackages        = 30
	corpusFilesPerPackage = 3
)

// corpusFile is one generated source file. Each scanner needs something to
// find, so it carries an exported type with methods, a function whose branches
// give the complexity and nesting measurements something to count, and a
// goroutine with a visible termination path.
const corpusFile = `package pkg@P@

import (
	"context"
	"fmt"
	"strings"
)

// Item@F@ is one record.
type Item@F@ struct {
	Name  string
	Count int
}

// Describe renders the item.
func (i Item@F@) Describe() string {
	if i.Count == 0 {
		return "empty " + i.Name
	}
	return fmt.Sprintf("%s x%d", i.Name, i.Count)
}

// Collect@F@ folds the items into one summary.
func Collect@F@(ctx context.Context, items []Item@F@) (string, error) {
	var out strings.Builder
	seen := 0
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if item.Count < 0 {
			continue
		}
		if item.Count > 10 {
			out.WriteString(strings.ToUpper(item.Name))
			seen++
			continue
		}
		out.WriteString(item.Describe())
		seen++
	}
	if seen == 0 {
		return "", fmt.Errorf("no usable items among %d", len(items))
	}
	return out.String(), nil
}

func feed@F@(ctx context.Context, work chan<- int) {
	go func() {
		defer close(work)
		for n := range 4 {
			select {
			case work <- n:
			case <-ctx.Done():
				return
			}
		}
	}()
}
`

// corpusTestFile keeps test files in the corpus, because several scanners treat
// them differently and a corpus without them would exercise only one branch.
const corpusTestFile = `package pkg@P@

import (
	"context"
	"testing"
)

func TestCollect@F@(t *testing.T) {
	got, err := Collect@F@(context.Background(), []Item@F@{{Name: "a", Count: 1}})
	if err != nil {
		t.Fatalf("Collect@F@: %v", err)
	}
	if got == "" {
		t.Fatal("Collect@F@ summarised one item as nothing")
	}
}
`

// benchCorpus writes the fixed corpus and answers its root and file list.
func benchCorpus(tb testing.TB) (root string, rel []string) {
	tb.Helper()
	root = tb.TempDir()
	write := func(name, src string) {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			tb.Fatalf("creating %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
			tb.Fatalf("writing %s: %v", name, err)
		}
		rel = append(rel, name)
	}
	for pkg := range corpusPackages {
		for i := range corpusFilesPerPackage {
			suffix := pkg*corpusFilesPerPackage + i
			write(fmt.Sprintf("pkg%02d/file%02d.go", pkg, i), expandCorpus(corpusFile, pkg, suffix))
		}
		write(fmt.Sprintf("pkg%02d/pkg_test.go", pkg),
			expandCorpus(corpusTestFile, pkg, pkg*corpusFilesPerPackage))
	}
	return root, rel
}

func expandCorpus(template string, pkg, suffix int) string {
	return strings.NewReplacer(
		"@P@", fmt.Sprintf("%02d", pkg),
		"@F@", fmt.Sprintf("%03d", suffix),
	).Replace(template)
}

// TestBenchmarkCorpusDoesNotDependOnTheRepository holds the property the
// allocation budget rests on: the base and head runs of a comparison must
// benchmark the same input, so the corpus cannot be read from whichever tree
// the run is standing in.
func TestBenchmarkCorpusDoesNotDependOnTheRepository(t *testing.T) {
	t.Parallel()
	root, files := benchCorpus(t)
	if want := corpusPackages * (corpusFilesPerPackage + 1); len(files) != want {
		t.Fatalf("the corpus holds %d files, want the fixed %d", len(files), want)
	}
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("locating the module: %v", err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("locating the corpus: %v", err)
	}
	rel, err := filepath.Rel(module, abs)
	if err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("the corpus lives inside the module at %s, so its size follows the repository", rel)
	}
}

// BenchmarkSeparateParses is the cost the three scanners paid before they
// shared a parse: every judged file read and parsed once per scanner.
func BenchmarkSeparateParses(b *testing.B) {
	root, files := benchCorpus(b)
	opts := analyze.Options{Concurrency: true, Network: true, Persistence: true}
	for b.Loop() {
		if _, err := analyze.Scan(b.Context(), os.DirFS(root), files, opts); err != nil {
			b.Fatal(err)
		}
		if _, err := analyze.ComputeMetrics(b.Context(), os.DirFS(root), files); err != nil {
			b.Fatal(err)
		}
		if _, err := analyze.CloneFindings(b.Context(), os.DirFS(root), files); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSharedParse is the same three answers from one parse.
func BenchmarkSharedParse(b *testing.B) {
	root, files := benchCorpus(b)
	opts := analyze.Options{Concurrency: true, Network: true, Persistence: true}
	for b.Loop() {
		scope, err := analyze.Parse(b.Context(), os.DirFS(root), files)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := scope.Scan(b.Context(), opts); err != nil {
			b.Fatal(err)
		}
		if _, err := scope.Metrics(b.Context()); err != nil {
			b.Fatal(err)
		}
		if _, err := scope.Clones(b.Context(), nil); err != nil {
			b.Fatal(err)
		}
	}
}
