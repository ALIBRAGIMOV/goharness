package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

func runWith(t *testing.T, f *fixture, opts verify.Options) verify.Result {
	t.Helper()
	opts.Dir = f.dir
	result, err := verify.Run(t.Context(), "test", opts)
	if err != nil {
		t.Fatalf("verify.Run(%s): %v", opts.Mode, err)
	}
	return result
}

func deterministic(t *testing.T, result verify.Result) string {
	t.Helper()
	encoded, err := report.DeterministicJSON("test", result)
	if err != nil {
		t.Fatalf("DeterministicJSON: %v", err)
	}
	return string(encoded)
}

// TestBaseEvidenceCacheChangesNothingButTheClock is the safety case for the one
// place a verification command writes outside a temporary directory. Reusing a
// base snapshot is only defensible while it cannot change an answer, so the
// cached run, the warm run and the run that refuses the cache must agree byte
// for byte.
func TestBaseEvidenceCacheChangesNothingButTheClock(t *testing.T) {
	useGolangci(t)
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())
	f := newFixture(t)
	f.write("lib/lib.go", uncheckedErrorLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("baseline that already carries debt")
	f.write("lib/lib.go", debtPlusAdditionLibrary)
	f.commit("unrelated addition")

	cold := runWith(t, f, verify.Options{Mode: verify.ModeVerify})
	if !cold.BaseCompared {
		t.Fatalf("base comparison did not run; change = %+v", cold.Change)
	}
	warm := runWith(t, f, verify.Options{Mode: verify.ModeVerify})
	refused := runWith(t, f, verify.Options{Mode: verify.ModeVerify, NoCache: true})

	if got, want := deterministic(t, warm), deterministic(t, cold); got != want {
		t.Fatalf("a cached base snapshot changed the report:\nwarm:\n%s\ncold:\n%s", got, want)
	}
	if got, want := deterministic(t, refused), deterministic(t, cold); got != want {
		t.Fatalf("--no-cache changed the report:\nrefused:\n%s\ncold:\n%s", got, want)
	}
}

// TestBaseEvidenceCacheIsActuallyRead proves the reuse path is live rather than
// merely present: a sentinel finding placed in the cached snapshot has to reach
// the report as pre-existing debt.
func TestBaseEvidenceCacheIsActuallyRead(t *testing.T) {
	useGolangci(t)
	root := t.TempDir()
	t.Setenv(toolcache.EnvCacheRoot, root)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.write("lib/lib.go", renamedAnswerLibrary)
	f.commit("second commit so a base exists")

	cold := runWith(t, f, verify.Options{Mode: verify.ModeVerify})
	if !cold.BaseCompared {
		t.Fatalf("base comparison did not run; change = %+v", cold.Change)
	}

	const sentinel = "GH-CACHE-SENTINEL"
	poisonCachedSnapshot(t, root, sentinel)

	warm := runWith(t, f, verify.Options{Mode: verify.ModeVerify})
	if !slices.Contains(ruleIDs(warm.Evidence), sentinel) {
		t.Fatalf("the cached base snapshot was not read: %v", ruleIDs(warm.Evidence))
	}
	refused := runWith(t, f, verify.Options{Mode: verify.ModeVerify, NoCache: true})
	if slices.Contains(ruleIDs(refused.Evidence), sentinel) {
		t.Fatal("--no-cache still read the cached base snapshot")
	}
}

// poisonCachedSnapshot rewrites the single cached base snapshot to carry one
// extra finding, which is how a test observes that the cache was consulted.
func poisonCachedSnapshot(t *testing.T, cacheRoot, ruleID string) {
	t.Helper()
	dir := filepath.Join(cacheRoot, "derived", "base-evidence")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("cached snapshots = %d, want exactly 1", len(entries))
	}
	path := filepath.Join(dir, entries[0].Name())
	var document map[string]any
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	document["evidence"] = []map[string]any{{
		"ruleId": ruleID, "tool": "test", "severity": "error",
		"file": "lib/lib.go", "message": "sentinel", "fingerprint": "cafefeed1234",
		"classification": "advisory",
	}}
	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encoding %s: %v", path, err)
	}
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestAnalyzeOptionsAreFullyKeyed fails when the native scanners gain a setting
// the cache key does not describe. A field added there without a matching field
// here would let one run reuse another run's findings, which is the one way a
// cache can change a verdict.
func TestAnalyzeOptionsAreFullyKeyed(t *testing.T) {
	t.Parallel()
	const keyed = 4
	if got := reflect.TypeFor[analyze.Options]().NumField(); got != keyed {
		t.Fatalf("analyze.Options has %d fields, the base-evidence cache key describes %d; "+
			"extend describeAnalyzeOptions and this count together", got, keyed)
	}
}
