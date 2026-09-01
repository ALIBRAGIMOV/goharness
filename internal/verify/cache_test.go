package verify_test

import (
	"encoding/json/v2"
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
	opts.Dir = f.verifyDir()
	result, err := verify.Run(t.Context(), "test", opts)
	if err != nil {
		t.Fatalf("verify.Run(%s): %v", opts.Mode, err)
	}
	keepReport(t, result)
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

// misformattedLibrary is a second package whose import block goimports would
// rewrite, so a case can watch one package's answer change while another's
// stays put.
const misformattedLibrary = `package other

import (
	"os"
	"fmt"
)

// Report writes one line and reports whether it could.
func Report(message string) error {
	if _, err := fmt.Fprintln(os.Stdout, message); err != nil {
		return err
	}
	return nil
}
`

// headFormatCacheDirs are the per-package caches the formatting checks own.
func headFormatCacheDirs(cacheRoot string) []string {
	return []string{
		filepath.Join(cacheRoot, "derived", "head-gofmt"),
		filepath.Join(cacheRoot, "derived", "head-goimports"),
	}
}

func cacheEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// TestHeadFormatCacheChangesNothingButTheClock is the safety case for the
// per-package head cache, and it is the one that matters: reusing an answer is
// only defensible while it cannot change one. The cold run, the warm run and
// the run that refuses the cache have to agree byte for byte.
func TestHeadFormatCacheChangesNothingButTheClock(t *testing.T) {
	useGolangci(t)
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("other/other.go", misformattedLibrary)
	f.commit("a package that formats and one that does not")

	cold := runWith(t, f, verify.Options{Mode: verify.ModeAudit})
	warm := runWith(t, f, verify.Options{Mode: verify.ModeAudit})
	refused := runWith(t, f, verify.Options{Mode: verify.ModeAudit, NoCache: true})

	if !slices.Contains(ruleIDs(cold.Evidence), "GH-FMT-002") {
		t.Fatalf("the misformatted package produced no goimports finding: %v", ruleIDs(cold.Evidence))
	}
	if got, want := deterministic(t, warm), deterministic(t, cold); got != want {
		t.Fatalf("a cached formatting answer changed the report:\nwarm:\n%s\ncold:\n%s", got, want)
	}
	if got, want := deterministic(t, refused), deterministic(t, cold); got != want {
		t.Fatalf("--no-cache changed the report:\nrefused:\n%s\ncold:\n%s", got, want)
	}
}

// TestHeadFormatCacheInvalidatesOnlyTheEditedPackage is the property the repair
// loop is bought with. Editing one file must leave every other package's stored
// answer usable, or the cache is a full recomputation with extra steps.
func TestHeadFormatCacheInvalidatesOnlyTheEditedPackage(t *testing.T) {
	useGolangci(t)
	cacheRoot := t.TempDir()
	t.Setenv(toolcache.EnvCacheRoot, cacheRoot)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.write("other/other.go", misformattedLibrary)
	f.commit("two packages")

	runWith(t, f, verify.Options{Mode: verify.ModeAudit})
	for _, dir := range headFormatCacheDirs(cacheRoot) {
		if got := len(cacheEntries(t, dir)); got != 2 {
			t.Fatalf("%s holds %d entries after the first run, want one per package", dir, got)
		}
	}

	before := map[string][]string{}
	for _, dir := range headFormatCacheDirs(cacheRoot) {
		before[dir] = cacheEntries(t, dir)
	}
	f.write("lib/lib.go", renamedAnswerLibrary)
	runWith(t, f, verify.Options{Mode: verify.ModeAudit})

	for _, dir := range headFormatCacheDirs(cacheRoot) {
		after := cacheEntries(t, dir)
		if len(after) != 3 {
			t.Fatalf("%s holds %d entries after one package changed, want 3", dir, len(after))
		}
		kept := 0
		for _, name := range before[dir] {
			if slices.Contains(after, name) {
				kept++
			}
		}
		if kept != len(before[dir]) {
			t.Fatalf("%s dropped %d of %d stored answers when one package changed",
				dir, len(before[dir])-kept, len(before[dir]))
		}
	}
}

// TestPoisonedHeadEntryIsRecomputed closes the gap a content-addressed key
// cannot close on its own. The key describes the inputs, so it says nothing
// about whether the stored value still corresponds to them; the entry carries a
// hash of its own payload for exactly that, and an edited value has to be
// treated as absent rather than believed.
func TestPoisonedHeadEntryIsRecomputed(t *testing.T) {
	useGolangci(t)
	cacheRoot := t.TempDir()
	t.Setenv(toolcache.EnvCacheRoot, cacheRoot)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("a package that formats cleanly")

	cold := runWith(t, f, verify.Options{Mode: verify.ModeAudit})
	if slices.Contains(ruleIDs(cold.Evidence), "GH-FMT-002") {
		t.Fatalf("the fixture is not goimports-clean: %v", ruleIDs(cold.Evidence))
	}

	dir := filepath.Join(cacheRoot, "derived", "head-goimports")
	entries := cacheEntries(t, dir)
	if len(entries) != 1 {
		t.Fatalf("cached goimports answers = %d, want exactly 1", len(entries))
	}
	poisonHeadEntry(t, filepath.Join(dir, entries[0]))

	warm := runWith(t, f, verify.Options{Mode: verify.ModeAudit})
	if slices.Contains(ruleIDs(warm.Evidence), "GH-FMT-002") {
		t.Fatal("a hand-edited cache entry was believed and reported as a finding")
	}
	if got, want := deterministic(t, warm), deterministic(t, cold); got != want {
		t.Fatalf("a poisoned entry changed the report:\nwarm:\n%s\ncold:\n%s", got, want)
	}
}

// poisonHeadEntry rewrites a stored answer without touching its integrity hash,
// which is what an operator editing a cache file by hand produces.
func poisonHeadEntry(t *testing.T, path string) {
	t.Helper()
	var document map[string]any
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	if _, ok := document["integrity"]; !ok {
		t.Fatalf("%s carries no integrity hash, so nothing guards its payload", path)
	}
	document["payload"] = []map[string]any{{"file": "lib/lib.go"}}
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
