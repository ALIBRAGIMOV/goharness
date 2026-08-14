package toolcache_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// FakeVulnDB is a minimal database in the v1 layout the scanner reads.
type FakeVulnDB struct {
	Modified time.Time
	Entries  map[string]string
}

// NewFakeVulnDB builds a database with one entry describing a vulnerable
// version of a module, which is enough for an end-to-end scan.
func NewFakeVulnDB(id, modulePath, fixedVersion, symbol, pkg string) FakeVulnDB {
	modified := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	entry := `{
  "id": "` + id + `",
  "modified": "` + modified.Format(time.RFC3339) + `",
  "published": "2026-01-15T00:00:00Z",
  "summary": "fixture vulnerability in ` + modulePath + `",
  "details": "A deliberately vulnerable fixture module.",
  "affected": [
    {
      "package": {"name": "` + modulePath + `", "ecosystem": "Go"},
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "` + fixedVersion + `"}]}
      ],
      "ecosystem_specific": {
        "imports": [{"path": "` + pkg + `", "symbols": ["` + symbol + `"]}]
      }
    }
  ],
  "database_specific": {"url": "https://pkg.go.dev/vuln/` + id + `"}
}`
	return FakeVulnDB{Modified: modified, Entries: map[string]string{id: entry}}
}

// Handler serves the database in the gzipped form the origin uses.
func (db FakeVulnDB) Handler(t *testing.T, modulePath string) http.Handler {
	t.Helper()
	files := map[string]string{
		"/index/db.json.gz":      `{"modified":"` + db.Modified.Format(time.RFC3339) + `"}`,
		"/index/modules.json.gz": db.modulesIndex(modulePath),
		"/index/vulns.json.gz":   db.vulnsIndex(),
	}
	for id, entry := range db.Entries {
		files["/ID/"+id+".json.gz"] = entry
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write([]byte(body)); err != nil {
			t.Errorf("compressing %s: %v", r.URL.Path, err)
			return
		}
		if err := gz.Close(); err != nil {
			t.Errorf("closing gzip for %s: %v", r.URL.Path, err)
			return
		}
		if _, err := w.Write(buf.Bytes()); err != nil {
			t.Errorf("serving %s: %v", r.URL.Path, err)
		}
	})
}

func (db FakeVulnDB) modulesIndex(modulePath string) string {
	var vulns []string
	for id := range db.Entries {
		vulns = append(vulns, `{"id":"`+id+`","modified":"`+db.Modified.Format(time.RFC3339)+`"}`)
	}
	return `[{"path":"` + modulePath + `","vulns":[` + strings.Join(vulns, ",") + `]}]`
}

func (db FakeVulnDB) vulnsIndex() string {
	var refs []string
	for id := range db.Entries {
		refs = append(refs, `{"id":"`+id+`","modified":"`+db.Modified.Format(time.RFC3339)+`","aliases":[]}`)
	}
	return `[` + strings.Join(refs, ",") + `]`
}

func TestSnapshotMirrorsTheV1Layout(t *testing.T) {
	t.Parallel()
	db := NewFakeVulnDB("GO-2026-0001", "example.com/vuln", "1.1.0", "Boom", "example.com/vuln")
	server := httptest.NewServer(db.Handler(t, "example.com/vuln"))
	defer server.Close()

	cache := newCache(t)
	result, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(server.Client()), server.URL)
	if err != nil {
		t.Fatalf("SnapshotVulnDB: %v", err)
	}
	if result.Manifest.EntryCount != 1 {
		t.Fatalf("entry count = %d, want 1", result.Manifest.EntryCount)
	}
	if !result.Manifest.Modified.Equal(db.Modified) {
		t.Fatalf("modified = %s, want %s", result.Manifest.Modified, db.Modified)
	}
	if result.Replaced {
		t.Fatal("the first snapshot reported replacing a previous one")
	}

	// The scanner's file:// client reads plain .json, so the mirror must have
	// decompressed everything it fetched.
	for _, rel := range []string{
		"index/db.json", "index/modules.json", "index/vulns.json",
		"ID/GO-2026-0001.json", "manifest.json",
	} {
		if _, err := os.Stat(filepath.Join(cache.VulnDBDir(), rel)); err != nil {
			t.Fatalf("snapshot is missing %s: %v", rel, err)
		}
	}
	var entry map[string]any
	raw, err := os.ReadFile(filepath.Join(cache.VulnDBDir(), "ID", "GO-2026-0001.json"))
	if err != nil {
		t.Fatalf("reading the mirrored entry: %v", err)
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("the mirrored entry is not plain JSON: %v", err)
	}
	if _, err := cache.VerifyVulnDB(); err != nil {
		t.Fatalf("VerifyVulnDB on a fresh snapshot: %v", err)
	}
}

func TestSnapshotChecksumDetectsTampering(t *testing.T) {
	t.Parallel()
	db := NewFakeVulnDB("GO-2026-0001", "example.com/vuln", "1.1.0", "Boom", "example.com/vuln")
	server := httptest.NewServer(db.Handler(t, "example.com/vuln"))
	defer server.Close()

	cache := newCache(t)
	if _, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(server.Client()), server.URL); err != nil {
		t.Fatalf("SnapshotVulnDB: %v", err)
	}
	target := filepath.Join(cache.VulnDBDir(), "ID", "GO-2026-0001.json")
	if err := os.WriteFile(target, []byte(`{"id":"tampered"}`), 0o600); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	if _, err := cache.VerifyVulnDB(); !errors.Is(err, toolcache.ErrCorruptEntry) {
		t.Fatalf("error = %v, want ErrCorruptEntry", err)
	}
}

// TestFailedUpdateLeavesThePreviousSnapshotInService is the atomicity
// guarantee: a machine that cannot reach the mirror keeps the database it
// already had rather than losing the ability to scan.
func TestFailedUpdateLeavesThePreviousSnapshotInService(t *testing.T) {
	t.Parallel()
	db := NewFakeVulnDB("GO-2026-0001", "example.com/vuln", "1.1.0", "Boom", "example.com/vuln")
	good := httptest.NewServer(db.Handler(t, "example.com/vuln"))
	defer good.Close()

	cache := newCache(t)
	first, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(good.Client()), good.URL)
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ID/") {
			http.Error(w, "mirror is down", http.StatusInternalServerError)
			return
		}
		db.Handler(t, "example.com/vuln").ServeHTTP(w, r)
	}))
	defer broken.Close()

	if _, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(broken.Client()), broken.URL); err == nil {
		t.Fatal("a failed mirror reported success")
	}
	if !cache.HasVulnDB() {
		t.Fatal("a failed update removed the snapshot that was in service")
	}
	surviving, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the surviving snapshot does not verify: %v", err)
	}
	if surviving.TreeChecksum != first.Manifest.TreeChecksum {
		t.Fatalf("the surviving snapshot is not the original: %s vs %s",
			surviving.TreeChecksum, first.Manifest.TreeChecksum)
	}
	if leftovers := stagingDirs(t, cache); len(leftovers) != 0 {
		t.Fatalf("a failed update left staging directories behind: %v", leftovers)
	}
}

func TestSuccessfulUpdateReplacesAtomically(t *testing.T) {
	t.Parallel()
	first := NewFakeVulnDB("GO-2026-0001", "example.com/vuln", "1.1.0", "Boom", "example.com/vuln")
	firstServer := httptest.NewServer(first.Handler(t, "example.com/vuln"))
	defer firstServer.Close()

	cache := newCache(t)
	if _, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(firstServer.Client()), firstServer.URL); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}

	second := NewFakeVulnDB("GO-2026-0002", "example.com/other", "2.0.0", "Bang", "example.com/other")
	secondServer := httptest.NewServer(second.Handler(t, "example.com/other"))
	defer secondServer.Close()

	result, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(secondServer.Client()), secondServer.URL)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if !result.Replaced {
		t.Fatal("the second snapshot did not report replacing the first")
	}
	if _, err := os.Stat(filepath.Join(cache.VulnDBDir(), "ID", "GO-2026-0001.json")); err == nil {
		t.Fatal("the replaced snapshot still contains the old entry")
	}
	if _, err := cache.VerifyVulnDB(); err != nil {
		t.Fatalf("the replacement does not verify: %v", err)
	}
	if leftovers := stagingDirs(t, cache); len(leftovers) != 0 {
		t.Fatalf("the swap left directories behind: %v", leftovers)
	}
}

func TestRecoverRestoresAnInterruptedSwap(t *testing.T) {
	t.Parallel()
	db := NewFakeVulnDB("GO-2026-0001", "example.com/vuln", "1.1.0", "Boom", "example.com/vuln")
	server := httptest.NewServer(db.Handler(t, "example.com/vuln"))
	defer server.Close()

	cache := newCache(t)
	original, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(server.Client()), server.URL)
	if err != nil {
		t.Fatalf("SnapshotVulnDB: %v", err)
	}

	// Reproduce a crash in the middle of the swap: the live snapshot has been
	// moved aside and the replacement never arrived.
	retiring := filepath.Join(filepath.Dir(cache.VulnDBDir()), "retiring-1")
	if err := os.Rename(cache.VulnDBDir(), retiring); err != nil {
		t.Fatalf("simulating an interrupted swap: %v", err)
	}
	if cache.HasVulnDB() {
		t.Fatal("the interrupted state still reports a snapshot in service")
	}

	recovered, err := cache.RecoverVulnDB()
	if err != nil {
		t.Fatalf("RecoverVulnDB: %v", err)
	}
	if !recovered {
		t.Fatal("recovery did not restore the snapshot")
	}
	restored, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the restored snapshot does not verify: %v", err)
	}
	if restored.TreeChecksum != original.Manifest.TreeChecksum {
		t.Fatal("recovery restored a different snapshot")
	}
}

func TestFreshness(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	fresh := toolcache.VulnDBManifest{Modified: now.Add(-2 * 24 * time.Hour)}
	stale := toolcache.VulnDBManifest{Modified: now.Add(-9 * 24 * time.Hour)}
	if fresh.Stale(now) {
		t.Fatal("a two day old snapshot was reported stale")
	}
	if !stale.Stale(now) {
		t.Fatal("a nine day old snapshot was not reported stale")
	}
	if days := int(stale.Age(now).Hours() / 24); days != 9 {
		t.Fatalf("age = %d days, want 9", days)
	}
}

func stagingDirs(t *testing.T, cache *toolcache.Cache) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(cache.VulnDBDir()))
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "staging-") || strings.HasPrefix(name, "retiring-") {
			out = append(out, name)
		}
	}
	return out
}
