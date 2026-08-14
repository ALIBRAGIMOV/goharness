package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/cli"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache/toolcachetest"
)

// useCache points the commands at a private cache root and returns it.
func useCache(t *testing.T) *toolcache.Cache {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving the cache root: %v", err)
	}
	root = filepath.Join(root, "cache")
	t.Setenv(toolcache.EnvCacheRoot, root)
	return toolcache.OpenAt(root)
}

// seedGolangci writes a manifest and blob that satisfy the pinned archive sum,
// so provisioning reports the linter as already present without needing the
// real sixty megabyte release in a unit test.
func seedGolangci(t *testing.T, cache *toolcache.Cache) toolcache.ToolManifest {
	t.Helper()
	spec, err := toolcache.GolangciSpec(tool.GolangciLintPin,
		toolcache.CurrentPlatform(), toolcache.DefaultGolangciBaseURL)
	if err != nil {
		t.Fatalf("GolangciSpec: %v", err)
	}
	binary := []byte("#!/bin/sh\necho seeded golangci-lint\n")
	blob, err := cache.WriteBlob(binary, 0o700)
	if err != nil {
		t.Fatalf("seeding the blob: %v", err)
	}
	manifest := toolcache.ToolManifest{
		Tool: spec.Tool, Version: spec.Version, Platform: spec.Platform,
		ArchiveSHA256: spec.SHA256, BinarySHA256: blob, Blob: blob,
		InstalledAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := cache.WriteToolManifest(manifest); err != nil {
		t.Fatalf("seeding the manifest: %v", err)
	}
	return manifest
}

func serveVulnDB(t *testing.T, db toolcachetest.VulnDB) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(db.Handler(t))
	t.Cleanup(server.Close)
	t.Setenv(toolcache.EnvVulnDBBaseURL, server.URL)
	return server
}

func TestSetupProvisionsTheSnapshotAndIsIdempotent(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	serveVulnDB(t, toolcachetest.VulnerableSyncDB())

	code, out, errOut := invoke(t, "setup")
	if code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"cache: " + cache.Root(),
		"already provisioned",
		"vuln database: mirroring",
		"tree sha256",
		"setup complete",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup output is missing %q:\n%s", want, out)
		}
	}
	first, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the provisioned snapshot does not verify: %v", err)
	}

	code, second, errOut := invoke(t, "setup")
	if code != cli.ExitAdmitted {
		t.Fatalf("second setup exit = %d\n%s%s", code, second, errOut)
	}
	if !strings.Contains(second, "already present") || !strings.Contains(second, "nothing to download") {
		t.Fatalf("the second setup did not report the snapshot as present:\n%s", second)
	}
	after, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the snapshot no longer verifies after a second setup: %v", err)
	}
	if after.FetchedAt != first.FetchedAt || after.TreeChecksum != first.TreeChecksum {
		t.Fatal("the second setup rewrote the snapshot instead of leaving it alone")
	}
}

func TestSetupAbortsOnAChecksumMismatchAndLeavesTheCacheUntouched(t *testing.T) {
	cache := useCache(t)
	corrupt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("not the release you pinned")); err != nil {
			t.Errorf("writing the corrupt archive: %v", err)
		}
	}))
	defer corrupt.Close()
	t.Setenv(toolcache.EnvGolangciBaseURL, corrupt.URL)
	serveVulnDB(t, toolcachetest.VulnerableSyncDB())

	code, out, errOut := invoke(t, "setup")
	if code != cli.ExitInconclusive {
		t.Fatalf("setup exit = %d, want %d\n%s%s", code, cli.ExitInconclusive, out, errOut)
	}
	if !strings.Contains(errOut, "does not match its pinned sha256") {
		t.Fatalf("the failure does not name the checksum mismatch:\n%s", errOut)
	}
	if !strings.Contains(errOut, "cache was left untouched") {
		t.Fatalf("the failure does not state that the cache is untouched:\n%s", errOut)
	}
	if cache.HasVulnDB() {
		t.Fatal("setup mirrored a database after aborting on the linter")
	}
	if _, err := cache.ReadToolManifest(toolcache.ToolGolangci, tool.GolangciLintPin); err == nil {
		t.Fatal("a manifest was written for a rejected download")
	}
}

func TestToolsUpdateKeepsThePreviousSnapshotWhenTheMirrorFails(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	db := toolcachetest.VulnerableSyncDB()
	good := serveVulnDB(t, db)

	if code, out, errOut := invoke(t, "setup"); code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\n%s%s", code, out, errOut)
	}
	original, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the initial snapshot does not verify: %v", err)
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ID/") {
			http.Error(w, "mirror is down", http.StatusBadGateway)
			return
		}
		db.Handler(t).ServeHTTP(w, r)
	}))
	defer broken.Close()
	t.Setenv(toolcache.EnvVulnDBBaseURL, broken.URL)

	code, out, errOut := invoke(t, "tools", "update")
	if code != cli.ExitInconclusive {
		t.Fatalf("tools update exit = %d, want %d\n%s%s", code, cli.ExitInconclusive, out, errOut)
	}
	if !strings.Contains(errOut, "previous snapshot is still in service") {
		t.Fatalf("the failure does not say the previous snapshot survived:\n%s", errOut)
	}
	surviving, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the surviving snapshot does not verify: %v", err)
	}
	if surviving.TreeChecksum != original.TreeChecksum {
		t.Fatal("a failed update replaced the snapshot that was in service")
	}
	_ = good
}

func TestToolsUpdateReplacesTheSnapshot(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	old := toolcachetest.VulnerableSyncDB().WithModified(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	serveVulnDB(t, old)
	if code, out, errOut := invoke(t, "setup"); code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\n%s%s", code, out, errOut)
	}
	before, err := cache.ReadVulnDBManifest()
	if err != nil {
		t.Fatalf("reading the first manifest: %v", err)
	}

	fresh := toolcachetest.VulnerableSyncDB().WithModified(time.Now().UTC().Truncate(time.Second))
	serveVulnDB(t, fresh)
	code, out, errOut := invoke(t, "tools", "update")
	if code != cli.ExitAdmitted {
		t.Fatalf("tools update exit = %d\n%s%s", code, out, errOut)
	}
	if !strings.Contains(out, "replaced the previous snapshot") {
		t.Fatalf("the update did not report a replacement:\n%s", out)
	}
	after, err := cache.VerifyVulnDB()
	if err != nil {
		t.Fatalf("the replacement does not verify: %v", err)
	}
	if !after.Modified.After(before.Modified) {
		t.Fatalf("modified went from %s to %s", before.Modified, after.Modified)
	}
}

func TestUnknownToolsSubcommandSuggests(t *testing.T) {
	code, _, errOut := invoke(t, "tools", "updaet")
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errOut, "did you mean: update") {
		t.Fatalf("no suggestion offered:\n%s", errOut)
	}
}

func TestDoctorReportsSnapshotFreshness(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	stale := toolcachetest.VulnerableSyncDB().
		WithModified(time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Second))
	serveVulnDB(t, stale)
	if code, out, errOut := invoke(t, "setup"); code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\n%s%s", code, out, errOut)
	}

	root, ok := repoRoot()
	if !ok {
		t.Skip("could not locate the goharness module root")
	}
	_, out, _ := invoke(t, "doctor", "--dir", root)
	if !strings.Contains(out, "[warn] vuln database") {
		t.Fatalf("doctor did not warn about a stale snapshot:\n%s", out)
	}
	if !strings.Contains(out, "over the 7 day budget") {
		t.Fatalf("doctor did not name the freshness budget:\n%s", out)
	}
	if !strings.Contains(out, "fix: goharness tools update") {
		t.Fatalf("doctor did not offer the update command:\n%s", out)
	}
	if !strings.Contains(out, "embedded golang.org/x/vuln") {
		t.Fatalf("doctor does not report the embedded scanner:\n%s", out)
	}
	if strings.Contains(out, "govulncheck") {
		t.Fatalf("doctor still probes for a govulncheck executable:\n%s", out)
	}
}

func TestDoctorReportsAFreshSnapshotAndTheCache(t *testing.T) {
	cache := useCache(t)
	manifest := seedGolangci(t, cache)
	serveVulnDB(t, toolcachetest.VulnerableSyncDB().WithModified(time.Now().UTC().Truncate(time.Second)))
	if code, out, errOut := invoke(t, "setup"); code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\n%s%s", code, out, errOut)
	}

	root, ok := repoRoot()
	if !ok {
		t.Skip("could not locate the goharness module root")
	}
	code, out, _ := invoke(t, "doctor", "--dir", root)
	if code != cli.ExitAdmitted {
		t.Fatalf("doctor exit = %d\n%s", code, out)
	}
	for _, want := range []string{
		"cache          " + cache.Root(),
		"cached linter  golangci-lint " + tool.GolangciLintPin,
		manifest.BinarySHA256[:12],
		"vuln database  1 entries",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output is missing %q:\n%s", want, out)
		}
	}
}

func TestDoctorReportsACorruptCachedLinter(t *testing.T) {
	cache := useCache(t)
	manifest := seedGolangci(t, cache)
	blob, _ := cache.BlobPath(manifest.Blob)
	if err := os.WriteFile(blob, []byte("tampered"), 0o700); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	root, ok := repoRoot()
	if !ok {
		t.Skip("could not locate the goharness module root")
	}
	code, out, _ := invoke(t, "doctor", "--dir", root)
	if code != cli.ExitInconclusive {
		t.Fatalf("doctor exit = %d, want %d\n%s", code, cli.ExitInconclusive, out)
	}
	if !strings.Contains(out, "does not match its manifest checksum") {
		t.Fatalf("doctor did not report the corrupt entry:\n%s", out)
	}
}

// TestDoctorNeverWritesTheCache is the read-only guarantee for the one command
// that inspects provisioned state.
func TestDoctorNeverWritesTheCache(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	serveVulnDB(t, toolcachetest.VulnerableSyncDB())
	if code, out, errOut := invoke(t, "setup"); code != cli.ExitAdmitted {
		t.Fatalf("setup exit = %d\n%s%s", code, out, errOut)
	}
	before := cacheTree(t, cache.Root())

	root, ok := repoRoot()
	if !ok {
		t.Skip("could not locate the goharness module root")
	}
	invoke(t, "doctor", "--dir", root)
	if after := cacheTree(t, cache.Root()); after != before {
		t.Fatalf("doctor changed the cache:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func cacheTree(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		if entry.IsDir() {
			lines = append(lines, rel+"/")
			return nil
		}
		sum, sumErr := toolcache.SumFile(p)
		if sumErr != nil {
			return sumErr
		}
		lines = append(lines, rel+":"+sum)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the cache: %v", err)
	}
	return strings.Join(lines, "\n")
}

func TestSetupJSONFreeOutputIsHumanReadable(t *testing.T) {
	cache := useCache(t)
	seedGolangci(t, cache)
	serveVulnDB(t, toolcachetest.VulnerableSyncDB())
	_, out, _ := invoke(t, "setup")
	var document map[string]any
	if err := json.Unmarshal([]byte(out), &document); err == nil {
		t.Fatal("setup emitted JSON on stdout; it is a human command")
	}
}
