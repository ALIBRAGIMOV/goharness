package toolcache_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// fakeRelease builds a tar.gz shaped like a golangci-lint release, so the
// extraction path is exercised for real rather than stubbed.
func fakeRelease(t *testing.T, version, platform, contents string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	writer := tar.NewWriter(gz)

	dir := fmt.Sprintf("golangci-lint-%s-%s", version, platform)
	for _, entry := range []struct {
		name string
		body string
	}{
		{dir + "/LICENSE", "license text"},
		{dir + "/golangci-lint", contents},
	} {
		header := &tar.Header{
			Name: entry.name, Mode: 0o755,
			Size: int64(len(entry.body)), Typeflag: tar.TypeReg,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("writing tar header: %v", err)
		}
		if _, err := writer.Write([]byte(entry.body)); err != nil {
			t.Fatalf("writing tar body: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
	return buf.Bytes()
}

func newCache(t *testing.T) *toolcache.Cache {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving the cache root: %v", err)
	}
	return toolcache.OpenAt(filepath.Join(root, "cache"))
}

func TestOpenHonoursTheEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(toolcache.EnvCacheRoot, dir)
	cache, err := toolcache.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if cache.Root() != dir {
		t.Fatalf("root = %q, want %q", cache.Root(), dir)
	}
	if entries, readErr := os.ReadDir(dir); readErr != nil || len(entries) != 0 {
		t.Fatalf("Open created something: %v %v", entries, readErr)
	}
}

func TestBlobsAreContentAddressedAndIdempotent(t *testing.T) {
	t.Parallel()
	cache := newCache(t)
	payload := []byte("some binary bytes")

	sum, err := cache.WriteBlob(payload, 0o700)
	if err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}
	if sum != toolcache.Sum(payload) {
		t.Fatalf("blob name = %q, want the payload's own sha256", sum)
	}
	again, err := cache.WriteBlob(payload, 0o700)
	if err != nil || again != sum {
		t.Fatalf("rewriting identical content changed the blob: %q %v", again, err)
	}
	path, present := cache.BlobPath(sum)
	if !present {
		t.Fatal("the blob is not where BlobPath says")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("stored blob = %q (%v)", stored, err)
	}
	if leftovers := incomingFiles(t, filepath.Dir(path)); len(leftovers) != 0 {
		t.Fatalf("temporary blob files were left behind: %v", leftovers)
	}
}

func incomingFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "incoming-") {
			out = append(out, entry.Name())
		}
	}
	return out
}

// countingFetcher records every request so a test can assert both what was
// fetched and, elsewhere, that nothing was.
type countingFetcher struct {
	inner    toolcache.Fetcher
	requests atomic.Int64
}

func (f *countingFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	f.requests.Add(1)
	return f.inner.Fetch(ctx, url)
}

func TestChecksumMismatchAbortsAndLeavesTheCacheUntouched(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("this is not the release you pinned")); err != nil {
			t.Errorf("writing the fake archive: %v", err)
		}
	}))
	defer server.Close()

	cache := newCache(t)
	spec, err := toolcache.GolangciSpec("2.13.2", "linux-amd64", server.URL)
	if err != nil {
		t.Fatalf("GolangciSpec: %v", err)
	}
	_, err = toolcache.ProvisionTool(t.Context(), cache, toolcache.NewHTTPFetcher(server.Client()), spec)
	if !errors.Is(err, toolcache.ErrChecksumMismatch) {
		t.Fatalf("error = %v, want ErrChecksumMismatch", err)
	}
	if !strings.Contains(err.Error(), spec.SHA256) {
		t.Fatalf("the error does not name the pinned sum: %v", err)
	}
	if _, statErr := os.Stat(cache.Root()); statErr == nil {
		entries, readErr := os.ReadDir(cache.Root())
		if readErr != nil {
			t.Fatalf("reading the cache root: %v", readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("a rejected download left %v in the cache", entries)
		}
	}
	if _, err := cache.ReadToolManifest(toolcache.ToolGolangci, "2.13.2"); !errors.Is(err, toolcache.ErrNotProvisioned) {
		t.Fatalf("a manifest was written for a rejected download: %v", err)
	}
}

func TestProvisionIsIdempotent(t *testing.T) {
	t.Parallel()
	const version, platform = "9.9.9", "linux-amd64"
	archive := fakeRelease(t, version, platform, "#!/bin/sh\necho fake\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(archive); err != nil {
			t.Errorf("serving the archive: %v", err)
		}
	}))
	defer server.Close()

	cache := newCache(t)
	fetcher := &countingFetcher{inner: toolcache.NewHTTPFetcher(server.Client())}
	spec := toolcache.ArchiveSpec{
		Tool: toolcache.ToolGolangci, Version: version, Platform: platform,
		URL: server.URL + "/archive.tar.gz", SHA256: toolcache.Sum(archive),
		Kind: toolcache.ArchiveTarGz, BinaryName: "golangci-lint",
	}

	first, err := toolcache.ProvisionTool(t.Context(), cache, fetcher, spec)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if first.AlreadyPresent {
		t.Fatal("the first provision reported the tool as already present")
	}
	if fetcher.requests.Load() != 1 {
		t.Fatalf("requests = %d after the first provision", fetcher.requests.Load())
	}

	second, err := toolcache.ProvisionTool(t.Context(), cache, fetcher, spec)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if !second.AlreadyPresent {
		t.Fatal("the second provision re-installed an existing tool")
	}
	if fetcher.requests.Load() != 1 {
		t.Fatalf("the second provision made %d extra request(s)", fetcher.requests.Load()-1)
	}
	binary, err := cache.VerifiedToolBinary(toolcache.ToolGolangci, version)
	if err != nil {
		t.Fatalf("VerifiedToolBinary: %v", err)
	}
	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("reading the extracted binary: %v", err)
	}
	if string(got) != "#!/bin/sh\necho fake\n" {
		t.Fatalf("extracted binary = %q", got)
	}
}

func TestCorruptCachedBinaryIsRejected(t *testing.T) {
	t.Parallel()
	const version, platform = "9.9.9", "linux-amd64"
	archive := fakeRelease(t, version, platform, "original")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(archive); err != nil {
			t.Errorf("serving the archive: %v", err)
		}
	}))
	defer server.Close()

	cache := newCache(t)
	spec := toolcache.ArchiveSpec{
		Tool: toolcache.ToolGolangci, Version: version, Platform: platform,
		URL: server.URL + "/a.tar.gz", SHA256: toolcache.Sum(archive),
		Kind: toolcache.ArchiveTarGz, BinaryName: "golangci-lint",
	}
	installation, err := toolcache.ProvisionTool(t.Context(), cache, toolcache.NewHTTPFetcher(server.Client()), spec)
	if err != nil {
		t.Fatalf("ProvisionTool: %v", err)
	}

	blob, _ := cache.BlobPath(installation.Manifest.Blob)
	if err := os.WriteFile(blob, []byte("tampered"), 0o700); err != nil {
		t.Fatalf("tampering with the blob: %v", err)
	}
	if _, err := cache.VerifiedToolBinary(toolcache.ToolGolangci, version); !errors.Is(err, toolcache.ErrCorruptEntry) {
		t.Fatalf("error = %v, want ErrCorruptEntry", err)
	}
}

func TestCancelledDownloadWritesNothing(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	cache := newCache(t)
	spec, err := toolcache.GolangciSpec("2.13.2", "linux-amd64", server.URL)
	if err != nil {
		t.Fatalf("GolangciSpec: %v", err)
	}
	if _, err := toolcache.ProvisionTool(ctx, cache, toolcache.NewHTTPFetcher(server.Client()), spec); err == nil {
		t.Fatal("a cancelled download reported success")
	}
	if _, err := cache.ReadToolManifest(toolcache.ToolGolangci, "2.13.2"); !errors.Is(err, toolcache.ErrNotProvisioned) {
		t.Fatalf("a cancelled download left a manifest: %v", err)
	}
}

func TestUnpinnedPlatformIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := toolcache.GolangciSpec("2.13.2", "plan9-386", "https://example.invalid"); err == nil {
		t.Fatal("a platform with no pinned checksum was accepted")
	}
}

func TestPinnedChecksumsCoverEveryDocumentedPlatform(t *testing.T) {
	t.Parallel()
	want := []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64"}
	got := toolcache.SupportedPlatforms()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("platforms = %v, want %v", got, want)
	}
	for _, platform := range got {
		spec, err := toolcache.GolangciSpec("2.13.2", platform, toolcache.DefaultGolangciBaseURL)
		if err != nil {
			t.Fatalf("GolangciSpec(%s): %v", platform, err)
		}
		if len(spec.SHA256) != 64 {
			t.Fatalf("%s checksum is not a sha256: %q", platform, spec.SHA256)
		}
		if !strings.HasPrefix(spec.URL, toolcache.DefaultGolangciBaseURL+"/v2.13.2/") {
			t.Fatalf("%s url = %q", platform, spec.URL)
		}
	}
}
