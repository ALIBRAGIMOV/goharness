package toolcache_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// EnvRunNetworkTests gates the tests that reach the real internet. They are
// skipped by default so the suite stays hermetic and works offline; set the
// variable to exercise the real origins before a release.
const EnvRunNetworkTests = "GOHARNESS_NETWORK_TESTS"

func requireNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvRunNetworkTests) == "" {
		t.Skipf("set %s=1 to run the tests that reach the real download origins", EnvRunNetworkTests)
	}
}

// TestRealGolangciDownloadMatchesThePin verifies the pinned checksum against
// the actual release. It is the only way to know the transcribed sums are
// right, and it is gated because it downloads tens of megabytes.
func TestRealGolangciDownloadMatchesThePin(t *testing.T) {
	requireNetwork(t)
	cache := toolcache.OpenAt(filepath.Join(t.TempDir(), "cache"))
	spec, err := toolcache.GolangciSpec(tool.GolangciLintPin,
		toolcache.CurrentPlatform(), toolcache.DefaultGolangciBaseURL)
	if err != nil {
		t.Fatalf("GolangciSpec: %v", err)
	}
	installation, err := toolcache.ProvisionTool(t.Context(), cache, toolcache.NewHTTPFetcher(nil), spec)
	if err != nil {
		t.Fatalf("provisioning the real release: %v", err)
	}
	if installation.AlreadyPresent {
		t.Fatal("a fresh cache reported the tool as already present")
	}
	if _, err := cache.VerifiedToolBinary(spec.Tool, spec.Version); err != nil {
		t.Fatalf("the provisioned binary does not verify: %v", err)
	}
}

// TestRealVulnDBSnapshot mirrors the live database. It is gated because it
// makes one request per entry against vuln.go.dev.
func TestRealVulnDBSnapshot(t *testing.T) {
	requireNetwork(t)
	cache := toolcache.OpenAt(filepath.Join(t.TempDir(), "cache"))
	result, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(nil), toolcache.DefaultVulnDBBaseURL)
	if err != nil {
		t.Fatalf("snapshotting the live database: %v", err)
	}
	if result.Manifest.EntryCount < 100 {
		t.Fatalf("entry count = %d, which is implausibly small for the live database",
			result.Manifest.EntryCount)
	}
	if _, err := cache.VerifyVulnDB(); err != nil {
		t.Fatalf("the live snapshot does not verify: %v", err)
	}
}
