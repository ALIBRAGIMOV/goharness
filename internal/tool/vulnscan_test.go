package tool_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache/toolcachetest"
)

func TestXVulnVersionIsReported(t *testing.T) {
	t.Parallel()
	if version := tool.XVulnVersion(); version != tool.XVulnPin {
		t.Fatalf("x/vuln version = %q, want %q", version, tool.XVulnPin)
	}
}

// TestXVulnPinMatchesGoMod keeps the fallback constant honest: build info is
// the authority in the released binary, but the constant must never claim a
// version the module does not require.
func TestXVulnPinMatchesGoMod(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	want := tool.XVulnModulePath + " " + tool.XVulnPin
	if !strings.Contains(string(data), want) {
		t.Fatalf("go.mod does not require %q; the pin constant has drifted", want)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not locate the module root")
		}
		dir = parent
	}
}

// TestScanAcceptsAFileSnapshot is the empirical proof the specification asks
// for: a database is mirrored from an httptest origin into the cache layout,
// and the embedded scanner reads it back through a file:// URL and finds the
// vulnerability in a module that really imports the affected symbol.
func TestScanAcceptsAFileSnapshot(t *testing.T) {
	t.Parallel()
	db := toolcachetest.VulnerableSyncDB()
	server := httptest.NewServer(db.Handler(t))
	defer server.Close()

	cache := toolcache.OpenAt(filepath.Join(t.TempDir(), "cache"))
	if _, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(server.Client()), server.URL); err != nil {
		t.Fatalf("SnapshotVulnDB: %v", err)
	}

	module := toolcachetest.WriteVulnerableModule(t)
	findings, err := tool.RunVulnScan(t.Context(), module, cache.VulnDBURL(), []string{"./..."})
	if err != nil {
		t.Fatalf("RunVulnScan against a file:// snapshot: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("the scanner read the snapshot but reported no vulnerability in a module that calls the affected symbol")
	}
	var matched bool
	for _, f := range findings {
		if f.OSV == toolcachetest.FixtureOSVID {
			matched = true
			if !strings.Contains(f.Message, "fixture vulnerability") {
				t.Fatalf("finding message lost the database summary: %q", f.Message)
			}
			if f.File == "" || f.Line == 0 {
				t.Fatalf("finding has no source position: %+v", f)
			}
		}
	}
	if !matched {
		t.Fatalf("findings = %+v, want %s", findings, toolcachetest.FixtureOSVID)
	}
}

// TestEmptyDatabaseFindsNothingSilently records why the pipeline refuses to
// scan unless a verified snapshot exists.
//
// Pointed at an empty directory the scanner does not fail: it interprets it as
// a database with no entries and reports a clean result. A harness that scanned
// unconditionally would therefore turn a missing database into a passing
// security claim, which is exactly the "safe by default" answer the admission
// model forbids. The check belongs in front of the scanner, not inside it.
func TestEmptyDatabaseFindsNothingSilently(t *testing.T) {
	t.Parallel()
	empty := filepath.Join(t.TempDir(), "empty-db")
	if err := os.MkdirAll(empty, 0o750); err != nil {
		t.Fatalf("creating an empty directory: %v", err)
	}
	module := toolcachetest.WriteVulnerableModule(t)
	findings, err := tool.RunVulnScan(t.Context(), module, "file://"+empty, []string{"./..."})
	if err != nil {
		t.Fatalf("RunVulnScan against an empty database: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("an empty database produced findings: %+v", findings)
	}
}

// TestMissingDatabaseDirectoryFails is the other half: a path that does not
// exist at all is an error the caller can see.
func TestMissingDatabaseDirectoryFails(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "no-such-directory")
	module := toolcachetest.WriteVulnerableModule(t)
	if _, err := tool.RunVulnScan(t.Context(), module, "file://"+missing, []string{"./..."}); err == nil {
		t.Fatal("scanning against a nonexistent database directory reported success")
	}
}
