// Package toolcachetest builds the fixtures that prove the vulnerability
// pipeline works end to end: a tiny database in the origin's wire format, and a
// module that really imports and calls an affected symbol.
//
// It is a test-support package rather than test files so that both the tool and
// verify suites can share one fixture and cannot drift apart.
package toolcachetest

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture pins a module that is already in the module cache as a build
// dependency of the harness, so the scan resolves offline and the test never
// reaches the network for anything but its own httptest origin.
const (
	FixtureOSVID      = "GO-2026-9001"
	FixtureModulePath = "golang.org/x/sync"
	FixtureVersion    = "v0.22.0"
	FixturePackage    = "golang.org/x/sync/errgroup"
	FixtureSymbol     = "WithContext"
	fixtureFixedIn    = "999.0.0"
)

// FixtureModified is the database's modified timestamp, fixed so snapshots are
// reproducible.
func FixtureModified() time.Time {
	return time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
}

// VulnDB is a minimal vulnerability database in the v1 layout.
type VulnDB struct {
	ID         string
	ModulePath string
	Package    string
	Symbol     string
	FixedIn    string
	Modified   time.Time
}

// VulnerableSyncDB declares the harness's own errgroup dependency vulnerable,
// which gives the scanner a real module at a real version to match against.
func VulnerableSyncDB() VulnDB {
	return VulnDB{
		ID:         FixtureOSVID,
		ModulePath: FixtureModulePath,
		Package:    FixturePackage,
		Symbol:     FixtureSymbol,
		FixedIn:    fixtureFixedIn,
		Modified:   FixtureModified(),
	}
}

// WithModified returns a copy whose database timestamp is t, so a test can
// choose between a fresh and a stale snapshot.
func (db VulnDB) WithModified(t time.Time) VulnDB {
	db.Modified = t.UTC()
	return db
}

func (db VulnDB) entry() string {
	stamp := db.Modified.Format(time.RFC3339)
	return `{
  "id": "` + db.ID + `",
  "modified": "` + stamp + `",
  "published": "2026-01-15T00:00:00Z",
  "summary": "fixture vulnerability in ` + db.ModulePath + `",
  "details": "A fixture entry used to prove the scanner reads a file:// snapshot.",
  "affected": [
    {
      "package": {"name": "` + db.ModulePath + `", "ecosystem": "Go"},
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "` + db.FixedIn + `"}]}
      ],
      "ecosystem_specific": {
        "imports": [{"path": "` + db.Package + `", "symbols": ["` + db.Symbol + `"]}]
      }
    }
  ],
  "database_specific": {"url": "https://pkg.go.dev/vuln/` + db.ID + `"}
}`
}

// Handler serves the database gzipped, exactly as vuln.go.dev does, so the
// mirroring code is exercised rather than bypassed.
func (db VulnDB) Handler(t *testing.T) http.Handler {
	t.Helper()
	stamp := db.Modified.Format(time.RFC3339)
	ref := `{"id":"` + db.ID + `","modified":"` + stamp + `"}`
	files := map[string]string{
		"/index/db.json.gz":         `{"modified":"` + stamp + `"}`,
		"/index/modules.json.gz":    `[{"path":"` + db.ModulePath + `","vulns":[` + ref + `]}]`,
		"/index/vulns.json.gz":      `[{"id":"` + db.ID + `","modified":"` + stamp + `","aliases":[]}]`,
		"/ID/" + db.ID + ".json.gz": db.entry(),
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

// WriteVulnerableModule creates a module that imports and calls the affected
// symbol, and returns its directory. The dependency is already in the module
// cache because the harness itself uses it, so the scan needs no network.
func WriteVulnerableModule(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving the fixture module directory: %v", err)
	}
	write(t, dir, "go.mod", "module example.com/vulnfixture\n\ngo 1.26\n\nrequire "+
		FixtureModulePath+" "+FixtureVersion+"\n")
	write(t, dir, "go.sum", syncSums())
	write(t, dir, "app.go", `package vulnfixture

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Run calls the symbol the fixture database marks as vulnerable.
func Run(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return groupCtx.Err() })
	return group.Wait()
}
`)
	return dir
}

// syncSums are the checksums for the pinned fixture dependency, copied from the
// harness's own go.sum so the fixture resolves from the module cache with the
// proxy switched off.
func syncSums() string {
	return strings.Join([]string{
		FixtureModulePath + " " + FixtureVersion + " h1:SZjpbeLmrCk4xhRSZFNZW5gFUeCeFgjekvI/+gfScek=",
		FixtureModulePath + " " + FixtureVersion + "/go.mod h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0=",
		"",
	}, "\n")
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// FixtureSums exposes the pinned dependency's checksums so a repository fixture
// can resolve the module offline.
func FixtureSums() string { return syncSums() }
