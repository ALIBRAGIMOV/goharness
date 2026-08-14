package verify_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache/toolcachetest"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// vulnerableFixture is a repository whose module calls a symbol the fixture
// database marks as vulnerable.
func vulnerableFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.write("go.mod", "module example.com/fixture\n\ngo 1.26\n\nrequire "+
		toolcachetest.FixtureModulePath+" "+toolcachetest.FixtureVersion+"\n")
	f.write("go.sum", toolcachetest.FixtureSums())
	f.write("lib/lib.go", `package lib

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Answer runs a bounded group and returns a constant.
func Answer(ctx context.Context) int {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return groupCtx.Err() })
	if err := group.Wait(); err != nil {
		return 0
	}
	return 42
}
`)
	f.write("lib/lib_test.go", `package lib

import (
	"context"
	"testing"
)

func TestAnswer(t *testing.T) {
	if got := Answer(context.Background()); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
}
`)
	f.commit("module that calls the affected symbol")
	return f
}

// provisionSnapshot mirrors the fixture database into a cache the run will use.
func provisionSnapshot(t *testing.T) {
	t.Helper()
	db := toolcachetest.VulnerableSyncDB()
	server := httptest.NewServer(db.Handler(t))
	t.Cleanup(server.Close)

	root := filepath.Join(t.TempDir(), "cache")
	t.Setenv(toolcache.EnvCacheRoot, root)
	cache := toolcache.OpenAt(root)
	if _, err := toolcache.SnapshotVulnDB(t.Context(), cache,
		toolcache.NewHTTPFetcher(server.Client()), server.URL); err != nil {
		t.Fatalf("provisioning the snapshot: %v", err)
	}
}

// TestAuditReportsVulnerabilitiesFromTheSnapshot is the end-to-end proof: a
// database mirrored from an httptest origin, read back through file://, becomes
// GO-VULN evidence that fails the security claim.
func TestAuditReportsVulnerabilitiesFromTheSnapshot(t *testing.T) {
	useGolangci(t)
	provisionSnapshot(t)
	f := vulnerableFixture(t)

	result := run(t, f, verify.ModeAudit)
	if !slices.Contains(blockingRules(result.Evidence), policy.RuleGovulncheck) {
		t.Fatalf("blocking rules = %v, want %s\nclaims: %+v",
			blockingRules(result.Evidence), policy.RuleGovulncheck, result.Decision.Claims)
	}
	requireVerdict(t, result, admission.VerdictRejected)

	claim := claimFor(t, result, admission.DimSecurity)
	if claim.State != admission.ClaimFail {
		t.Fatalf("security claim = %s (%s), want FAIL", claim.State, claim.Reason)
	}
	var named bool
	for _, e := range result.Evidence {
		if e.RuleID == policy.RuleGovulncheck && strings.Contains(e.Message, toolcachetest.FixtureOSVID) {
			named = true
		}
	}
	if !named {
		t.Fatalf("no finding names %s: %v", toolcachetest.FixtureOSVID, ruleIDs(result.Evidence))
	}
	if result.VulnDB == nil {
		t.Fatal("the result does not record which snapshot produced the evidence")
	}
	if result.VulnDB.EntryCount != 1 || result.VulnDB.TreeChecksum == "" {
		t.Fatalf("snapshot metadata = %+v", result.VulnDB)
	}
}

// TestAuditWithoutASnapshotIsInconclusive is the guarantee that a missing
// database is never read as a clean bill of health.
func TestAuditWithoutASnapshotIsInconclusive(t *testing.T) {
	useGolangci(t)
	t.Setenv(toolcache.EnvCacheRoot, filepath.Join(t.TempDir(), "empty-cache"))
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")

	result := run(t, f, verify.ModeAudit)
	requireVerdict(t, result, admission.VerdictInconclusive)

	claim := claimFor(t, result, admission.DimSecurity)
	if claim.State != admission.ClaimInconclusive {
		t.Fatalf("security claim = %s (%s), want INCONCLUSIVE", claim.State, claim.Reason)
	}
	if !slices.Contains(claim.MissingEvidence, admission.KindVulnerabilityScan) {
		t.Fatalf("missing evidence = %v", claim.MissingEvidence)
	}
	var remedy string
	for _, u := range result.Unproducible {
		if u.Kind == admission.KindVulnerabilityScan {
			remedy = u.Remedy
		}
	}
	if remedy != "run goharness setup" {
		t.Fatalf("remedy = %q, want the setup command", remedy)
	}
	if result.VulnDB != nil {
		t.Fatal("a run with no snapshot still reported one")
	}
}

// TestVerificationMakesNoNetworkRequests is the offline guarantee. Both
// download origins are pointed at recording servers; a verification run that
// constructed a fetcher for any reason would show up as a request.
func TestVerificationMakesNoNetworkRequests(t *testing.T) {
	useGolangci(t)
	var requests atomic.Int64
	recorder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "verification must not reach the network", http.StatusTeapot)
	}))
	defer recorder.Close()

	t.Setenv(toolcache.EnvGolangciBaseURL, recorder.URL)
	t.Setenv(toolcache.EnvVulnDBBaseURL, recorder.URL)
	provisionRequests := requests.Load()

	provisionSnapshot(t)
	if requests.Load() != provisionRequests {
		t.Fatal("the snapshot fixture used the recorder rather than its own server")
	}

	f := vulnerableFixture(t)
	for _, mode := range []verify.Mode{verify.ModeFast, verify.ModeVerify, verify.ModeAudit} {
		before := requests.Load()
		run(t, f, mode)
		if after := requests.Load(); after != before {
			t.Fatalf("%s made %d network request(s); verification must never install or fetch",
				mode, after-before)
		}
	}
}
