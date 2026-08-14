package toolcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Environment overrides for the download origins. They exist so tests can point
// the fetcher at an httptest server; nothing reads them unless a Fetcher is
// constructed, which only setup and tools update ever do.
const (
	EnvGolangciBaseURL = "GOHARNESS_GOLANGCI_URL"
	EnvVulnDBBaseURL   = "GOHARNESS_VULNDB_URL"
)

// Default download origins.
const (
	DefaultGolangciBaseURL = "https://github.com/golangci/golangci-lint/releases/download"
	DefaultVulnDBBaseURL   = "https://vuln.go.dev"
)

// MaxDownloadBytes bounds any single response the harness will read. The
// golangci-lint archives are tens of megabytes; a response an order of
// magnitude larger is a mirror problem, not a release.
const MaxDownloadBytes = 512 << 20

// FetchTimeout bounds one request so a hung mirror cannot stall provisioning
// indefinitely.
const FetchTimeout = 5 * time.Minute

// Sources are the origins provisioning downloads from.
type Sources struct {
	GolangciBaseURL string
	VulnDBBaseURL   string
}

// DefaultSources returns the pinned origins, honouring the environment
// overrides used by tests.
func DefaultSources() Sources {
	sources := Sources{
		GolangciBaseURL: DefaultGolangciBaseURL,
		VulnDBBaseURL:   DefaultVulnDBBaseURL,
	}
	if override := os.Getenv(EnvGolangciBaseURL); override != "" {
		sources.GolangciBaseURL = override
	}
	if override := os.Getenv(EnvVulnDBBaseURL); override != "" {
		sources.VulnDBBaseURL = override
	}
	return sources
}

// Fetcher retrieves bytes over the network. It is the single seam through which
// every network read in the harness passes, so a test can both substitute a
// server and prove that a verification command never asked for one.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPFetcher is the production Fetcher.
type HTTPFetcher struct {
	client *http.Client
	limit  int64
}

// NewHTTPFetcher builds a fetcher over an HTTP client. Passing nil uses a
// client with a bounded per-request timeout rather than http.DefaultClient,
// which has none.
func NewHTTPFetcher(client *http.Client) *HTTPFetcher {
	if client == nil {
		client = &http.Client{Timeout: FetchTimeout}
	}
	return &HTTPFetcher{client: client, limit: MaxDownloadBytes}
}

// Fetch reads one URL in full. The request carries the caller's context so a
// cancelled provisioning run stops in flight, and the body is bounded so a
// hostile or broken origin cannot exhaust memory.
func (f *HTTPFetcher) Fetch(ctx context.Context, target string) (_ []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("building a request for %s: %w", target, err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", target, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", target, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", target, err)
	}
	if int64(len(data)) > f.limit {
		return nil, fmt.Errorf("fetching %s: response exceeds the %d byte limit", target, f.limit)
	}
	return data, nil
}
