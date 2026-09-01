package toolcache

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Snapshot layout constants. The file:// client the scanner uses reads plain
// .json files, while the origin serves .json.gz, so mirroring means fetching
// compressed and writing decompressed.
const (
	vulnIndexDir     = "index"
	vulnEntryDir     = "ID"
	vulnManifestName = "manifest.json"
)

// SnapshotConcurrency bounds the entry fetches. The database holds thousands of
// entries; an unbounded fan-out would open a connection per entry and be
// throttled or refused.
const SnapshotConcurrency = 8

// StaleAfter is when a snapshot starts being reported as old. It never stops a
// scan: an old database still finds the vulnerabilities it knows about.
const StaleAfter = 7 * 24 * time.Hour

// VulnDBManifest describes the active snapshot. Every field is stable for the
// life of the snapshot, so a report can embed it without breaking byte
// determinism across repeated runs.
type VulnDBManifest struct {
	Source       string    `json:"source"`
	Modified     time.Time `json:"modified"`
	FetchedAt    time.Time `json:"fetchedAt"`
	TreeChecksum string    `json:"treeChecksum"`
	EntryCount   int       `json:"entryCount"`
}

// Age is how long ago the database itself was last modified.
func (m VulnDBManifest) Age(now time.Time) time.Duration {
	return now.Sub(m.Modified)
}

// Stale reports whether the snapshot is older than the freshness budget.
func (m VulnDBManifest) Stale(now time.Time) bool {
	return m.Age(now) > StaleAfter
}

// ReadVulnDBManifest loads the active snapshot's manifest.
func (c *Cache) ReadVulnDBManifest() (VulnDBManifest, error) {
	var manifest VulnDBManifest
	if err := readJSON(filepath.Join(c.vulnCurrent(), vulnManifestName), &manifest); err != nil {
		return VulnDBManifest{}, err
	}
	return manifest, nil
}

// HasVulnDB reports whether a usable snapshot is in place. It only reads.
func (c *Cache) HasVulnDB() bool {
	_, err := os.Stat(filepath.Join(c.vulnCurrent(), vulnIndexDir, "db.json"))
	return err == nil
}

// VerifyVulnDB recomputes the snapshot's tree checksum and compares it with the
// manifest, so doctor can tell a complete snapshot from a damaged one.
func (c *Cache) VerifyVulnDB() (VulnDBManifest, error) {
	manifest, err := c.ReadVulnDBManifest()
	if err != nil {
		return VulnDBManifest{}, err
	}
	sum, _, err := treeChecksum(c.vulnCurrent())
	if err != nil {
		return manifest, err
	}
	if sum != manifest.TreeChecksum {
		return manifest, fmt.Errorf(
			"vulnerability snapshot hashes to %s but its manifest records %s: %w",
			sum, manifest.TreeChecksum, ErrCorruptEntry)
	}
	return manifest, nil
}

// SnapshotResult reports what a refresh downloaded and wrote.
type SnapshotResult struct {
	Manifest VulnDBManifest
	Files    int
	Bytes    int64
	Replaced bool
}

type vulnEntryRef struct {
	ID string `json:"id"`
}

type vulnDBMeta struct {
	Modified time.Time `json:"modified"`
}

// SnapshotVulnDB mirrors the origin database into the cache and swaps it into
// service atomically.
//
// The new snapshot is assembled in a staging directory beside the live one and
// only becomes current once every file is written and the manifest is
// complete. A download that fails, is cancelled, or produces an inconsistent
// tree leaves the previous snapshot untouched and in service.
func SnapshotVulnDB(ctx context.Context, cache *Cache, fetcher Fetcher, baseURL string) (_ SnapshotResult, err error) {
	base := strings.TrimRight(baseURL, "/")
	if err := os.MkdirAll(cache.vulnDir(), 0o750); err != nil {
		return SnapshotResult{}, fmt.Errorf("creating the vulnerability cache directory: %w", err)
	}
	staging, err := os.MkdirTemp(cache.vulnDir(), "staging-")
	if err != nil {
		return SnapshotResult{}, fmt.Errorf("creating a staging directory: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(staging); rmErr != nil && err == nil {
			err = fmt.Errorf("removing the staging directory: %w", rmErr)
		}
	}()

	written, err := mirrorIndexes(ctx, fetcher, base, staging)
	if err != nil {
		return SnapshotResult{}, err
	}
	ids, err := entryIDs(staging)
	if err != nil {
		return SnapshotResult{}, err
	}
	entryBytes, err := mirrorEntries(ctx, fetcher, base, staging, ids)
	if err != nil {
		return SnapshotResult{}, err
	}

	modified, err := snapshotModified(staging)
	if err != nil {
		return SnapshotResult{}, err
	}
	sum, files, err := treeChecksum(staging)
	if err != nil {
		return SnapshotResult{}, err
	}
	manifest := VulnDBManifest{
		Source:       base,
		Modified:     modified,
		FetchedAt:    time.Now().UTC().Truncate(time.Second),
		TreeChecksum: sum,
		EntryCount:   len(ids),
	}
	if err := writeJSON(filepath.Join(staging, vulnManifestName), manifest); err != nil {
		return SnapshotResult{}, err
	}

	replaced, err := cache.swapVulnDB(staging)
	if err != nil {
		return SnapshotResult{}, err
	}
	return SnapshotResult{
		Manifest: manifest,
		Files:    files + 1,
		Bytes:    written + entryBytes,
		Replaced: replaced,
	}, nil
}

// swapVulnDB moves a staged snapshot into service. The live directory is moved
// aside first and restored if the second rename fails, so the window in which
// no snapshot is current is two rename calls wide and never leaves a half-built
// tree in service.
func (c *Cache) swapVulnDB(staging string) (replaced bool, err error) {
	current := c.vulnCurrent()
	retiring := ""
	if _, statErr := os.Stat(current); statErr == nil {
		retiring = filepath.Join(c.vulnDir(), fmt.Sprintf("retiring-%d", time.Now().UnixNano()))
		if err := os.Rename(current, retiring); err != nil {
			return false, fmt.Errorf("moving the previous snapshot aside: %w", err)
		}
		replaced = true
	}
	if err := os.Rename(staging, current); err != nil {
		if retiring != "" {
			return false, errors.Join(
				fmt.Errorf("publishing the new snapshot: %w", err),
				os.Rename(retiring, current))
		}
		return false, fmt.Errorf("publishing the new snapshot: %w", err)
	}
	if retiring != "" {
		if err := os.RemoveAll(retiring); err != nil {
			return replaced, fmt.Errorf("removing the previous snapshot: %w", err)
		}
	}
	return replaced, nil
}

// RecoverVulnDB restores a snapshot left aside by an interrupted swap. It is a
// write, so only the provisioning commands call it; the read path reports a
// missing snapshot instead of repairing one behind the user's back.
func (c *Cache) RecoverVulnDB() (bool, error) {
	if c.HasVulnDB() {
		return false, nil
	}
	entries, err := os.ReadDir(c.vulnDir())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspecting the vulnerability cache: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "retiring-") {
			continue
		}
		if err := os.Rename(filepath.Join(c.vulnDir(), entry.Name()), c.vulnCurrent()); err != nil {
			return false, fmt.Errorf("restoring an interrupted snapshot swap: %w", err)
		}
		return true, nil
	}
	return false, nil
}

func mirrorIndexes(ctx context.Context, fetcher Fetcher, base, staging string) (int64, error) {
	var total int64
	for _, name := range []string{"db", "modules", "vulns"} {
		endpoint := path.Join(vulnIndexDir, name)
		data, err := fetchJSONGz(ctx, fetcher, base, endpoint)
		if err != nil {
			return total, err
		}
		if err := writeSnapshotFile(staging, endpoint+".json", data); err != nil {
			return total, err
		}
		total += int64(len(data))
	}
	return total, nil
}

// entryIDs reads the vulnerability index the origin already gave us rather than
// re-deriving it, so the snapshot mirrors exactly what the database advertises.
func entryIDs(staging string) ([]string, error) {
	data, err := readStaged(staging, vulnIndexDir+"/vulns.json")
	if err != nil {
		return nil, fmt.Errorf("reading the mirrored vulnerability index: %w", err)
	}
	var refs []vulnEntryRef
	if err := json.Unmarshal(data, &refs); err != nil {
		return nil, fmt.Errorf("decoding the vulnerability index: %w", err)
	}
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.ID != "" && !slices.Contains(ids, ref.ID) {
			ids = append(ids, ref.ID)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

func mirrorEntries(ctx context.Context, fetcher Fetcher, base, staging string, ids []string) (int64, error) {
	sizes := make([]int64, len(ids))
	sem := semaphore.NewWeighted(SnapshotConcurrency)
	group, gctx := errgroup.WithContext(ctx)

	for i, id := range ids {
		group.Go(func() error {
			if err := sem.Acquire(gctx, 1); err != nil {
				return err
			}
			defer sem.Release(1)

			endpoint := path.Join(vulnEntryDir, id)
			data, err := fetchJSONGz(gctx, fetcher, base, endpoint)
			if err != nil {
				return err
			}
			if err := writeSnapshotFile(staging, endpoint+".json", data); err != nil {
				return err
			}
			sizes[i] = int64(len(data))
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return 0, err
	}
	var total int64
	for _, size := range sizes {
		total += size
	}
	return total, nil
}

func fetchJSONGz(ctx context.Context, fetcher Fetcher, base, endpoint string) (_ []byte, err error) {
	compressed, err := fetcher.Fetch(ctx, base+"/"+endpoint+".json.gz")
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", endpoint, err)
	}
	defer func() { err = errors.Join(err, reader.Close()) }()

	data, err := io.ReadAll(io.LimitReader(reader, MaxArchiveBytes))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", endpoint, err)
	}
	return data, nil
}

// writeSnapshotFile rejects any endpoint that would escape the staging tree,
// so a hostile index cannot direct a write outside the cache.
func writeSnapshotFile(staging, relative string, data []byte) error {
	clean := path.Clean(relative)
	if path.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("refusing to write snapshot entry outside the cache: %q", relative)
	}
	full := filepath.Join(staging, filepath.FromSlash(clean))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", full, err)
	}
	return nil
}

// readStaged reads one mirrored file through a root bounded to the staging
// directory, so an index entry naming a path outside it is refused rather than
// followed.
func readStaged(staging, rel string) (_ []byte, err error) {
	root, err := os.OpenRoot(staging)
	if err != nil {
		return nil, fmt.Errorf("opening the staging directory: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return root.ReadFile(filepath.FromSlash(rel))
}

func snapshotModified(staging string) (time.Time, error) {
	data, err := readStaged(staging, vulnIndexDir+"/db.json")
	if err != nil {
		return time.Time{}, fmt.Errorf("reading the mirrored database metadata: %w", err)
	}
	var meta vulnDBMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return time.Time{}, fmt.Errorf("decoding the database metadata: %w", err)
	}
	return meta.Modified.UTC(), nil
}

// treeChecksum hashes the snapshot as a whole: sha256 over the sorted
// "path:sha256" line of every file. The manifest itself is excluded, since it
// carries the checksum and cannot contain its own hash.
func treeChecksum(dir string) (_ string, _ int, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", 0, fmt.Errorf("opening the snapshot directory: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()

	var lines []string
	tree := root.FS()
	walkErr := fs.WalkDir(tree, ".", func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || p == vulnManifestName {
			return nil
		}
		data, readErr := fs.ReadFile(tree, p)
		if readErr != nil {
			return readErr
		}
		lines = append(lines, p+":"+Sum(data))
		return nil
	})
	if walkErr != nil {
		return "", 0, fmt.Errorf("checksumming the snapshot: %w", walkErr)
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), len(lines), nil
}
