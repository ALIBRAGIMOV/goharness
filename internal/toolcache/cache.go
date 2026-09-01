// Package toolcache owns the content-addressed cache of provisioned tools and
// the vulnerability database snapshot.
//
// Two rules shape everything here. Payloads are named by the hex of their own
// sha256 and written temp-file-then-rename, so a cache entry is either absent
// or complete and correct. And every network read goes through one injected
// Fetcher, so the commands that verify code cannot reach the network even by
// accident: they never construct one.
package toolcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// EnvCacheRoot overrides the cache location.
const EnvCacheRoot = "GOHARNESS_CACHE"

// ErrNotProvisioned reports that the cache holds no entry for what was asked.
// Callers turn it into an INCONCLUSIVE claim with a setup hint, never into a
// pass and never into a code finding.
var ErrNotProvisioned = errors.New("not provisioned in the goharness cache")

// ErrCorruptEntry reports that a cached payload no longer hashes to what its
// manifest recorded.
var ErrCorruptEntry = errors.New("cached payload does not match its manifest checksum")

// Cache is a handle on the cache root. Opening one performs no I/O, so a
// read-only command can hold a Cache for a tree that does not exist yet.
type Cache struct {
	root string
}

// Open resolves the cache root from the environment override, falling back to
// the user cache directory. It creates nothing.
func Open() (*Cache, error) {
	if root := os.Getenv(EnvCacheRoot); root != "" {
		return OpenAt(root), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("locating the user cache directory: %w", err)
	}
	return OpenAt(filepath.Join(base, "goharness")), nil
}

// OpenAt returns a cache rooted at an explicit directory.
func OpenAt(root string) *Cache {
	return &Cache{root: root}
}

// Root is the cache directory, whether or not it exists.
func (c *Cache) Root() string { return c.root }

func (c *Cache) blobsDir() string    { return filepath.Join(c.root, "blobs", "sha256") }
func (c *Cache) toolsDir() string    { return filepath.Join(c.root, "tools") }
func (c *Cache) vulnDir() string     { return filepath.Join(c.root, "vulndb") }
func (c *Cache) vulnCurrent() string { return filepath.Join(c.vulnDir(), "current") }

// VulnDBDir is the directory holding the active snapshot.
func (c *Cache) VulnDBDir() string { return c.vulnCurrent() }

// VulnDBURL renders the active snapshot as a file URL for the scanner.
func (c *Cache) VulnDBURL() string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(c.vulnCurrent())}).String()
}

// Sum returns the hex sha256 of a payload, which is also its blob name.
func Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SumFile returns the hex sha256 of a file's contents. It streams, because the
// files it is asked about are executables of tens of megabytes.
func SumFile(path string) (_ string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// BlobPath returns the location of a blob and whether it is present.
func (c *Cache) BlobPath(sum string) (string, bool) {
	path := filepath.Join(c.blobsDir(), sum)
	info, err := os.Stat(path)
	return path, err == nil && !info.IsDir()
}

// WriteBlob stores a payload under the hex of its own sha256 and returns that
// name. Writing is temp-file-then-rename, so a reader never observes a partial
// blob, and re-writing identical content is a no-op.
func (c *Cache) WriteBlob(data []byte, mode fs.FileMode) (_ string, err error) {
	sum := Sum(data)
	if err := os.MkdirAll(c.blobsDir(), 0o750); err != nil {
		return "", fmt.Errorf("creating the blob directory: %w", err)
	}
	final := filepath.Join(c.blobsDir(), sum)
	if info, statErr := os.Stat(final); statErr == nil && !info.IsDir() {
		return sum, nil
	}
	temp, err := os.CreateTemp(c.blobsDir(), "incoming-*")
	if err != nil {
		return "", fmt.Errorf("creating a temporary blob: %w", err)
	}
	tempName := temp.Name()
	published := false
	defer func() { err = errors.Join(err, discardTemp(tempName, published)) }()

	if _, err := temp.Write(data); err != nil {
		return "", errors.Join(fmt.Errorf("writing a temporary blob: %w", err), temp.Close())
	}
	if err := temp.Chmod(mode); err != nil {
		return "", errors.Join(fmt.Errorf("setting blob permissions: %w", err), temp.Close())
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("closing a temporary blob: %w", err)
	}
	if err := os.Rename(tempName, final); err != nil {
		return "", fmt.Errorf("publishing a blob: %w", err)
	}
	published = true
	return sum, nil
}

// discardTemp removes a temporary file that was never published. Once the
// rename has happened the file is gone by definition, so nothing is attempted;
// a failure to clean up an abandoned one is reported rather than swallowed,
// because it leaves rubbish in a cache the harness promises to keep tidy.
func discardTemp(name string, published bool) error {
	if published {
		return nil
	}
	if err := os.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing an abandoned temporary file: %w", err)
	}
	return nil
}

// Size reports the total bytes the cache occupies, for doctor. An entry that
// disappears mid-walk is skipped rather than failing the measurement: another
// process may be provisioning, and a size is advisory information.
func (c *Cache) Size() (int64, error) {
	var total int64
	err := filepath.WalkDir(c.root, func(_ string, entry fs.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil && errors.Is(walkErr, fs.ErrNotExist):
			return nil
		case walkErr != nil:
			return walkErr
		case entry.IsDir():
			return nil
		}
		size, known := entrySize(entry)
		if known {
			total += size
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return total, fmt.Errorf("measuring the cache: %w", err)
	}
	return total, nil
}

// entrySize reports a file's size, or that it could not be determined. An
// entry that vanishes between the walk and the stat is not an error: another
// process may be provisioning, and the total is advisory.
func entrySize(entry fs.DirEntry) (int64, bool) {
	info, err := entry.Info()
	if err != nil {
		return 0, false
	}
	return info.Size(), true
}

// writeJSON stores a document temp-file-then-rename so a reader never sees a
// half-written manifest.
func writeJSON(path string, document any) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	encoded, err := json.Marshal(document, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	encoded = append(encoded, '\n')

	temp, err := os.CreateTemp(filepath.Dir(path), "incoming-*")
	if err != nil {
		return fmt.Errorf("creating a temporary manifest: %w", err)
	}
	tempName := temp.Name()
	published := false
	defer func() { err = errors.Join(err, discardTemp(tempName, published)) }()

	if _, err := temp.Write(encoded); err != nil {
		return errors.Join(fmt.Errorf("writing %s: %w", path, err), temp.Close())
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing a temporary manifest: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("publishing %s: %w", path, err)
	}
	published = true
	return nil
}

func readJSON(path string, document any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", path, ErrNotProvisioned)
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(data, document); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// ToolManifest records how one provisioned tool was obtained and what it must
// still hash to.
type ToolManifest struct {
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	Platform      string    `json:"platform"`
	ArchiveSHA256 string    `json:"archiveSha256"`
	BinarySHA256  string    `json:"binarySha256"`
	Blob          string    `json:"blob"`
	InstalledAt   time.Time `json:"installedAt"`
}

func (c *Cache) toolManifestPath(tool, version string) string {
	return filepath.Join(c.toolsDir(), tool, version, "manifest.json")
}

// ReadToolManifest loads a tool's manifest.
func (c *Cache) ReadToolManifest(tool, version string) (ToolManifest, error) {
	var manifest ToolManifest
	if err := readJSON(c.toolManifestPath(tool, version), &manifest); err != nil {
		return ToolManifest{}, err
	}
	return manifest, nil
}

// WriteToolManifest publishes a tool's manifest.
func (c *Cache) WriteToolManifest(manifest ToolManifest) error {
	return writeJSON(c.toolManifestPath(manifest.Tool, manifest.Version), manifest)
}

// VerifiedToolBinary returns the path to a provisioned binary after re-hashing
// it against its manifest. A cached payload that no longer matches is never
// executed: the caller is told the entry is corrupt and can fall through to
// another discovery source.
func (c *Cache) VerifiedToolBinary(tool, version string) (string, error) {
	manifest, err := c.ReadToolManifest(tool, version)
	if err != nil {
		return "", err
	}
	path, present := c.BlobPath(manifest.Blob)
	if !present {
		return "", fmt.Errorf("blob %s for %s %s is missing: %w",
			manifest.Blob, tool, version, ErrNotProvisioned)
	}
	sum, err := SumFile(path)
	if err != nil {
		return "", err
	}
	if sum != manifest.BinarySHA256 {
		return "", fmt.Errorf("%s %s binary hashes to %s but its manifest records %s: %w",
			tool, version, sum, manifest.BinarySHA256, ErrCorruptEntry)
	}
	return path, nil
}
