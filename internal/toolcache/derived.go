package toolcache

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// MaxDerivedEntries bounds a kind whose documents describe a whole run. The
// cache is keyed by content, so entries are never overwritten and would
// otherwise grow with every base revision a repository ever verified; the
// oldest are dropped once the directory passes this size.
const MaxDerivedEntries = 128

// MaxPerPackageEntries bounds a kind whose documents describe one package.
//
// A repository writes one entry per package per revision here, so the bound has
// to be a multiple of the package count of a large module or the cache evicts
// what the next run is about to ask for and never warms up. These documents are
// small, and an oversized directory costs disk rather than correctness.
const MaxPerPackageEntries = 8192

// derivedDir holds results the harness computed rather than downloaded. They
// are reproducible from their key, so losing one costs time and nothing else.
func (c *Cache) derivedDir(kind string) string {
	return filepath.Join(c.root, "derived", kind)
}

// ReadDerived loads a derived document into out. A missing entry reports
// ErrNotProvisioned, which callers treat as "compute it again".
func (c *Cache) ReadDerived(kind, key string, out any) error {
	return readJSON(filepath.Join(c.derivedDir(kind), key+".json"), out)
}

// WriteDerived stores a derived document under its key and trims the kind back
// to maxEntries. The bound is the caller's because it follows from how much one
// document describes, which the cache cannot see.
func (c *Cache) WriteDerived(kind, key string, document any, maxEntries int) error {
	if err := writeJSON(filepath.Join(c.derivedDir(kind), key+".json"), document); err != nil {
		return err
	}
	return c.trimDerived(kind, maxEntries)
}

// trimDerived keeps the oldest entries from accumulating without limit. A
// failure to trim is not a failure to cache: the document is already published,
// and the next write tries again.
func (c *Cache) trimDerived(kind string, maxEntries int) error {
	dir := c.derivedDir(kind)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("listing %s: %w", dir, err)
	}
	if len(entries) <= maxEntries {
		return nil
	}
	type aged struct {
		name string
		age  int64
	}
	dated := make([]aged, 0, len(entries))
	for _, e := range entries {
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		dated = append(dated, aged{name: e.Name(), age: info.ModTime().UnixNano()})
	}
	slices.SortFunc(dated, func(a, b aged) int { return int(a.age - b.age) })
	for _, e := range dated[:max(0, len(dated)-maxEntries)] {
		if err := os.Remove(filepath.Join(dir, e.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("trimming %s: %w", dir, err)
		}
	}
	return nil
}
