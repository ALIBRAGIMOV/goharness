package toolcache

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// MaxDerivedEntries bounds one kind of derived document. The cache is keyed by
// content, so entries are never overwritten and would otherwise grow with every
// base revision a repository ever verified; the oldest are dropped once the
// directory passes this size.
const MaxDerivedEntries = 128

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
// to its bound.
func (c *Cache) WriteDerived(kind, key string, document any) error {
	if err := writeJSON(filepath.Join(c.derivedDir(kind), key+".json"), document); err != nil {
		return err
	}
	return c.trimDerived(kind)
}

// trimDerived keeps the oldest entries from accumulating without limit. A
// failure to trim is not a failure to cache: the document is already published,
// and the next write tries again.
func (c *Cache) trimDerived(kind string) error {
	dir := c.derivedDir(kind)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("listing %s: %w", dir, err)
	}
	if len(entries) <= MaxDerivedEntries {
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
	for _, e := range dated[:max(0, len(dated)-MaxDerivedEntries)] {
		if err := os.Remove(filepath.Join(dir, e.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("trimming %s: %w", dir, err)
		}
	}
	return nil
}
