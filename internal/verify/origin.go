package verify

import (
	"path"

	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// attributeOrigin marks each finding with whether it sits in code this change
// wrote.
//
// It is a second axis, not a refinement of the first. State answers whether a
// finding existed at the base revision; origin answers whether it is located in
// a file the change touched. Neither implies the other: a change can create a
// finding in a package it never opened, and a file it rewrote can carry debt
// older than the branch. A report of a branch is the two read together.
//
// A finding this cannot place keeps the zero value rather than being guessed
// into one bucket or the other, and every rendering keeps unplaced findings for
// exactly that reason.
func (t *target) attributeOrigin(cs change.ChangeSet, items []evidence.Evidence) []evidence.Evidence {
	if cs.FullScope || len(cs.Entries) == 0 {
		return items
	}
	files := make(map[string]bool, len(cs.Entries))
	dirs := map[string]bool{}
	for _, entry := range cs.Entries {
		if entry.Status == change.StatusDeleted {
			continue
		}
		files[entry.Path] = true
		dirs[path.Dir(entry.Path)] = true
	}
	out := make([]evidence.Evidence, 0, len(items))
	for _, e := range items {
		e.Origin = t.originOf(e, files, dirs)
		out = append(out, e)
	}
	return out
}

// originOf places one finding against the diff.
//
// A file the change wrote is the direct answer. What makes the rest of this
// necessary is that findings which belong to a package rather than to a line
// have nowhere better to be: a goroutine leak carries its package directory, an
// API break carries the import path of the package that broke, a test failure
// carries the package alone. Every one of those is the change's when it touched
// anything in that directory, so each candidate is resolved to a directory and
// tried.
func (t *target) originOf(e evidence.Evidence, files, dirs map[string]bool) evidence.Origin {
	if e.File == "" && e.Package == "" {
		return evidence.OriginUnscoped
	}
	if files[e.File] {
		return evidence.OriginChanged
	}
	for _, dir := range []string{e.File, t.packageDir(e.Package), t.packageDir(e.File)} {
		if dir != "" && dirs[dir] {
			return evidence.OriginChanged
		}
	}
	return evidence.OriginUntouched
}

// packageDir is a package's directory in the coordinate system the change set
// uses. An unknown package returns the empty string, which no changed directory
// can equal.
func (t *target) packageDir(pkgPath string) string {
	dir, _, ok := t.graph.DirAndName(pkgPath)
	if !ok {
		return ""
	}
	return t.rel(dir)
}
