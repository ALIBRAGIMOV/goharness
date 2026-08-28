package verify

import (
	"path"

	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// attributeOrigin marks each finding with where it sits relative to the change.
//
// It is a second axis, not a refinement of the first. State answers whether a
// finding existed at the base revision; origin answers how close it is to the
// code this change wrote. Neither implies the other: a change can create a
// finding in a package it never opened, and a file it rewrote can carry debt
// older than the branch. A report of a branch is the two read together.
//
// A finding this cannot place keeps the zero value rather than being guessed
// into a bucket, and everything downstream treats unplaced as the change's:
// leniency is never granted on the strength of something the harness does not
// know.
func (t *target) attributeOrigin(cs change.ChangeSet, items []evidence.Evidence) []evidence.Evidence {
	if len(cs.Entries) == 0 {
		return items
	}
	scope := newDiffScope(cs)
	out := make([]evidence.Evidence, 0, len(items))
	for _, e := range items {
		e.Origin = t.originOf(e, scope)
		out = append(out, e)
	}
	return out
}

// diffScope is the change reduced to the lookups attribution needs.
type diffScope struct {
	// whole names the files the change created, where every line is its own.
	whole map[string]bool
	// added is the line spans the change wrote in files that already existed.
	added map[string][]change.LineRange
	files map[string]bool
	dirs  map[string]bool
}

func newDiffScope(cs change.ChangeSet) diffScope {
	s := diffScope{
		whole: map[string]bool{},
		added: cs.Added,
		files: make(map[string]bool, len(cs.Entries)),
		dirs:  map[string]bool{},
	}
	for _, entry := range cs.Entries {
		if entry.Status == change.StatusDeleted {
			continue
		}
		s.files[entry.Path] = true
		s.dirs[path.Dir(entry.Path)] = true
		if entry.Status == change.StatusAdded {
			s.whole[entry.Path] = true
		}
	}
	return s
}

// wrote reports whether one line of a file falls in a span the change added.
func (s diffScope) wrote(file string, line int) bool {
	for _, span := range s.added[file] {
		if span.Contains(line) {
			return true
		}
	}
	return false
}

// originOf places one finding against the change, nearest distance first.
//
// The order is what makes this correct, and getting it wrong is what shipped in
// 0.7.0: the package test ran for every row rather than only for the rows that
// have no file of their own, so every finding anywhere in a package holding a
// changed file came out as the change's.
//
// The package tests exist for the findings that belong to a package rather than
// to a line. A goroutine leak carries the directory it leaked in, an API break
// carries the import path of the package that broke, a test failure carries the
// package alone, and each of those is the change's business when it touched
// anything in that directory.
func (t *target) originOf(e evidence.Evidence, s diffScope) evidence.Origin {
	if e.File == "" && e.Package == "" {
		return evidence.OriginUnscoped
	}
	if s.files[e.File] {
		// A finding with no line is about the whole file rather than a place in it,
		// so it is the change's writing only where the change wrote the file.
		if s.whole[e.File] || (e.Line > 0 && s.wrote(e.File, e.Line)) {
			return evidence.OriginAddedLine
		}
		return evidence.OriginChangedFile
	}
	// Package holds an import path from most producers and a module-relative
	// directory from the ones that measure a package rather than resolve it, so
	// both readings are tried. An import path can never equal a directory inside
	// the module, so trying both cannot place a finding twice.
	for _, dir := range []string{
		e.File, e.Package, t.packageDir(e.Package), t.packageDir(e.File),
	} {
		if dir != "" && s.dirs[dir] {
			return evidence.OriginChangedPackage
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
