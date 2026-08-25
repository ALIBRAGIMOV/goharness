package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// Derived kinds this file owns, one per check so that a stored answer can never
// be read back for a different question.
const (
	gofmtEvidenceKind     = "head-gofmt"
	goimportsEvidenceKind = "head-goimports"
)

// formatFinding is what one formatting check concluded about one file, before
// any policy has looked at it.
//
// The cache stores findings rather than evidence on purpose. Classification,
// consequence and fingerprint are recomputed on every run because they depend
// on the policy in force, which the key does not fully describe; storing the
// raw answer keeps a cached entry honest across a policy edit.
type formatFinding struct {
	File string `json:"file"`
}

// packageScope is one package directory and the files this run judges in it.
//
// The file list is the run's, not the directory's: a generated file the change
// leaves alone is exempt and never scanned, so a key built from the directory
// listing would describe work that did not happen. A file that is deleted or
// renamed leaves the list and moves the key by itself.
type packageScope struct {
	dir    string
	files  []string
	digest string
}

// scopePackages groups the judged files by directory, hashing each group's
// contents where a cached answer could be stored under it.
//
// The coordinator runs this once for the whole target, before any check starts,
// because two checks ask the same question of the same files and hashing them
// twice would spend the reads the cache is there to save.
func (t *target) scopePackages(ctx context.Context) error {
	if t.packageScopes != nil {
		return nil
	}
	byDir := map[string][]string{}
	for _, rel := range t.judged {
		dir := path.Dir(rel)
		byDir[dir] = append(byDir[dir], rel)
	}
	cacheable := t.headCacheable()
	scopes := make([]packageScope, 0, len(byDir))
	for _, dir := range slices.Sorted(maps.Keys(byDir)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		files := slices.Sorted(slices.Values(byDir[dir]))
		scope := packageScope{dir: dir, files: files}
		if cacheable {
			digest, err := t.contentDigest(files)
			if err != nil {
				return err
			}
			scope.digest = digest
		}
		scopes = append(scopes, scope)
	}
	t.packageScopes = scopes
	if cacheable {
		t.module = t.moduleDigest()
	}
	return nil
}

// contentDigest hashes the exact bytes the checks are about to read. Hashing
// the content rather than a modification time is what makes a cache hit a
// statement about the code instead of a statement about the filesystem.
func (t *target) contentDigest(files []string) (string, error) {
	parts := make([]string, 0, len(files))
	for _, rel := range files {
		src, err := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(rel)))
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", rel, err)
		}
		fileSum := sha256.Sum256(src)
		parts = append(parts, rel+"\x00"+hex.EncodeToString(fileSum[:]))
	}
	return digestOf(parts), nil
}

// digestOf hashes a list of already-distinct strings. The separator is a byte
// none of them can contain, so no two different lists can spell one digest.
func digestOf(parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// headCacheable reports whether this target may read and write per-package
// answers.
//
// The base tree is excluded because its whole run is already cached as one
// snapshot; caching it again per package would store the same conclusions
// twice under two keys that can disagree.
func (t *target) headCacheable() bool {
	return !t.isBase && !t.engine.NoCache
}

// headKey renders one package's inputs into a content address.
//
// Everything that can change the answer is named: the harness and its
// decoration, the toolchain that formats, the module requirements that decide
// which imports resolve, the check being answered, and the files themselves.
func (e *Engine) headKey(kind string, pkg packageScope, moduleDigest string) string {
	parts := []string{
		"goharness=" + e.Version,
		"decoration=" + evidenceDecoration,
		"go=" + tool.GoVersion(),
		"config=" + e.ConfigDigest,
		"module=" + moduleDigest,
		"kind=" + kind,
		"dir=" + pkg.dir,
		"files=" + strings.Join(pkg.files, ","),
		"content=" + pkg.digest,
	}
	return digestOf(parts)
}

// moduleDigest hashes the module requirements.
//
// goimports resolves an unknown identifier against what the module can reach,
// so an edit to go.mod can change its answer for a file whose own bytes did not
// move. Absent files hash as absent, which is the honest reading for a module
// with no go.sum yet.
func (t *target) moduleDigest() string {
	names := []string{"go.mod", "go.sum"}
	parts := make([]string, 0, len(names))
	for _, name := range names {
		src, err := os.ReadFile(filepath.Join(t.root, name))
		if err != nil {
			parts = append(parts, name+"\x00absent")
			continue
		}
		fileSum := sha256.Sum256(src)
		parts = append(parts, name+"\x00"+hex.EncodeToString(fileSum[:]))
	}
	return digestOf(parts)
}

// headEntry wraps a cached answer with what is needed to distrust it.
//
// Integrity is a hash of the payload as it was written. The key addresses the
// inputs, so it cannot notice a value someone edited by hand; comparing the
// payload against its own recorded hash can, and a mismatch is treated as a
// miss rather than as an error, because a damaged cache must cost time and
// never a verdict.
type headEntry[T any] struct {
	Key       string `json:"key"`
	Goharness string `json:"goharness"`
	Integrity string `json:"integrity"`
	Payload   T      `json:"payload"`
}

func payloadIntegrity[T any](payload T) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return toolcache.Sum(encoded), nil
}

// readHeadEntry returns a cached payload, or reports that this run has to
// compute one. Every failure mode is a miss: an unreadable cache, an entry from
// another release, and a payload that does not match its own integrity hash.
func readHeadEntry[T any](e *Engine, kind, key string) (payload T, ok bool) {
	var zero T
	cache, err := toolcache.Open()
	if err != nil {
		return zero, false
	}
	var doc headEntry[T]
	if err := cache.ReadDerived(kind, key, &doc); err != nil {
		if !errors.Is(err, toolcache.ErrNotProvisioned) {
			e.Logger.Info("head evidence cache unreadable",
				zap.String("kind", kind), zap.String("key", key), zap.Error(err))
		}
		return zero, false
	}
	if doc.Goharness != e.Version || doc.Key != key {
		return zero, false
	}
	integrity, err := payloadIntegrity(doc.Payload)
	if err != nil || integrity != doc.Integrity {
		e.Logger.Info("head evidence entry failed its integrity check; recomputing",
			zap.String("kind", kind), zap.String("key", key))
		return zero, false
	}
	return doc.Payload, true
}

// writeHeadEntry stores one package's answer. Failing to store it costs the
// next run some time and nothing else, so the error is logged rather than
// raised, exactly as the base snapshot does it.
func writeHeadEntry[T any](e *Engine, kind, key string, payload T) {
	cache, err := toolcache.Open()
	if err != nil {
		return
	}
	integrity, err := payloadIntegrity(payload)
	if err != nil {
		return
	}
	doc := headEntry[T]{Key: key, Goharness: e.Version, Integrity: integrity, Payload: payload}
	if err := cache.WriteDerived(kind, key, doc, toolcache.MaxPerPackageEntries); err != nil {
		e.Logger.Info("head evidence not cached",
			zap.String("kind", kind), zap.String("key", key), zap.Error(err))
	}
}
