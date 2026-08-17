package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// baseEvidenceKind names the derived documents this file owns.
const baseEvidenceKind = "base-evidence"

// baseSnapshot is what running the checks over the base revision produced.
//
// Caching it is sound because every input is in the key: the base revision is a
// commit that cannot change, and the tools, the policy, the scope and the file
// set that produced the result are all named there too. A run in an agent's
// repair loop re-examines the same untouched base ten times over, and that is
// the single largest thing a verification pays for twice.
//
// The rule this bends is the one that says verifying writes nothing outside a
// temporary directory. The carve-out is deliberately narrow: derived evidence
// only, keyed by content, never a tool payload and never a vulnerability
// database, both of which stay the exclusive business of setup. `--no-cache`
// turns the whole thing off, and a run with it must reach the same verdict.
type baseSnapshot struct {
	Key          string                   `json:"key"`
	Goharness    string                   `json:"goharness"`
	Base         string                   `json:"base"`
	Evidence     []evidence.Evidence      `json:"evidence"`
	Failures     []CheckFailure           `json:"failures"`
	Unproducible []admission.Unproducible `json:"unproducible"`
	Produced     []admission.EvidenceKind `json:"produced"`
}

// baseCacheInput is everything the key has to cover: change the value of any
// field and the cached result stops describing this run.
type baseCacheInput struct {
	base         string
	packages     []string
	testPackages []string
	judged       []string
	exempt       []string
	checks       []string
	analyzeOpts  string
	configDigest string
}

// key renders the inputs into one content address. Fields are separated by a
// byte no field can contain, so no two different inputs can spell the same key.
func (e *Engine) baseCacheKey(in baseCacheInput) string {
	parts := []string{
		"goharness=" + e.Version,
		"go=" + tool.GoVersion(),
		"golangci=" + e.Golangci.Version + "@" + e.Golangci.SHA256,
		"xvuln=" + tool.XVulnVersion(),
		"goleak=" + leakcheck.Version,
		"config=" + in.configDigest,
		"base=" + in.base,
		"analyze=" + in.analyzeOpts,
		"packages=" + strings.Join(in.packages, ","),
		"tests=" + strings.Join(in.testPackages, ","),
		"judged=" + strings.Join(in.judged, ","),
		"exempt=" + strings.Join(in.exempt, ","),
		"checks=" + strings.Join(in.checks, ","),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// readBaseSnapshot returns a cached base result, or reports that there is none.
// A cache that cannot be read is not an error: the run recomputes and says so
// in the log, because a verdict must never depend on a cache being healthy.
func (e *Engine) readBaseSnapshot(key string) (runOutput, bool) {
	cache, err := toolcache.Open()
	if err != nil {
		return runOutput{}, false
	}
	var doc baseSnapshot
	if err := cache.ReadDerived(baseEvidenceKind, key, &doc); err != nil {
		if !errors.Is(err, toolcache.ErrNotProvisioned) {
			e.Logger.Info("base evidence cache unreadable", zap.String("key", key), zap.Error(err))
		}
		return runOutput{}, false
	}
	if doc.Goharness != e.Version {
		return runOutput{}, false
	}
	e.Logger.Info("base evidence reused", zap.String("key", key), zap.String("base", doc.Base))
	return runOutput{
		Evidence:     doc.Evidence,
		Failures:     doc.Failures,
		Unproducible: doc.Unproducible,
		Produced:     doc.Produced,
	}, true
}

// writeBaseSnapshot stores a base result. Failing to store one costs the next
// run some time and nothing else, so the error is logged rather than raised.
func (e *Engine) writeBaseSnapshot(key, base string, out runOutput) {
	cache, err := toolcache.Open()
	if err != nil {
		return
	}
	doc := baseSnapshot{
		Key: key, Goharness: e.Version, Base: base,
		Evidence: out.Evidence, Failures: out.Failures,
		Unproducible: out.Unproducible, Produced: out.Produced,
	}
	if err := cache.WriteDerived(baseEvidenceKind, key, doc); err != nil {
		e.Logger.Info("base evidence not cached", zap.String("key", key), zap.Error(err))
	}
}

// describeAnalyzeOptions renders the native scanners' configuration for the
// cache key. Every field of analyze.Options that can change a finding has to
// appear here, and a test in this package fails if the struct grows a field
// without this function growing with it.
func describeAnalyzeOptions(o analyze.Options) string {
	rules := make([]string, 0, len(o.Architecture.ForbiddenImports))
	for _, rule := range o.Architecture.ForbiddenImports {
		rules = append(rules, rule.From+">"+rule.Deny)
	}
	slices.Sort(rules)
	return fmt.Sprintf("concurrency=%t;network=%t;persistence=%t;module=%s;imports=%s",
		o.Concurrency, o.Network, o.Persistence,
		o.Architecture.ModulePath, strings.Join(rules, "|"))
}
