// Package report renders a verification result as human-readable text or as the
// versioned goharness.report/v2 JSON document.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// SchemaID identifies the JSON report format. Consumers must reject unknown
// schema identifiers rather than guess. v2 adds the claims table, the task
// contract, the risk profile, and the obligation set.
const SchemaID = "goharness.report/v2"

// Document is the JSON report. Everything outside the Timing block is
// deterministic: two runs over an unchanged tree produce identical bytes.
type Document struct {
	Schema                  string                       `json:"schema"`
	Verdict                 string                       `json:"verdict"`
	ExitCode                int                          `json:"exitCode"`
	Mode                    string                       `json:"mode"`
	AdmissionGate           bool                         `json:"admissionGate"`
	SufficientForCompletion bool                         `json:"sufficientForCompletion"`
	Reason                  string                       `json:"reason"`
	Versions                Versions                     `json:"versions"`
	Module                  Module                       `json:"module"`
	Contract                Contract                     `json:"contract"`
	Risks                   Risks                        `json:"risks"`
	Policy                  PolicyInfo                   `json:"policy"`
	VulnDB                  *VulnDB                      `json:"vulnDb,omitempty"`
	Change                  ChangeInfo                   `json:"change"`
	Plan                    PlanInfo                     `json:"plan"`
	Claims                  []admission.QualityClaim     `json:"claims"`
	UnmetObligations        []admission.RequiredEvidence `json:"unmetObligations"`
	Unproducible            []Unproducible               `json:"unproducible"`
	Summary                 Summary                      `json:"summary"`
	Coverage                Coverage                     `json:"coverage"`
	// Baseline is the burn-down of the acknowledged-debt ledger, present only in
	// an audit that read one. Absent everywhere else, so a report from a run with
	// no ledger is byte-for-byte what it always was.
	Baseline *Baseline `json:"baseline,omitempty"`
	// PolicyShadow is what the repository's own lint configuration hides from
	// itself. A section, never a claim: it is absent from every verdict, every
	// count, and every exit code.
	PolicyShadow *PolicyShadow `json:"policyShadow,omitempty"`
	Evidence     []Finding     `json:"evidence"`
	// EvidenceTruncated says the evidence list is a selection rather than the
	// whole set, and EvidenceOmitted says how much is missing. Truncation is
	// always declared: a consumer must never have to guess whether it holds the
	// complete enumeration, because the enumeration being complete is the whole
	// reason to trust it.
	EvidenceTruncated bool `json:"evidenceTruncated"`
	EvidenceOmitted   int  `json:"evidenceOmitted"`
	// EvidenceScope names the view evidence[] is a selection under, so a consumer
	// reading a short list knows whether it is short because the run was clean or
	// because the rendering asked a narrower question.
	EvidenceScope string                `json:"evidenceScope"`
	Failures      []verify.CheckFailure `json:"failures"`
	Timing        Timing                `json:"timing"`
}

// Scope selects which findings a rendering carries.
//
// Like EvidenceLimit it is rendering only: the verdict, the claims, and every
// count in Summary are computed over the whole evidence set before any of this
// applies. What it changes is how much a reader has to read, never what they
// have to fix.
type Scope string

// Evidence scopes. The zero value renders everything, so a caller that does not
// care gets the complete document.
const (
	ScopeFull Scope = "full"
	ScopeDiff Scope = "diff"
	ScopeNew  Scope = "new"
)

// orFull resolves the zero value, which is the complete set.
func (s Scope) orFull() Scope {
	if s == "" {
		return ScopeFull
	}
	return s
}

// Keeps reports whether one finding survives this scope.
//
// A blocking finding survives every scope without exception: a view that could
// hide the row that decided the verdict would be a way to be admitted by not
// looking, and no rendering flag may ever be that. A finding the run could not
// place against the diff survives too, because unplaced is not the same as
// irrelevant and the honest treatment of what the harness does not know is to
// show it.
//
// What diff drops is debt the run placed away from the change: a package the
// author never opened, or a sibling file of one they did. Those are the rows a
// reverse-dependency closure produces in the thousands, and they are the reason
// this scope exists.
func (s Scope) Keeps(e evidence.Evidence) bool {
	if verify.Blocking(e) || e.State == evidence.StateNew || e.State == evidence.StateFixed {
		return true
	}
	switch s.orFull() {
	case ScopeNew:
		return false
	case ScopeDiff:
		return !e.Origin.OutsideChange()
	default:
		return true
	}
}

// Summary is the aggregation every consumer of this document rebuilds by hand.
//
// The counts are over the same final evidence set the document carries, so a
// truncated rendering still reports the totals of the run rather than of what
// survived truncation. Blocking and Advisory partition the set on the predicate
// the verdict itself used; New, Preexisting and Fixed partition it on the base
// comparison, and are all zero when there was none.
type Summary struct {
	Total         int            `json:"total"`
	Blocking      int            `json:"blocking"`
	Advisory      int            `json:"advisory"`
	New           int            `json:"new"`
	Preexisting   int            `json:"preexisting"`
	Fixed         int            `json:"fixed"`
	ByConsequence map[string]int `json:"byConsequence"`
	ByRule        map[string]int `json:"byRule"`
	ByDimension   map[string]int `json:"byDimension"`
	ByRemedyClass map[string]int `json:"byRemedyClass"`
	ByFile        map[string]int `json:"byFile"`
}

// Coverage states what the verdict does and does not rest on.
//
// The harness already refuses to claim what it did not prove; this is the other
// half of that discipline, which is stating what it did not look at. An
// ADMITTED whose scope is invisible cannot be audited by the person who has to
// stand behind it. Head only: the base tree is an input to a comparison, not
// something this run makes a claim about.
type Coverage struct {
	PackageCount         int      `json:"packageCount"`
	Packages             []string `json:"packages"`
	FilesJudged          int      `json:"filesJudged"`
	GeneratedExemptCount int      `json:"generatedExemptCount"`
	GeneratedExempt      []string `json:"generatedExempt"`
	TestPackageCount     int      `json:"testPackageCount"`
	TestPackages         []string `json:"testPackages"`
	// LeakInjectionBlocked names the test packages whose own TestMain kept the
	// goroutine-leak detector out. It was reachable only as prose inside an
	// unproducible reason, which is not somewhere a consumer can act on.
	LeakInjectionBlocked []string `json:"leakInjectionBlocked"`
	// LocalScanNarrowed says the file-local scanners examined only the package
	// directories the change touched, and LocalScanPackages names them. They may,
	// because a directory identical at base and head produces identical findings
	// at both and so can contribute neither a new nor a fixed one; what the
	// narrowing removes is pre-existing rows. Compilation, vet, golangci-lint,
	// the tests and the vulnerability scan always see the whole scope, because a
	// change in one package can create a genuine new finding in another.
	LocalScanNarrowed bool     `json:"localScanNarrowed"`
	LocalScanPackages []string `json:"localScanPackages"`
}

// Baseline is the burn-down of an acknowledged-debt ledger.
//
// A ratchet is only honest while its progress is visible. Without these counts
// a ledger that never shrinks looks exactly like one that is being worked down,
// and a repository could sit at ADMITTED for years on the strength of a
// document nobody reads. Recorded is the revision the ledger names; a reader
// who finds it far behind head is looking at a stagnant ratchet.
type Baseline struct {
	RecordedAt   string `json:"recordedAt"`
	Entries      int    `json:"entries"`
	StillPresent int    `json:"stillPresent"`
	FixedSince   int    `json:"fixedSince"`
	// New counts the blocking findings the ledger does not acknowledge. It is the
	// number that has to be zero, and the bar it measures never moves.
	New int `json:"new"`
	// Unbaselineable counts the blocking findings whose rules can never be
	// acknowledged by any ledger: suppressions, the policy guards, generated
	// prose. They are why an entry for one of them has no effect.
	Unbaselineable int `json:"unbaselineable"`
}

// PolicyShadow is the repository's own lint configuration measured against the
// strict pack.
type PolicyShadow struct {
	File     string        `json:"file"`
	Analysed bool          `json:"analysed"`
	Reason   string        `json:"reason,omitempty"`
	Entries  []ShadowEntry `json:"entries"`
}

// ShadowEntry is one detected mechanism and the findings behind it.
type ShadowEntry struct {
	ID        string   `json:"id"`
	Mechanism string   `json:"mechanism"`
	Detail    string   `json:"detail"`
	RuleIDs   []string `json:"ruleIds"`
	// Attributed says whether FindingsInShadow is exact. Where it is false the
	// count is zero and Note says why no exact one exists.
	Attributed       bool   `json:"attributed"`
	FindingsInShadow int    `json:"findingsInShadow"`
	Note             string `json:"note,omitempty"`
}

// Finding is one piece of evidence as the protocol presents it: the finding
// itself, plus whether it can fail its claim. Without that flag a consumer has
// to re-derive the harness's grandfathering rules to know what to fix first,
// and an agent that guesses wrong either ignores a blocker or chases debt it
// did not create.
type Finding struct {
	evidence.Evidence
	Blocking bool `json:"blocking"`
}

// Unproducible is one obligation the run could not discharge, with the action
// that would let the next run discharge it. It is what makes an INCONCLUSIVE
// verdict actionable rather than merely honest.
type Unproducible struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Remedy string `json:"remedy,omitempty"`
}

// Versions records every pin that could change a verdict.
type Versions struct {
	Goharness string `json:"goharness"`
	Go        string `json:"go"`
	// GoStdlib is the toolchain the checks actually ran against, which for the
	// security claim is the standard library that was judged. It can differ from
	// Go, which is the toolchain this binary was built with, and two runs that
	// disagree about it are not comparable however alike the rest looks.
	GoStdlib            string `json:"goStdlib"`
	GolangciLint        string `json:"golangciLint"`
	GolangciLintPin     string `json:"golangciLintPin"`
	GolangciLintMatches bool   `json:"golangciLintMatchesPin"`
	GolangciLintSHA256  string `json:"golangciLintSha256"`
	XVuln               string `json:"xVuln"`
	Goleak              string `json:"goleak"`
	UberGuideCommit     string `json:"uberGuideCommit"`
}

// VulnDB records which vulnerability database snapshot produced the security
// evidence. Every field is fixed for the life of a snapshot, so including it
// keeps repeated runs byte-identical; the derived age belongs to the human
// report only.
type VulnDB struct {
	Source       string `json:"source"`
	Modified     string `json:"modified"`
	FetchedAt    string `json:"fetchedAt"`
	TreeChecksum string `json:"treeChecksum"`
	EntryCount   int    `json:"entryCount"`
}

// Module identifies the module under verification.
type Module struct {
	Path        string `json:"path"`
	GoDirective string `json:"goDirective"`
}

// Contract is the task contract the run was judged against. Authenticated
// records whether its grants came from the base revision; IgnoredGrants names
// the permissions the working tree asked for and did not receive.
type Contract struct {
	Source          string   `json:"source"`
	Goal            string   `json:"goal,omitempty"`
	DeclaredScope   []string `json:"declaredScope"`
	DeclaredRisks   []string `json:"declaredRisks"`
	AllowAPIBreak   bool     `json:"allowApiBreak"`
	AllowPolicyEdit bool     `json:"allowPolicyEdit"`
	Authenticated   bool     `json:"authenticated"`
	IgnoredGrants   []string `json:"ignoredGrants"`
}

// Risks records which risk domains were active and why.
type Risks struct {
	Active  []string            `json:"active"`
	Reasons map[string][]string `json:"reasons"`
}

// PolicyInfo records the composed policy packs.
type PolicyInfo struct {
	Packs []string `json:"packs"`
}

// ChangeInfo records how scope was derived.
type ChangeInfo struct {
	Base         string   `json:"base,omitempty"`
	BaseOrigin   string   `json:"baseOrigin"`
	BaseCompared bool     `json:"baseCompared"`
	FullScope    bool     `json:"fullScope"`
	Files        []string `json:"files"`
	// OutsideModule names changed files the repository contains and the module
	// does not. In a monorepo their absence from Files is a decision, and a
	// reader cannot audit a decision that leaves no trace.
	OutsideModule []string `json:"outsideModule"`
}

// PlanInfo records the obligations and the checks that discharge them.
type PlanInfo struct {
	Obligations  []admission.RequiredEvidence `json:"obligations"`
	Checks       []string                     `json:"checks"`
	Tools        []string                     `json:"tools"`
	Packages     []string                     `json:"packages"`
	TestPackages []string                     `json:"testPackages"`
	Skipped      []string                     `json:"skipped"`
}

// Timing is the only non-deterministic block; determinism comparisons exclude
// it by name.
type Timing struct {
	TotalMs  int64            `json:"totalMs"`
	ChecksMs map[string]int64 `json:"checksMs"`
}

// Options tune the rendering only. Nothing here can change the verdict, the
// claims, or the counts: they are computed from the whole evidence set before
// any of this applies.
type Options struct {
	// EvidenceLimit truncates evidence[] to the highest-consequence findings.
	// Zero or negative means the complete set, which stays the default.
	EvidenceLimit int
	// Scope selects which findings evidence[] carries. The zero value is the
	// complete set.
	Scope Scope
}

// Build converts a verification result into the complete JSON document.
func Build(version string, r verify.Result) Document {
	return BuildWithOptions(version, r, Options{})
}

// BuildWithOptions converts a verification result into the JSON document,
// applying any rendering limits after the document is complete.
func BuildWithOptions(version string, r verify.Result, opts Options) Document {
	doc := buildFull(version, r)
	doc = applyScope(doc, opts.Scope)
	return truncateEvidence(doc, opts.EvidenceLimit)
}

// applyScope narrows evidence[] to one view and records both the view and what
// it withheld. Omission is always declared: a consumer must never have to guess
// whether it holds the complete enumeration, because the enumeration being
// complete is the whole reason to trust it.
func applyScope(doc Document, scope Scope) Document {
	doc.EvidenceScope = string(scope.orFull())
	if scope.orFull() == ScopeFull {
		return doc
	}
	kept := make([]Finding, 0, len(doc.Evidence))
	for _, f := range doc.Evidence {
		if scope.Keeps(f.Evidence) {
			kept = append(kept, f)
		}
	}
	if omitted := len(doc.Evidence) - len(kept); omitted > 0 {
		doc.EvidenceOmitted += omitted
		doc.EvidenceTruncated = true
	}
	doc.Evidence = kept
	return doc
}

// truncateEvidence keeps the highest-consequence findings and says how many it
// dropped. The evidence set is already in consequence order, so "the top" needs
// no second sort and means the same thing every run.
func truncateEvidence(doc Document, limit int) Document {
	if limit <= 0 || len(doc.Evidence) <= limit {
		return doc
	}
	doc.EvidenceOmitted += len(doc.Evidence) - limit
	doc.EvidenceTruncated = true
	doc.Evidence = doc.Evidence[:limit]
	return doc
}

func buildFull(version string, r verify.Result) Document {
	decision := r.Decision
	findings := buildFindings(r.Evidence)
	return Document{
		Schema:                  SchemaID,
		Verdict:                 string(decision.Verdict),
		ExitCode:                decision.Verdict.ExitCode(),
		Mode:                    string(r.Mode),
		AdmissionGate:           r.Mode.IsAdmissionGate(),
		SufficientForCompletion: decision.SufficientForCompletion,
		Reason:                  decision.Reason,
		Versions: Versions{
			Goharness:           version,
			Go:                  tool.GoVersion(),
			GoStdlib:            r.GoVersion,
			GolangciLint:        r.Golangci.Version,
			GolangciLintPin:     tool.GolangciLintPin,
			GolangciLintMatches: r.Golangci.MatchesPin(),
			GolangciLintSHA256:  r.Golangci.SHA256,
			XVuln:               tool.XVulnVersion(),
			Goleak:              leakcheck.Version,
			UberGuideCommit:     policy.UberGuideCommit,
		},
		Module:           Module{Path: r.Repository.ModulePath, GoDirective: r.Repository.GoDirective},
		Contract:         buildContract(r.Contract),
		Risks:            buildRisks(r.Risks),
		Policy:           PolicyInfo{Packs: nonNil(r.PolicyPacks)},
		VulnDB:           buildVulnDB(r),
		Change:           buildChange(r),
		Plan:             buildPlan(r),
		Claims:           normalizeClaims(decision.Claims),
		UnmetObligations: nonNilObligations(decision.UnmetObligations),
		Unproducible:     buildUnproducible(r.Unproducible),
		Summary:          buildSummary(findings),
		Coverage:         buildCoverage(r),
		Baseline:         buildBaseline(r.Debt, findings),
		PolicyShadow:     buildPolicyShadow(r.PolicyShadow),
		Evidence:         findings,
		Failures:         nonNilFailures(r.Failures),
		Timing:           buildTiming(r),
	}
}

func buildSummary(findings []Finding) Summary {
	s := Summary{
		Total:         len(findings),
		ByConsequence: map[string]int{},
		ByRule:        map[string]int{},
		ByDimension:   map[string]int{},
		ByRemedyClass: map[string]int{},
		ByFile:        map[string]int{},
	}
	for _, f := range findings {
		if f.Blocking {
			s.Blocking++
		} else {
			s.Advisory++
		}
		switch f.State {
		case evidence.StateNew:
			s.New++
		case evidence.StatePreexisting:
			s.Preexisting++
		case evidence.StateFixed:
			s.Fixed++
		case evidence.StateUncompared:
		}
		s.ByRule[f.RuleID]++
		if f.Consequence != "" {
			s.ByConsequence[f.Consequence]++
		}
		if f.RemedyClass != "" {
			s.ByRemedyClass[f.RemedyClass]++
		}
		if dim, ok := admission.DimensionOf(f.RuleID); ok {
			s.ByDimension[string(dim)]++
		}
		if f.File != "" {
			s.ByFile[f.File]++
		}
	}
	return s
}

// buildBaseline measures the ledger against this run.
//
// Fixed findings are counted as a set difference over fingerprints and nothing
// cleverer. Occurrence indexes make identical findings distinguishable in
// identity order, so removing one of several leaves the survivors named exactly
// as they were and the last index is the one that disappears; any counting rule
// that tried to be smarter than "this fingerprint is no longer here" would be
// counting something other than what the ledger recorded.
func buildBaseline(ledger *policy.DebtLedger, findings []Finding) *Baseline {
	if ledger == nil {
		return nil
	}
	acknowledged := ledger.Fingerprints()
	present := make(map[string]bool, len(findings))
	out := &Baseline{RecordedAt: ledger.RecordedAt, Entries: len(ledger.Entries)}
	for _, f := range findings {
		present[f.Fingerprint] = true
		if !f.Blocking {
			continue
		}
		if !acknowledged[f.Fingerprint] {
			out.New++
		}
		if policy.IsUngrandfatherable(f.RuleID) {
			out.Unbaselineable++
		}
	}
	for _, e := range ledger.Entries {
		if present[e.Fingerprint] {
			out.StillPresent++
		}
	}
	out.FixedSince = out.Entries - out.StillPresent
	return out
}

func buildPolicyShadow(s *verify.PolicyShadow) *PolicyShadow {
	if s == nil {
		return nil
	}
	entries := make([]ShadowEntry, 0, len(s.Entries))
	for _, e := range s.Entries {
		entries = append(entries, ShadowEntry{
			ID: e.ID, Mechanism: e.Mechanism, Detail: e.Detail,
			RuleIDs: nonNil(e.RuleIDs), Attributed: e.Attributed,
			FindingsInShadow: e.Findings, Note: e.Note,
		})
	}
	return &PolicyShadow{File: s.File, Analysed: s.Analysed, Reason: s.Reason, Entries: entries}
}

func buildCoverage(r verify.Result) Coverage {
	return Coverage{
		PackageCount:         len(r.Execution.Packages),
		Packages:             nonNil(r.Execution.Packages),
		FilesJudged:          len(r.Execution.Files),
		GeneratedExemptCount: len(r.GeneratedExempt),
		GeneratedExempt:      nonNil(r.GeneratedExempt),
		TestPackageCount:     len(r.Execution.Tests),
		TestPackages:         nonNil(r.Execution.Tests),
		LeakInjectionBlocked: nonNil(r.LeakBlockedPackages),
		LocalScanNarrowed:    r.Execution.LocalScope != nil,
		LocalScanPackages:    nonNil(r.Execution.LocalScope),
	}
}

func buildContract(c admission.TaskContract) Contract {
	risks := make([]string, 0, len(c.DeclaredRisks))
	for _, domain := range c.DeclaredRisks {
		risks = append(risks, string(domain))
	}
	return Contract{
		Source:          string(c.Source),
		Goal:            c.Goal,
		DeclaredScope:   nonNil(c.DeclaredScope),
		DeclaredRisks:   risks,
		AllowAPIBreak:   c.AllowAPIBreak,
		AllowPolicyEdit: c.AllowPolicyEdit,
		Authenticated:   c.Authenticated,
		IgnoredGrants:   nonNil(c.IgnoredGrants),
	}
}

func buildRisks(p admission.RiskProfile) Risks {
	active := make([]string, 0, len(p.Active))
	for _, domain := range p.Active {
		active = append(active, string(domain))
	}
	reasons := p.AllReasons()
	if reasons == nil {
		reasons = map[string][]string{}
	}
	return Risks{Active: active, Reasons: reasons}
}

func buildVulnDB(r verify.Result) *VulnDB {
	if r.VulnDB == nil {
		return nil
	}
	return &VulnDB{
		Source:       r.VulnDB.Source,
		Modified:     r.VulnDB.Modified.UTC().Format(time.RFC3339),
		FetchedAt:    r.VulnDB.FetchedAt.UTC().Format(time.RFC3339),
		TreeChecksum: r.VulnDB.TreeChecksum,
		EntryCount:   r.VulnDB.EntryCount,
	}
}

func buildChange(r verify.Result) ChangeInfo {
	return ChangeInfo{
		Base:          r.Change.Base,
		BaseOrigin:    string(r.Change.BaseOrigin),
		BaseCompared:  r.BaseCompared,
		FullScope:     r.Change.FullScope,
		Files:         nonNil(r.Change.Files),
		OutsideModule: nonNil(r.Change.OutsideModule),
	}
}

func buildPlan(r verify.Result) PlanInfo {
	return PlanInfo{
		Obligations:  nonNilObligations(r.Plan.Obligations),
		Checks:       nonNil(r.Execution.CheckIDs()),
		Tools:        nonNil(r.Execution.Tools()),
		Packages:     nonNil(r.Execution.Packages),
		TestPackages: nonNil(r.Execution.Tests),
		Skipped:      nonNil(r.Skipped),
	}
}

func buildTiming(r verify.Result) Timing {
	checks := map[string]int64{}
	for id, d := range r.CheckTimings {
		checks[id] = d.Milliseconds()
	}
	return Timing{TotalMs: r.Duration.Milliseconds(), ChecksMs: checks}
}

// normalizeClaims guarantees every slice inside a claim is non-nil, so the JSON
// shape never varies with whether a claim happened to have findings.
func normalizeClaims(claims []admission.QualityClaim) []admission.QualityClaim {
	out := make([]admission.QualityClaim, 0, len(claims))
	for _, c := range claims {
		c.EvidenceRefs = nonNil(c.EvidenceRefs)
		if c.MissingEvidence == nil {
			c.MissingEvidence = []admission.EvidenceKind{}
		}
		out = append(out, c)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// buildFindings marks each finding with whether it blocks, using the same
// predicate the verdict itself was decided by.
func buildFindings(items []evidence.Evidence) []Finding {
	out := make([]Finding, 0, len(items))
	for _, e := range items {
		out = append(out, Finding{Evidence: e, Blocking: verify.Blocking(e)})
	}
	return out
}

func buildUnproducible(items []admission.Unproducible) []Unproducible {
	out := make([]Unproducible, 0, len(items))
	for _, u := range items {
		out = append(out, Unproducible{Kind: string(u.Kind), Reason: u.Reason, Remedy: u.Remedy})
	}
	slices.SortFunc(out, func(a, b Unproducible) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	return out
}

func nonNilFailures(s []verify.CheckFailure) []verify.CheckFailure {
	if s == nil {
		return []verify.CheckFailure{}
	}
	return s
}

func nonNilObligations(s []admission.RequiredEvidence) []admission.RequiredEvidence {
	if s == nil {
		return []admission.RequiredEvidence{}
	}
	return s
}

// WriteJSON renders the complete JSON report.
func WriteJSON(w io.Writer, version string, r verify.Result) error {
	return WriteJSONWithOptions(w, version, r, Options{})
}

// WriteJSONWithOptions renders the JSON report under rendering limits.
func WriteJSONWithOptions(w io.Writer, version string, r verify.Result, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(BuildWithOptions(version, r, opts)); err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	return nil
}

// DeterministicJSON renders the report with the timing block removed, which is
// what determinism comparisons and golden tests should use.
func DeterministicJSON(version string, r verify.Result) ([]byte, error) {
	doc := Build(version, r)
	doc.Timing = Timing{ChecksMs: map[string]int64{}}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding deterministic report: %w", err)
	}
	return encoded, nil
}

// EvidenceCounts summarises the evidence set by comparison state.
func EvidenceCounts(items []evidence.Evidence) (newFindings, preexisting, fixed, advisory int) {
	for _, e := range items {
		switch {
		case e.State == evidence.StateFixed:
			fixed++
		case !verify.Blocking(e) && e.Classification == evidence.ClassificationAdvisory:
			advisory++
		case e.State == evidence.StatePreexisting:
			preexisting++
		default:
			newFindings++
		}
	}
	return newFindings, preexisting, fixed, advisory
}
