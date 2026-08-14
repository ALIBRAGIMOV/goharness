// Package report renders a verification result as human-readable text or as the
// versioned goharness.report/v2 JSON document.
package report

import (
	"encoding/json"
	"fmt"
	"io"
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
	Evidence                []evidence.Evidence          `json:"evidence"`
	Failures                []verify.CheckFailure        `json:"failures"`
	Timing                  Timing                       `json:"timing"`
}

// Versions records every pin that could change a verdict.
type Versions struct {
	Goharness           string `json:"goharness"`
	Go                  string `json:"go"`
	GolangciLint        string `json:"golangciLint"`
	GolangciLintPin     string `json:"golangciLintPin"`
	GolangciLintMatches bool   `json:"golangciLintMatchesPin"`
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

// Contract is the task contract the run was judged against.
type Contract struct {
	Source        string   `json:"source"`
	Goal          string   `json:"goal,omitempty"`
	DeclaredScope []string `json:"declaredScope"`
	DeclaredRisks []string `json:"declaredRisks"`
	AllowAPIBreak bool     `json:"allowApiBreak"`
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

// Build converts a verification result into the JSON document.
func Build(version string, r verify.Result) Document {
	decision := r.Decision
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
			GolangciLint:        r.Golangci.Version,
			GolangciLintPin:     tool.GolangciLintPin,
			GolangciLintMatches: r.Golangci.MatchesPin(),
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
		Evidence:         nonNilEvidence(r.Evidence),
		Failures:         nonNilFailures(r.Failures),
		Timing:           buildTiming(r),
	}
}

func buildContract(c admission.TaskContract) Contract {
	risks := make([]string, 0, len(c.DeclaredRisks))
	for _, domain := range c.DeclaredRisks {
		risks = append(risks, string(domain))
	}
	return Contract{
		Source:        string(c.Source),
		Goal:          c.Goal,
		DeclaredScope: nonNil(c.DeclaredScope),
		DeclaredRisks: risks,
		AllowAPIBreak: c.AllowAPIBreak,
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
		Base:         r.Change.Base,
		BaseOrigin:   string(r.Change.BaseOrigin),
		BaseCompared: r.BaseCompared,
		FullScope:    r.Change.FullScope,
		Files:        nonNil(r.Change.Files),
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

func nonNilEvidence(s []evidence.Evidence) []evidence.Evidence {
	if s == nil {
		return []evidence.Evidence{}
	}
	return s
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

// WriteJSON renders the JSON report.
func WriteJSON(w io.Writer, version string, r verify.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(Build(version, r)); err != nil {
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
