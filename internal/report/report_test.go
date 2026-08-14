package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/change"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

func sampleResult() verify.Result {
	return verify.Result{
		Decision: admission.AdmissionDecision{
			Verdict: admission.VerdictRejected,
			Reason:  "failing claims: policy-integrity",
			Claims: []admission.QualityClaim{
				{Dimension: admission.DimCorrectness, State: admission.ClaimPass, Reason: "4 obligation(s) discharged"},
				{Dimension: admission.DimPolicyIntegrity, State: admission.ClaimFail, Reason: "1 required violation(s): GH-SUPPRESS-001"},
				{Dimension: admission.DimPerformance, State: admission.ClaimNotApplicable, Reason: "no obligation"},
			},
			SufficientForCompletion: false,
		},
		Mode:       verify.ModeVerify,
		Repository: repo.Repository{ModulePath: "example.com/x", GoDirective: "1.26"},
		Contract:   admission.TaskContract{Source: admission.ContractFromDefault, Goal: "be admissible"},
		Risks:      admission.RiskProfile{Active: []admission.RiskDomain{admission.RiskTests}},
		Change: change.ChangeSet{
			Base: "abcdef1234567890", BaseOrigin: change.BaseFromParent, Files: []string{"a.go"},
		},
		Execution: verify.ExecutionPlan{
			Mode: verify.ModeVerify, Packages: []string{"example.com/x"}, Tests: []string{"example.com/x"},
		},
		Evidence: evidence.Finalize([]evidence.Evidence{{
			RuleID: policy.RuleSuppressNolint, File: "a.go", Line: 4, Column: 2,
			Message: "inline suppression directive", Severity: evidence.SeverityError,
			Classification: evidence.ClassificationRequired, State: evidence.StateNew,
			Tool: "goharness",
		}}),
		Golangci:     tool.Golangci{Version: tool.GolangciLintPin, Path: "/x/golangci-lint"},
		PolicyPacks:  []string{policy.PackAgentHygiene},
		BaseCompared: true,
		Duration:     3 * time.Second,
		CheckTimings: map[string]time.Duration{"native": time.Second},
	}
}

func TestSchemaIsVersionTwo(t *testing.T) {
	t.Parallel()
	if report.SchemaID != "goharness.report/v2" {
		t.Fatalf("schema = %q", report.SchemaID)
	}
}

func TestDocumentCarriesClaimsAndPins(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.2.0", sampleResult())
	if doc.Schema != report.SchemaID || doc.ExitCode != 1 {
		t.Fatalf("schema = %q exit = %d", doc.Schema, doc.ExitCode)
	}
	if doc.Versions.UberGuideCommit != policy.UberGuideCommit {
		t.Fatalf("uber commit = %q", doc.Versions.UberGuideCommit)
	}
	if len(doc.Claims) != 3 {
		t.Fatalf("claims = %+v", doc.Claims)
	}
	if doc.SufficientForCompletion {
		t.Fatal("a rejected run reported itself sufficient for completion")
	}
	if doc.Contract.Source != string(admission.ContractFromDefault) {
		t.Fatalf("contract source = %q", doc.Contract.Source)
	}
}

func TestClaimsAppearInTheJSONWithTheirStates(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "0.2.0", sampleResult()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var doc struct {
		Claims []struct {
			Dimension string `json:"dimension"`
			State     string `json:"state"`
			Reason    string `json:"reason"`
		} `json:"claims"`
		SufficientForCompletion bool `json:"sufficientForCompletion"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	states := map[string]string{}
	for _, c := range doc.Claims {
		states[c.Dimension] = c.State
		if c.Reason == "" {
			t.Fatalf("claim %s has no reason", c.Dimension)
		}
	}
	if states["correctness"] != "PASS" || states["policy-integrity"] != "FAIL" ||
		states["performance"] != "NOT_APPLICABLE" {
		t.Fatalf("claim states = %v", states)
	}
}

// TestDeterministicJSONExcludesTiming is what the determinism comparison relies
// on: everything except the timing block must be byte-stable.
func TestDeterministicJSONExcludesTiming(t *testing.T) {
	t.Parallel()
	first := sampleResult()
	second := sampleResult()
	second.Duration = 99 * time.Second
	second.CheckTimings = map[string]time.Duration{"native": 42 * time.Second}

	a, err := report.DeterministicJSON("0.2.0", first)
	if err != nil {
		t.Fatalf("DeterministicJSON: %v", err)
	}
	b, err := report.DeterministicJSON("0.2.0", second)
	if err != nil {
		t.Fatalf("DeterministicJSON: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("timing leaked into the deterministic portion of the report")
	}
	if !strings.Contains(string(a), "\"timing\"") {
		t.Fatal("the timing block is missing entirely; it should be present but empty")
	}
}

func TestJSONIncludesTimingWhenNotComparing(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "0.2.0", sampleResult()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "\"totalMs\": 3000") {
		t.Fatalf("the timing block does not carry the duration:\n%s", buf.String())
	}
}

func TestEmptyCollectionsRenderAsArrays(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "0.2.0", verify.Result{}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"evidence", "failures", "claims", "unmetObligations"} {
		if _, ok := doc[key].([]any); !ok {
			t.Fatalf("%s = %v, want an array rather than null", key, doc[key])
		}
	}
}

func TestTextReportLeadsWithTheVerdictAndClaims(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := report.WriteText(&buf, "0.2.0", sampleResult()); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "REJECTED") {
		t.Fatalf("the report does not lead with the verdict:\n%s", out)
	}
	for _, want := range []string{
		"quality claims:", "policy-integrity", "FAIL", "NOT_APPLICABLE",
		"evidence:", policy.RuleSuppressNolint, "a.go:4:2",
		"run: goharness explain " + policy.RuleSuppressNolint,
		"next steps",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("text report is missing %q:\n%s", want, out)
		}
	}
}

func TestQuietReportIsJustTheVerdictLine(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := report.WriteTextWithOptions(&buf, "0.2.0", sampleResult(), report.TextOptions{Quiet: true})
	if err != nil {
		t.Fatalf("WriteTextWithOptions: %v", err)
	}
	if lines := strings.Count(strings.TrimSpace(buf.String()), "\n"); lines != 0 {
		t.Fatalf("quiet output has %d extra lines:\n%s", lines, buf.String())
	}
}

func TestFastReportSaysItIsNotAGate(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.Mode = verify.ModeFast
	var buf bytes.Buffer
	if err := report.WriteText(&buf, "0.2.0", result); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "not an admission gate") {
		t.Fatalf("fast does not disclaim being a gate:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "goharness verify --agent") {
		t.Fatalf("fast does not point at the gate command:\n%s", buf.String())
	}
}

func TestInconclusiveReportNamesTheMissingEvidence(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.Decision.Verdict = admission.VerdictInconclusive
	result.Unproducible = []admission.Unproducible{{
		Kind:   admission.KindBenchDelta,
		Reason: "no benchmark ran at both base and head",
		Remedy: "add a Benchmark function to the changed package",
	}}
	var buf bytes.Buffer
	if err := report.WriteText(&buf, "0.2.0", result); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"bench-delta", "no benchmark ran", "to produce it: add a Benchmark"} {
		if !strings.Contains(out, want) {
			t.Fatalf("inconclusive report is missing %q:\n%s", want, out)
		}
	}
}

func TestColourIsOptIn(t *testing.T) {
	t.Parallel()
	var plain, coloured bytes.Buffer
	if err := report.WriteText(&plain, "0.2.0", sampleResult()); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	err := report.WriteTextWithOptions(&coloured, "0.2.0", sampleResult(),
		report.TextOptions{Palette: report.Palette{Enabled: true}})
	if err != nil {
		t.Fatalf("WriteTextWithOptions: %v", err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatal("plain output contains escape sequences")
	}
	if !strings.Contains(coloured.String(), "\x1b[") {
		t.Fatal("colour was requested but no escape sequences were emitted")
	}
}

func TestVulnDBBlockAppearsAndStaysDeterministic(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.VulnDB = &toolcache.VulnDBManifest{
		Source:       "https://vuln.go.dev",
		Modified:     time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		FetchedAt:    time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC),
		TreeChecksum: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		EntryCount:   1721,
	}
	doc := report.Build("0.3.0", result)
	if doc.VulnDB == nil {
		t.Fatal("the vulnDb block is missing when the scanner ran")
	}
	if doc.VulnDB.EntryCount != 1721 || doc.VulnDB.Source != "https://vuln.go.dev" {
		t.Fatalf("vulnDb = %+v", doc.VulnDB)
	}
	if doc.VulnDB.Modified != "2026-08-01T12:00:00Z" {
		t.Fatalf("modified = %q, want an RFC3339 stamp", doc.VulnDB.Modified)
	}

	// Every field is fixed for the life of a snapshot, so two renders separated
	// by real time must still be byte-identical.
	first, err := report.DeterministicJSON("0.3.0", result)
	if err != nil {
		t.Fatalf("DeterministicJSON: %v", err)
	}
	later := result
	later.Duration = 99 * time.Second
	second, err := report.DeterministicJSON("0.3.0", later)
	if err != nil {
		t.Fatalf("DeterministicJSON: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("the vulnDb block is not stable across renders")
	}
	if !bytes.Contains(first, []byte(`"treeChecksum"`)) {
		t.Fatal("the deterministic portion does not carry the snapshot checksum")
	}
	for _, volatile := range []string{"ageDays", "age_days", "daysOld"} {
		if bytes.Contains(first, []byte(volatile)) {
			t.Fatalf("a derived age leaked into the deterministic JSON: %s", volatile)
		}
	}
}

func TestVulnDBBlockIsAbsentWhenNoScanRan(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.3.0", sampleResult())
	if doc.VulnDB != nil {
		t.Fatalf("a run with no scan reported a database: %+v", doc.VulnDB)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "0.3.0", sampleResult()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.Contains(buf.String(), "vulnDb") {
		t.Fatalf("the vulnDb key is present without a scan:\n%s", buf.String())
	}
}

func TestVersionsBlockCarriesTheEmbeddedScanner(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.3.0", sampleResult())
	if doc.Versions.XVuln == "" {
		t.Fatal("the versions block does not record the embedded scanner")
	}
	if doc.Versions.XVuln != tool.XVulnVersion() {
		t.Fatalf("xVuln = %q, want %q", doc.Versions.XVuln, tool.XVulnVersion())
	}
}

func TestTextReportShowsSnapshotAgeButJSONDoesNot(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.VulnDB = &toolcache.VulnDBManifest{
		Source:       "https://vuln.go.dev",
		Modified:     time.Now().UTC().Add(-30 * 24 * time.Hour),
		FetchedAt:    time.Now().UTC(),
		TreeChecksum: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		EntryCount:   12,
	}
	var buf bytes.Buffer
	if err := report.WriteText(&buf, "0.3.0", result); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "vuln database: 12 entries") {
		t.Fatalf("the text report omits the database:\n%s", out)
	}
	if !strings.Contains(out, "day(s) ago") {
		t.Fatalf("the text report omits the age:\n%s", out)
	}
	if !strings.Contains(out, "goharness tools update") {
		t.Fatalf("a stale database does not prompt an update:\n%s", out)
	}
}
