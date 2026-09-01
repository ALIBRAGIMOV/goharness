package report_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
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
	for _, key := range []string{
		"evidence", "failures", "claims", "unmetObligations", "summary", "coverage",
	} {
		if key == "summary" || key == "coverage" {
			if _, ok := doc[key].(map[string]any); !ok {
				t.Fatalf("%s = %v, want an object rather than null", key, doc[key])
			}
			continue
		}
		if _, ok := doc[key].([]any); !ok {
			t.Fatalf("%s = %v, want an array rather than null", key, doc[key])
		}
	}
}

// summaryFixture is an evidence set with one finding of each consequence class,
// two of them in the same file, so every aggregation the summary reports has
// something to count.
func summaryFixture(t *testing.T) verify.Result {
	t.Helper()
	r := sampleResult()
	r.Evidence = evidence.Finalize(decorated(defaultPolicy(t), []evidence.Evidence{
		{RuleID: policy.RuleErrcheck, File: "store.go", Line: 20, Tool: "golangci-lint",
			Message: "Error return value of `s.store.Audit` is not checked", State: evidence.StateNew},
		{RuleID: policy.RuleErrcheck, File: "store.go", Line: 30, Tool: "golangci-lint",
			Message: "Error return value of `rows.Close` is not checked", State: evidence.StatePreexisting},
		{RuleID: policy.RuleCommentEmDash, File: "doc.go", Line: 3, Tool: "goharness",
			Message: "comment contains the em dash", State: evidence.StateNew},
		{RuleID: policy.RuleGoroutineLeak, Package: "example.com/x/server", Tool: "runtime/pprof",
			Message: "tests leave goroutines running", State: evidence.StateFixed},
	}))
	r.Execution.Files = []string{"store.go", "doc.go"}
	r.GeneratedExempt = []string{"api.pb.go"}
	r.LeakBlockedPackages = []string{"example.com/x/legacy"}
	return r
}

func defaultPolicy(t *testing.T) policy.ResolvedPolicy {
	t.Helper()
	resolved, err := policy.Resolve(policy.Config{}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("resolving the default policy: %v", err)
	}
	return resolved
}

func decorated(p policy.ResolvedPolicy, items []evidence.Evidence) []evidence.Evidence {
	out := make([]evidence.Evidence, 0, len(items))
	for _, e := range items {
		out = append(out, p.Decorate(e))
	}
	return out
}

// TestEvidenceIsOrderedByConsequence pins the property the document's readers
// depend on: position in evidence[] is triage order, so a consumer that works
// the list top down meets the silent data loss before the typography.
func TestEvidenceIsOrderedByConsequence(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.6.0", summaryFixture(t))
	var got []string
	for _, f := range doc.Evidence {
		got = append(got, f.Consequence)
	}
	want := []string{
		evidence.ConsequenceSilentLoss, evidence.ConsequenceUnsafeBehavior,
		evidence.ConsequenceStructural, evidence.ConsequenceHygiene,
	}
	if len(got) != len(want) {
		t.Fatalf("evidence = %v, want one finding per class", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("evidence order = %v, want %v", got, want)
		}
	}
}

// TestErrcheckFindingsCarryTheirRemedyClass covers the split that turns one
// rule's undifferentiated volume into a handful of decisions: a discarded
// domain write and a discarded rows.Close are the same linter finding and are
// not remotely the same defect.
func TestErrcheckFindingsCarryTheirRemedyClass(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.6.0", summaryFixture(t))
	got := map[string]string{}
	for _, f := range doc.Evidence {
		if f.RuleID == policy.RuleErrcheck {
			got[f.RemedyClass] = f.Consequence
		}
	}
	if got[policy.RemedyDomainWrite] != evidence.ConsequenceSilentLoss {
		t.Fatalf("an unrecognised discarded call was not treated as a lost domain write: %v", got)
	}
	if got[policy.RemedyResourceClose] != evidence.ConsequenceStructural {
		t.Fatalf("rows.Close was not bucketed as a resource close: %v", got)
	}
}

func TestSummaryAggregatesTheWholeEvidenceSet(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.6.0", summaryFixture(t))
	s := doc.Summary
	if s.Total != 4 || s.Blocking+s.Advisory != s.Total {
		t.Fatalf("summary totals do not partition the set: %+v", s)
	}
	if s.New != 2 || s.Preexisting != 1 || s.Fixed != 1 {
		t.Fatalf("state split = new %d, preexisting %d, fixed %d", s.New, s.Preexisting, s.Fixed)
	}
	if s.ByRule[policy.RuleErrcheck] != 2 || s.ByFile["store.go"] != 2 {
		t.Fatalf("per-rule or per-file counts are wrong: %+v", s)
	}
	if s.ByConsequence[evidence.ConsequenceSilentLoss] != 1 ||
		s.ByConsequence[evidence.ConsequenceHygiene] != 1 {
		t.Fatalf("per-consequence counts are wrong: %v", s.ByConsequence)
	}
	if s.ByRemedyClass[policy.RemedyDomainWrite] != 1 {
		t.Fatalf("per-remedy counts are wrong: %v", s.ByRemedyClass)
	}
	if s.ByDimension[string(admission.DimPolicyIntegrity)] == 0 {
		t.Fatalf("per-dimension counts are wrong: %v", s.ByDimension)
	}
	if s.ByFile["ok.go"] != 0 || len(s.ByFile) != 2 {
		t.Fatalf("byFile names files with no findings: %v", s.ByFile)
	}
}

// TestCoverageStatesWhatTheVerdictSkipped is the other half of the
// honest-INCONCLUSIVE discipline: the tool already refuses to claim what it did
// not prove, and this makes it state what it did not look at.
func TestCoverageStatesWhatTheVerdictSkipped(t *testing.T) {
	t.Parallel()
	doc := report.Build("0.6.0", summaryFixture(t))
	c := doc.Coverage
	if c.FilesJudged != 2 || c.PackageCount != 1 || c.TestPackageCount != 1 {
		t.Fatalf("coverage counts = %+v", c)
	}
	if c.GeneratedExemptCount != 1 || len(c.GeneratedExempt) != 1 {
		t.Fatalf("a generated exemption is invisible: %+v", c)
	}
	if len(c.LeakInjectionBlocked) != 1 {
		t.Fatalf("a package the leak detector could not reach is invisible: %+v", c)
	}
}

// TestTruncationIsAlwaysDeclared keeps the enumeration trustworthy: a consumer
// must never have to guess whether the list it holds is complete.
func TestTruncationIsAlwaysDeclared(t *testing.T) {
	t.Parallel()
	full := report.Build("0.6.0", summaryFixture(t))
	if full.EvidenceTruncated || full.EvidenceOmitted != 0 {
		t.Fatalf("the complete document declares itself truncated: %+v", full.EvidenceTruncated)
	}
	top := report.BuildWithOptions("0.6.0", summaryFixture(t), report.Options{EvidenceLimit: 2})
	if !top.EvidenceTruncated || top.EvidenceOmitted != 2 || len(top.Evidence) != 2 {
		t.Fatalf("truncation = %t, omitted %d, kept %d",
			top.EvidenceTruncated, top.EvidenceOmitted, len(top.Evidence))
	}
	// The verdict and every aggregate are computed before truncation, so a
	// budgeted rendering reports the run rather than the excerpt.
	if top.Summary.Total != full.Summary.Total || top.Verdict != full.Verdict ||
		len(top.Claims) != len(full.Claims) ||
		!maps.Equal(top.Summary.ByConsequence, full.Summary.ByConsequence) {
		t.Fatal("truncation changed the summary, the verdict, or the claims")
	}
	if top.Evidence[0].Consequence != evidence.ConsequenceSilentLoss {
		t.Fatalf("truncation kept %q rather than the highest consequence", top.Evidence[0].Consequence)
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

// TestNewBlocksAreAbsentWhenThereIsNothingToSay keeps the schema additive. A
// run with no ledger and no local lint configuration has to render exactly the
// document it rendered before either existed, or every consumer of
// goharness.report/v2 has to be told about a change that says nothing.
func TestNewBlocksAreAbsentWhenThereIsNothingToSay(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(report.Build("test", sampleResult()))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, key := range []string{"baseline", "policyShadow"} {
		if _, present := fields[key]; present {
			t.Fatalf("%q is present in a document with nothing to report", key)
		}
	}
}

// TestBaselineBlockCountsTheBurnDown checks the arithmetic the whole ratchet is
// read through: what was acknowledged, what is left, what was repaid, and what
// no ledger could ever accept.
func TestBaselineBlockCountsTheBurnDown(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	present := result.Evidence[0].Fingerprint
	result.Debt = &policy.DebtLedger{
		Schema: policy.DebtSchema, RecordedAt: "abcdef1234567890",
		Entries: []policy.DebtEntry{
			{Fingerprint: present, RuleID: policy.RuleSuppressNolint, File: "a.go"},
			{Fingerprint: "0000000000000000", RuleID: policy.RuleErrcheck, File: "gone.go"},
		},
	}
	doc := report.Build("test", result)
	if doc.Baseline == nil {
		t.Fatal("a run with a ledger carries no baseline block")
	}
	got := *doc.Baseline
	want := report.Baseline{
		RecordedAt: "abcdef1234567890", Entries: 2, StillPresent: 1, FixedSince: 1,
		New: 0, Unbaselineable: 1,
	}
	if got != want {
		t.Fatalf("baseline = %+v, want %+v", got, want)
	}
	// The acknowledged finding is a suppression, so acknowledging it changed
	// nothing about whether it blocks.
	if !doc.Evidence[0].Blocking {
		t.Fatalf("a ledger entry stopped a suppression from blocking: %+v", doc.Evidence[0])
	}
}

// TestPolicyShadowRendersWhatItCouldAndCouldNotCount is the honesty guard on the
// section: a count that cannot be exact is declared, never printed as if it
// were.
func TestPolicyShadowRendersWhatItCouldAndCouldNotCount(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.PolicyShadow = &verify.PolicyShadow{
		File: ".golangci.yml", Analysed: true,
		Entries: []verify.ShadowEntry{
			{ID: "test-file-exclusion", Mechanism: "m", Detail: "d",
				RuleIDs: []string{policy.RuleErrcheck}, Attributed: true, Findings: 259},
			{ID: "errcheck-check-blank", Mechanism: "m", Detail: "d",
				RuleIDs: []string{policy.RuleErrcheck}, Note: "cannot be counted exactly"},
		},
	}
	doc := report.Build("test", result)
	if doc.PolicyShadow == nil || len(doc.PolicyShadow.Entries) != 2 {
		t.Fatalf("policy shadow = %+v", doc.PolicyShadow)
	}
	if doc.PolicyShadow.Entries[0].FindingsInShadow != 259 || !doc.PolicyShadow.Entries[0].Attributed {
		t.Fatalf("attributed entry = %+v", doc.PolicyShadow.Entries[0])
	}
	if doc.PolicyShadow.Entries[1].Attributed || doc.PolicyShadow.Entries[1].Note == "" {
		t.Fatalf("unattributed entry claims an exact count: %+v", doc.PolicyShadow.Entries[1])
	}
	// Nothing in the section may reach the verdict or the counts.
	plain := report.Build("test", sampleResult())
	if doc.Verdict != plain.Verdict || doc.ExitCode != plain.ExitCode {
		t.Fatal("the policy shadow moved the verdict")
	}
	if doc.Summary.Total != plain.Summary.Total || doc.Summary.Blocking != plain.Summary.Blocking {
		t.Fatal("the policy shadow moved the summary counts")
	}

	var text bytes.Buffer
	if err := report.WriteText(&text, "test", result); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(text.String(), "does not affect the verdict") {
		t.Fatalf("the text report does not say the section is inert:\n%s", text.String())
	}
}
