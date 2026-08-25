package report

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// Palette renders emphasis. The zero value is plain text, which is what a pipe,
// NO_COLOR, and --no-color all get.
type Palette struct {
	Enabled bool
}

func (p Palette) wrap(code, s string) string {
	if !p.Enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Palette) good(s string) string   { return p.wrap("32", s) }
func (p Palette) bad(s string) string    { return p.wrap("31", s) }
func (p Palette) warn(s string) string   { return p.wrap("33", s) }
func (p Palette) dim(s string) string    { return p.wrap("2", s) }
func (p Palette) accent(s string) string { return p.wrap("4", s) }

func (p Palette) verdict(v admission.Verdict) string {
	switch v {
	case admission.VerdictAdmitted:
		return p.good(string(v))
	case admission.VerdictRejected:
		return p.bad(string(v))
	default:
		return p.warn(string(v))
	}
}

func (p Palette) claimState(s admission.ClaimState) string {
	switch s {
	case admission.ClaimPass:
		return p.good(string(s))
	case admission.ClaimFail:
		return p.bad(string(s))
	case admission.ClaimInconclusive:
		return p.warn(string(s))
	default:
		return p.dim(string(s))
	}
}

// TextOptions configures the human renderer.
type TextOptions struct {
	Palette Palette
	Quiet   bool
}

// WriteText renders the human report: verdict first, then the claim table, the
// evidence counts, the findings grouped by the claim that owns them, and the
// smallest set of actions that would change the verdict.
func WriteText(w io.Writer, version string, r verify.Result) error {
	return WriteTextWithOptions(w, version, r, TextOptions{})
}

// WriteTextWithOptions is WriteText with explicit colour and verbosity.
func WriteTextWithOptions(w io.Writer, version string, r verify.Result, opts TextOptions) error {
	var b strings.Builder
	p := opts.Palette

	fmt.Fprintf(&b, "%s  %s\n", p.verdict(r.Decision.Verdict), r.Decision.Reason)
	if opts.Quiet {
		return flush(w, b.String())
	}

	writeHeader(&b, p, version, r)
	writeClaims(&b, p, r)
	writeCounts(&b, r)
	writeBaseline(&b, p, r)
	writePolicyShadow(&b, p, r)
	writeFailures(&b, p, r)
	writeFindings(&b, p, r)
	writeNextSteps(&b, p, r)
	return flush(w, b.String())
}

func flush(w io.Writer, s string) error {
	if _, err := io.WriteString(w, s); err != nil {
		return fmt.Errorf("writing text report: %w", err)
	}
	return nil
}

func writeHeader(b *strings.Builder, p Palette, version string, r verify.Result) {
	fmt.Fprintf(b, "goharness %s  mode=%s  module %s (go %s)\n",
		version, r.Mode, r.Repository.ModulePath, r.Repository.GoDirective)
	fmt.Fprintf(b, "%s\n", p.dim(fmt.Sprintf(
		"tools: go %s, golangci-lint %s (pin %s), x/vuln %s, uber guide %s",
		tool.GoVersion(), versionOrMissing(r.Golangci.Version),
		tool.GolangciLintPin, versionOrMissing(tool.XVulnVersion()),
		policy.UberGuideCommit[:12])))
	writeVulnDB(b, p, r)

	if !r.Mode.IsAdmissionGate() {
		fmt.Fprintf(b, "%s\n", p.warn(
			"fast is a developer loop aid, not an admission gate: finish with `goharness verify --agent`"))
	}
	fmt.Fprintf(b, "contract: %s", r.Contract.Source)
	if r.Contract.Goal != "" {
		fmt.Fprintf(b, " (%s)", r.Contract.Goal)
	}
	b.WriteString("\n")
	if grants := r.Contract.IgnoredGrants; len(grants) > 0 {
		fmt.Fprintf(b, "%s\n", p.warn(fmt.Sprintf(
			"contract grants ignored: %s (not committed at the base revision)",
			strings.Join(grants, ", "))))
	}
	writeScope(b, r)
	if len(r.Risks.Active) > 0 {
		names := make([]string, 0, len(r.Risks.Active))
		for _, domain := range r.Risks.Active {
			names = append(names, string(domain))
		}
		fmt.Fprintf(b, "risk domains: %s\n", strings.Join(names, ", "))
	}
}

// writeVulnDB reports the snapshot that produced the security evidence. The
// age is derived and therefore lives here, never in the deterministic JSON.
func writeVulnDB(b *strings.Builder, p Palette, r verify.Result) {
	if r.VulnDB == nil {
		return
	}
	age := time.Since(r.VulnDB.Modified)
	line := fmt.Sprintf("vuln database: %d entries, modified %s (%d day(s) ago), checksum %s",
		r.VulnDB.EntryCount, r.VulnDB.Modified.UTC().Format("2006-01-02"),
		int(age.Hours()/24), r.VulnDB.TreeChecksum[:12])
	if r.VulnDB.Stale(time.Now()) {
		fmt.Fprintf(b, "%s\n", p.warn(line+"; run `goharness tools update`"))
		return
	}
	fmt.Fprintf(b, "%s\n", p.dim(line))
}

func versionOrMissing(v string) string {
	if v == "" {
		return "not found"
	}
	return v
}

func writeScope(b *strings.Builder, r verify.Result) {
	switch {
	case r.Change.FullScope:
		fmt.Fprintf(b, "scope: whole module (%d packages)\n", len(r.Execution.Packages))
	case r.Change.HasBase():
		fmt.Fprintf(b, "scope: %d changed files against %s (%s), %d packages, %d test packages\n",
			len(r.Change.Files), shortRev(r.Change.Base), r.Change.BaseOrigin,
			len(r.Execution.Packages), len(r.Execution.Tests))
	default:
		fmt.Fprintf(b, "scope: %d changed files, no base revision available, %d packages\n",
			len(r.Change.Files), len(r.Execution.Packages))
	}
}

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func writeClaims(b *strings.Builder, p Palette, r verify.Result) {
	if len(r.Decision.Claims) == 0 {
		return
	}
	b.WriteString("\nquality claims:\n")
	for _, claim := range r.Decision.Claims {
		fmt.Fprintf(b, "  %-14s %-22s %s\n",
			p.claimState(claim.State), claim.Dimension, p.dim(claim.Reason))
	}
}

func writeCounts(b *strings.Builder, r verify.Result) {
	newFindings, preexisting, fixed, advisory := EvidenceCounts(r.Evidence)
	fmt.Fprintf(b, "\nevidence: %d new, %d pre-existing, %d fixed, %d advisory; %d tool failure(s); %s\n",
		newFindings, preexisting, fixed, advisory, len(r.Failures), r.Duration.Round(1e6))
}

// writeBaseline prints the ledger burn-down in one line, which is the whole
// point of recording it: a ratchet nobody can see the progress of is a way of
// never fixing anything.
func writeBaseline(b *strings.Builder, p Palette, r verify.Result) {
	base := buildBaseline(r.Debt, buildFindings(r.Evidence))
	if base == nil {
		return
	}
	line := fmt.Sprintf(
		"baseline %s: %d acknowledged, %d still present, %d fixed since, %d new blocking, "+
			"%d that no ledger can ever acknowledge",
		shortRev(base.RecordedAt), base.Entries, base.StillPresent,
		base.FixedSince, base.New, base.Unbaselineable)
	if base.New > 0 || base.Unbaselineable > 0 {
		fmt.Fprintf(b, "%s\n", p.warn(line))
		return
	}
	fmt.Fprintf(b, "%s\n", p.dim(line))
}

// writePolicyShadow states what the repository's own lint configuration hides.
// It never appears in the next steps: nothing here is a defect in the code, and
// no part of it moved the verdict.
func writePolicyShadow(b *strings.Builder, p Palette, r verify.Result) {
	shadow := r.PolicyShadow
	if shadow == nil {
		return
	}
	fmt.Fprintf(b, "\npolicy shadow (%s, from your own configuration; it does not affect the verdict):\n",
		shadow.File)
	if !shadow.Analysed {
		fmt.Fprintf(b, "  %s\n", p.dim("not analysed: "+shadow.Reason))
		return
	}
	if len(shadow.Entries) == 0 {
		fmt.Fprintf(b, "  %s\n", p.dim("no shadow detected against the strict pack"))
		return
	}
	for _, e := range shadow.Entries {
		fmt.Fprintf(b, "  %s  %s\n      %s (%s)\n", p.warn(e.ID),
			strings.Join(e.RuleIDs, ", "), e.Mechanism, e.Detail)
		if e.Attributed {
			fmt.Fprintf(b, "      %d finding(s) of this run live in that shadow\n", e.Findings)
			continue
		}
		fmt.Fprintf(b, "      %s\n", p.dim(e.Note))
	}
}

func writeFailures(b *strings.Builder, p Palette, r verify.Result) {
	if len(r.Failures) == 0 {
		return
	}
	b.WriteString("\n" + p.warn("tool failures") +
		" (these prevent a trustworthy answer; they are not code defects):\n")
	for _, f := range r.Failures {
		fmt.Fprintf(b, "  [%s] %s\n", f.CheckID, f.Reason)
		if f.Hint != "" {
			fmt.Fprintf(b, "      hint: %s\n", f.Hint)
		}
	}
}

func writeFindings(b *strings.Builder, p Palette, r verify.Result) {
	if len(r.Evidence) == 0 {
		return
	}
	grouped := map[admission.Dimension][]evidence.Evidence{}
	for _, e := range r.Evidence {
		dim, ok := admission.DimensionOf(e.RuleID)
		if !ok {
			dim = admission.DimPolicyIntegrity
		}
		grouped[dim] = append(grouped[dim], e)
	}
	for _, dim := range admission.Dimensions() {
		items := grouped[dim]
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n%s:\n", dim)
		rules := map[string]bool{}
		for _, e := range items {
			fmt.Fprintf(b, "  %s %s %s%s\n      %s\n",
				marker(p, e), p.dim(e.RuleID), p.accent(location(e)), stateSuffix(e), e.Message)
			if e.Fix != nil {
				fmt.Fprintf(b, "      %s\n", p.dim("fix: "+e.Fix.Command))
			}
			rules[e.RuleID] = true
		}
		for _, ruleID := range slices.Sorted(mapKeys(rules)) {
			fmt.Fprintf(b, "  %s\n", p.dim("run: goharness explain "+ruleID))
		}
	}
}

func mapKeys(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func marker(p Palette, e evidence.Evidence) string {
	switch {
	case verify.Blocking(e):
		return p.bad("BLOCK ")
	case e.State == evidence.StateFixed:
		return p.good("fixed ")
	case e.Classification == evidence.ClassificationRequired:
		return p.warn("debt  ")
	default:
		return p.dim("advise")
	}
}

func location(e evidence.Evidence) string {
	switch {
	case e.File != "" && e.Line > 0:
		return fmt.Sprintf("%s:%d:%d", e.File, e.Line, e.Column)
	case e.File != "":
		return e.File
	case e.Package != "":
		return e.Package
	default:
		return "(module)"
	}
}

func stateSuffix(e evidence.Evidence) string {
	if e.State == "" {
		return ""
	}
	return " [" + string(e.State) + "]"
}

func writeNextSteps(b *strings.Builder, p Palette, r verify.Result) {
	switch r.Decision.Verdict {
	case admission.VerdictRejected:
		writeRejectionSteps(b, p, r)
	case admission.VerdictInconclusive:
		writeInconclusiveSteps(b, p, r)
	default:
		if r.Mode.IsAdmissionGate() {
			b.WriteString("\n" + p.good("this change is admissible") +
				": every applicable claim has sufficient evidence.\n")
		}
	}
}

func writeRejectionSteps(b *strings.Builder, p Palette, r verify.Result) {
	b.WriteString("\n" + p.bad("next steps") + " (smallest set of actions that would flip each failing claim):\n")
	for _, claim := range admission.ClaimsInState(r.Decision.Claims, admission.ClaimFail) {
		fmt.Fprintf(b, "  %s: %s\n", claim.Dimension, claim.Reason)
		for _, ruleID := range failingRules(r.Evidence, claim.Dimension) {
			fmt.Fprintf(b, "      fix every %s finding above, then rerun; `goharness explain %s` says why it blocks\n",
				ruleID, ruleID)
		}
	}
}

func failingRules(items []evidence.Evidence, dim admission.Dimension) []string {
	seen := map[string]bool{}
	for _, e := range items {
		if !verify.Blocking(e) {
			continue
		}
		if d, ok := admission.DimensionOf(e.RuleID); ok && d == dim {
			seen[e.RuleID] = true
		}
	}
	return slices.Sorted(mapKeys(seen))
}

func writeInconclusiveSteps(b *strings.Builder, p Palette, r verify.Result) {
	b.WriteString("\n" + p.warn("inconclusive") +
		": the following evidence could not be produced, so no claim of safety is made.\n")
	for _, line := range admission.Remedies(r.Unproducible) {
		fmt.Fprintf(b, "  %s\n", line)
	}
	if len(r.Unproducible) == 0 {
		for _, claim := range admission.ClaimsInState(r.Decision.Claims, admission.ClaimInconclusive) {
			fmt.Fprintf(b, "  %s: %s\n", claim.Dimension, claim.Reason)
		}
	}
}
