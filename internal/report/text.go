package report

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
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
	// Scope selects which findings are printed. The counts above them are always
	// of the whole run, so a narrowed view still states the true totals.
	Scope Scope
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
	writeCounts(&b, p, r, opts.Scope)
	writeBaseline(&b, p, r)
	writePolicyShadow(&b, p, r)
	writeFailures(&b, p, r)
	writeFindings(&b, p, r, opts.Scope)
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

func writeCounts(b *strings.Builder, p Palette, r verify.Result, scope Scope) {
	newFindings, preexisting, fixed, advisory := EvidenceCounts(r.Evidence)
	fmt.Fprintf(b, "\nevidence: %d new, %d pre-existing, %d fixed, %d advisory; %d tool failure(s); %s\n",
		newFindings, preexisting, fixed, advisory, len(r.Failures), r.Duration.Round(1e6))
	writeSlowestChecks(b, p, r)
	writeMutation(b, p, r)
	writeScopeNote(b, p, r, scope)
}

// writeMutation says what the mutation check measured, in one line. A
// discharged test-effectiveness claim over zero mutants is honest only when
// the reader can see that zero.
func writeMutation(b *strings.Builder, p Palette, r verify.Result) {
	m := r.Mutation
	if m == nil {
		return
	}
	var line string
	switch {
	case m.Targets == 0:
		line = "mutation: no function body changed, nothing to mutate"
	case m.Mutants == 0:
		line = fmt.Sprintf("mutation: %d changed function(s) offer no construct to mutate", m.Targets)
	default:
		line = fmt.Sprintf("mutation: %d mutant(s) over %d changed function(s); %d ran, %d killed, %d survived",
			m.Mutants, m.Targets, m.Ran, m.Killed, m.Survived)
		if m.Unbuilt > 0 {
			line += fmt.Sprintf(", %d did not build", m.Unbuilt)
		}
		if m.TimedOut > 0 {
			line += fmt.Sprintf(", %d timed out", m.TimedOut)
		}
	}
	fmt.Fprintf(b, "%s\n", p.dim(line))
}

// Past slowCheckThreshold the report says where the time went. Below it the
// total is enough; above it, a reader who wants to make the next run cheaper
// had to dig timing.checksMs out of the JSON to learn that benchmarks were
// seventy percent of a six-minute run.
const (
	slowCheckThreshold = time.Minute
	slowChecksShown    = 3
)

func writeSlowestChecks(b *strings.Builder, p Palette, r verify.Result) {
	if r.Duration < slowCheckThreshold || len(r.CheckTimings) == 0 {
		return
	}
	type timing struct {
		id      string
		elapsed time.Duration
	}
	items := make([]timing, 0, len(r.CheckTimings))
	for id, elapsed := range r.CheckTimings {
		items = append(items, timing{id: id, elapsed: elapsed})
	}
	slices.SortFunc(items, func(x, y timing) int {
		if c := cmp.Compare(y.elapsed, x.elapsed); c != 0 {
			return c
		}
		return strings.Compare(x.id, y.id)
	})
	parts := make([]string, 0, slowChecksShown)
	for _, item := range items[:min(len(items), slowChecksShown)] {
		parts = append(parts, item.id+" "+item.elapsed.Round(time.Second).String())
	}
	fmt.Fprintf(b, "%s\n", p.dim("slowest checks: "+strings.Join(parts, ", ")))
}

// writeScopeNote says how much of the run the printed list leaves out.
//
// The counts above this line are of the whole run and the list below it may not
// be, so a reader given no note has to work out which of the two they are
// looking at. It says nothing when nothing was withheld, because then the list
// is the run and a line claiming otherwise would be the lie this exists to
// prevent.
func writeScopeNote(b *strings.Builder, p Palette, r verify.Result, scope Scope) {
	if scope.orFull() == ScopeFull {
		return
	}
	omitted := 0
	for _, e := range r.Evidence {
		if !scope.Keeps(e) {
			omitted++
		}
	}
	if omitted == 0 {
		return
	}
	fmt.Fprintf(b, "%s\n", p.dim(fmt.Sprintf(
		"--evidence %s: %d of %d finding(s) not shown; "+
			"rerun with --evidence full to read them", scope, omitted, len(r.Evidence))))
	writeEditedFileDebt(b, p, r, scope)
}

// debtFilesShown bounds the debt line: past it the line names the largest
// files and counts the rest, because a change that opens thirty legacy files
// needs the number, not the list.
const debtFilesShown = 5

// writeEditedFileDebt names the files the change edited whose pre-existing
// findings the view withheld. The rows are debt an audit judges; the line is
// what keeps a short report from reading as a clean file.
func writeEditedFileDebt(b *strings.Builder, p Palette, r verify.Result, scope Scope) {
	debt := map[string]int{}
	for _, e := range r.Evidence {
		if !scope.Keeps(e) && e.State == evidence.StatePreexisting && e.Origin == evidence.OriginChangedFile {
			debt[e.File]++
		}
	}
	if len(debt) == 0 {
		return
	}
	files := slices.SortedFunc(maps.Keys(debt), func(x, y string) int {
		if c := cmp.Compare(debt[y], debt[x]); c != 0 {
			return c
		}
		return strings.Compare(x, y)
	})
	parts := make([]string, 0, debtFilesShown)
	for _, file := range files[:min(len(files), debtFilesShown)] {
		parts = append(parts, fmt.Sprintf("%s %d", file, debt[file]))
	}
	line := "debt in edited files, pre-existing and not shown: " + strings.Join(parts, ", ")
	if len(files) > len(parts) {
		line += fmt.Sprintf(" and %d more file(s)", len(files)-len(parts))
	}
	fmt.Fprintf(b, "%s\n", p.dim(line+"; an audit judges it"))
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

func writeFindings(b *strings.Builder, p Palette, r verify.Result, scope Scope) {
	if len(r.Evidence) == 0 {
		return
	}
	grouped := map[admission.Dimension][]evidence.Evidence{}
	for _, e := range r.Evidence {
		if !scope.Keeps(e) {
			continue
		}
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
		repeats := countRepeats(items)
		printed := map[string]bool{}
		for _, e := range items {
			rules[e.RuleID] = true
			key := repeatKey(e)
			if printed[key] {
				continue
			}
			printed[key] = true
			fmt.Fprintf(b, "  %s %s %s%s%s\n      %s\n",
				marker(p, e), p.dim(e.RuleID), p.accent(location(e)), stateSuffix(e),
				repeatSuffix(p, repeats[key]), e.Message)
			if e.Fix != nil {
				fmt.Fprintf(b, "      %s\n", p.dim("fix: "+e.Fix.Command))
			}
		}
		for _, ruleID := range slices.Sorted(mapKeys(rules)) {
			fmt.Fprintf(b, "  %s\n", p.dim("run: goharness explain "+ruleID))
		}
	}
}

// repeatKey identifies rows that say exactly the same thing in exactly the same
// place, which occurrence indexes keep apart in the document and a reader has no
// use for one at a time.
func repeatKey(e evidence.Evidence) string {
	return strings.Join([]string{
		e.RuleID, e.File, strconv.Itoa(e.Line), string(e.State), string(e.Origin), e.Message,
	}, "\x00")
}

func countRepeats(items []evidence.Evidence) map[string]int {
	out := make(map[string]int, len(items))
	for _, e := range items {
		out[repeatKey(e)]++
	}
	return out
}

func repeatSuffix(p Palette, count int) string {
	if count < 2 {
		return ""
	}
	return p.dim(fmt.Sprintf(" (x%d)", count))
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

// stateSuffix names both axes a finding carries: whether it existed at base,
// and whether it sits in a file the change wrote. A reader deciding what to do
// with a row wants the second as much as the first.
func stateSuffix(e evidence.Evidence) string {
	switch {
	case e.State == "" && e.Origin == evidence.OriginUnscoped:
		return ""
	case e.State == "":
		return " [" + string(e.Origin) + "]"
	case e.Origin == evidence.OriginUnscoped:
		return " [" + string(e.State) + "]"
	default:
		return " [" + string(e.State) + ", " + string(e.Origin) + "]"
	}
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
