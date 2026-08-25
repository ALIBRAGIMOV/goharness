package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// DiffSchemaID identifies the report-to-report comparison document. It is
// versioned from birth and it is not the report schema: a comparison of two
// goharness.report/v2 documents is a different kind of statement than either.
const DiffSchemaID = "goharness.diff/v1"

// Diff is the comparison of two reports on fingerprint identity.
//
// Fingerprints are content-based and carry no line numbers, so a finding keeps
// its name across unrelated edits and this comparison measures repair rather
// than movement. Nothing here is derived from the filesystem, git, or a clock:
// the same two documents always produce the same bytes.
type Diff struct {
	Schema string      `json:"schema"`
	Old    DiffSubject `json:"old"`
	New    DiffSubject `json:"new"`
	// SubjectMismatch says the two reports describe different modules or were
	// produced by different modes. Fingerprint identity is only meaningful inside
	// one subject, so the comparison below is mechanical rather than a burn-down.
	// It is a warning and never an error: two honest reports of different modules
	// still diff, and refusing would hide that fact instead of stating it.
	SubjectMismatch bool              `json:"subjectMismatch"`
	Verdict         VerdictTransition `json:"verdict"`
	Claims          []ClaimTransition `json:"claims"`
	Counts          DiffCounts        `json:"counts"`
	// Fixed, Introduced and Remaining partition the union of the two evidence
	// sets. Blocking is taken from the report the finding is being reported out
	// of: the old one for Fixed, the new one for the other two.
	Fixed      []DiffGroup `json:"fixed"`
	Introduced []DiffGroup `json:"introduced"`
	Remaining  []DiffGroup `json:"remaining"`
	ExitCode   int         `json:"exitCode"`
}

// DiffSubject is what one side of the comparison was a report of.
type DiffSubject struct {
	Module  string `json:"module"`
	Mode    string `json:"mode"`
	Verdict string `json:"verdict"`
	Total   int    `json:"total"`
	// Truncated repeats the report's own declaration that its evidence list is a
	// selection. A diff of a truncated report describes only the rows it carries,
	// which is not the same statement as a burn-down of the run.
	Truncated bool `json:"truncated"`
	Omitted   int  `json:"omitted"`
}

// VerdictTransition is how the admission answer moved between the two runs.
type VerdictTransition struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Changed bool   `json:"changed"`
}

// ClaimTransition is how one quality dimension moved. An empty From or To means
// the dimension was absent from that report.
type ClaimTransition struct {
	Dimension string `json:"dimension"`
	From      string `json:"from"`
	To        string `json:"to"`
	Changed   bool   `json:"changed"`
}

// DiffCounts is the burn-down in one block, so a consumer never has to sum the
// groups to learn whether the change moved forwards.
type DiffCounts struct {
	Fixed      DiffSplit `json:"fixed"`
	Introduced DiffSplit `json:"introduced"`
	Remaining  DiffSplit `json:"remaining"`
}

// DiffSplit is one bucket split on the axis the verdict itself uses.
type DiffSplit struct {
	Total    int `json:"total"`
	Blocking int `json:"blocking"`
	Advisory int `json:"advisory"`
}

// DiffGroup is one consequence class inside a bucket. An empty Consequence is
// the unclassified group, which is where every finding from a report predating
// consequence classes lands, and it sorts last like any other unknown class.
type DiffGroup struct {
	Consequence string          `json:"consequence"`
	Total       int             `json:"total"`
	Blocking    int             `json:"blocking"`
	Advisory    int             `json:"advisory"`
	Rules       []DiffRuleCount `json:"rules"`
}

// DiffRuleCount is one rule inside a consequence group, with the fingerprints
// behind it. The identities are carried rather than only counted: a count can
// be narrated, and a fingerprint resolves through
// "goharness explain FINGERPRINT --report FILE".
type DiffRuleCount struct {
	RuleID       string   `json:"ruleId"`
	Total        int      `json:"total"`
	Blocking     int      `json:"blocking"`
	Advisory     int      `json:"advisory"`
	Fingerprints []string `json:"fingerprints"`
}

// Diff exit codes. They are not the verdict exit codes: this command answers
// "did the change introduce anything", not "is this admissible".
const (
	// DiffExitClean means nothing blocking was introduced. Fixed and remaining
	// findings do not fail it: a run that repaired debt and left the rest alone
	// went in the right direction.
	DiffExitClean = 0
	// DiffExitIntroduced means the newer report carries blocking evidence the
	// older one did not.
	DiffExitIntroduced = 1
	// DiffExitError means no comparison was produced: a report could not be read,
	// parsed, or was not a document this binary understands. It matches the
	// harness's INCONCLUSIVE code because it carries the same meaning, which is
	// that there is no answer rather than a bad one.
	DiffExitError = 2
)

// CompareDocuments diffs two reports by fingerprint. It reads nothing outside
// its arguments.
func CompareDocuments(oldDoc, newDoc Document) Diff {
	fixed, introduced, remaining := partitionByFingerprint(oldDoc.Evidence, newDoc.Evidence)
	d := Diff{
		Schema:          DiffSchemaID,
		Old:             diffSubject(oldDoc),
		New:             diffSubject(newDoc),
		SubjectMismatch: oldDoc.Module.Path != newDoc.Module.Path || oldDoc.Mode != newDoc.Mode,
		Verdict: VerdictTransition{
			From: oldDoc.Verdict, To: newDoc.Verdict,
			Changed: oldDoc.Verdict != newDoc.Verdict,
		},
		Claims: claimTransitions(oldDoc.Claims, newDoc.Claims),
		Counts: DiffCounts{
			Fixed:      splitOf(fixed),
			Introduced: splitOf(introduced),
			Remaining:  splitOf(remaining),
		},
		Fixed:      groupFindings(fixed),
		Introduced: groupFindings(introduced),
		Remaining:  groupFindings(remaining),
	}
	d.ExitCode = DiffExitClean
	if d.Counts.Introduced.Blocking > 0 {
		d.ExitCode = DiffExitIntroduced
	}
	return d
}

func diffSubject(doc Document) DiffSubject {
	return DiffSubject{
		Module: doc.Module.Path, Mode: doc.Mode, Verdict: doc.Verdict,
		Total: len(doc.Evidence), Truncated: doc.EvidenceTruncated, Omitted: doc.EvidenceOmitted,
	}
}

// partitionByFingerprint splits the union of the two evidence sets. A
// fingerprint repeated inside one report is kept once: it is one identity, and
// the occurrence index that made repeats distinguishable is already inside it.
func partitionByFingerprint(oldItems, newItems []Finding) (fixed, introduced, remaining []Finding) {
	inNew := make(map[string]bool, len(newItems))
	for _, f := range newItems {
		inNew[f.Fingerprint] = true
	}
	inOld := make(map[string]bool, len(oldItems))
	for _, f := range oldItems {
		if inOld[f.Fingerprint] {
			continue
		}
		inOld[f.Fingerprint] = true
		if !inNew[f.Fingerprint] {
			fixed = append(fixed, f)
		}
	}
	seen := make(map[string]bool, len(newItems))
	for _, f := range newItems {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		if inOld[f.Fingerprint] {
			remaining = append(remaining, f)
			continue
		}
		introduced = append(introduced, f)
	}
	return fixed, introduced, remaining
}

func splitOf(items []Finding) DiffSplit {
	s := DiffSplit{Total: len(items)}
	for _, f := range items {
		if f.Blocking {
			s.Blocking++
			continue
		}
		s.Advisory++
	}
	return s
}

// groupFindings buckets one side of the comparison by consequence class and
// then by rule, in the order a reader should work them.
func groupFindings(items []Finding) []DiffGroup {
	byClass := map[string]map[string][]Finding{}
	for _, f := range items {
		rules, ok := byClass[f.Consequence]
		if !ok {
			rules = map[string][]Finding{}
			byClass[f.Consequence] = rules
		}
		rules[f.RuleID] = append(rules[f.RuleID], f)
	}
	out := make([]DiffGroup, 0, len(byClass))
	for class, rules := range byClass {
		out = append(out, diffGroup(class, rules))
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := evidence.ConsequenceRank(out[i].Consequence), evidence.ConsequenceRank(out[j].Consequence)
		if ri != rj {
			return ri < rj
		}
		return out[i].Consequence < out[j].Consequence
	})
	return out
}

func diffGroup(class string, rules map[string][]Finding) DiffGroup {
	g := DiffGroup{Consequence: class, Rules: make([]DiffRuleCount, 0, len(rules))}
	for ruleID, items := range rules {
		split := splitOf(items)
		prints := make([]string, 0, len(items))
		for _, f := range items {
			prints = append(prints, f.Fingerprint)
		}
		slices.Sort(prints)
		g.Rules = append(g.Rules, DiffRuleCount{
			RuleID: ruleID, Total: split.Total, Blocking: split.Blocking,
			Advisory: split.Advisory, Fingerprints: prints,
		})
		g.Total += split.Total
		g.Blocking += split.Blocking
		g.Advisory += split.Advisory
	}
	sort.Slice(g.Rules, func(i, j int) bool { return g.Rules[i].RuleID < g.Rules[j].RuleID })
	return g
}

// claimTransitions pairs the two claim tables by dimension, in the order the
// claims model itself declares. A dimension either report knows and the
// dimension list does not still appears, sorted after the known ones, so a
// report from a newer binary is compared rather than silently trimmed.
func claimTransitions(oldClaims, newClaims []admission.QualityClaim) []ClaimTransition {
	before := claimStates(oldClaims)
	after := claimStates(newClaims)
	names := make([]string, 0, len(before)+len(after))
	for name := range before {
		names = append(names, name)
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			names = append(names, name)
		}
	}
	order := dimensionOrder()
	sort.Slice(names, func(i, j int) bool {
		oi, oj := order[names[i]], order[names[j]]
		if oi != oj {
			return oi < oj
		}
		return names[i] < names[j]
	})
	out := make([]ClaimTransition, 0, len(names))
	for _, name := range names {
		out = append(out, ClaimTransition{
			Dimension: name, From: before[name], To: after[name],
			Changed: before[name] != after[name],
		})
	}
	return out
}

func claimStates(claims []admission.QualityClaim) map[string]string {
	out := make(map[string]string, len(claims))
	for _, c := range claims {
		out[string(c.Dimension)] = string(c.State)
	}
	return out
}

func dimensionOrder() map[string]int {
	dims := admission.Dimensions()
	order := make(map[string]int, len(dims))
	for i, d := range dims {
		order[string(d)] = i
	}
	return order
}

// ParseDocument decodes a goharness report and refuses any schema this binary
// does not read. A document whose schema is unknown is not a document with
// missing fields; guessing at one would be the one way a comparison could be
// confidently wrong.
func ParseDocument(name string, data []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("parsing %s: %w", name, err)
	}
	if doc.Schema != SchemaID {
		return Document{}, fmt.Errorf(
			"%s declares schema %q, and this binary reads %s", name, doc.Schema, SchemaID)
	}
	return doc, nil
}

// WriteDiffJSON renders the comparison as the goharness.diff/v1 document.
func WriteDiffJSON(w io.Writer, d Diff) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return fmt.Errorf("writing JSON diff: %w", err)
	}
	return nil
}

// DiffTextOptions configures the human rendering. The labels name the two
// reports for the reader; they are deliberately not part of the JSON document,
// which is a function of the two reports and not of where they were stored.
type DiffTextOptions struct {
	Palette  Palette
	OldLabel string
	NewLabel string
}

// diffFingerprintsShown bounds the identities the text form lists per rule. The
// full set is always in the JSON; a terminal rendering that printed sixteen
// hundred hex strings would bury the counts it exists to show.
const diffFingerprintsShown = 8

// WriteDiffText renders the comparison for a human or an agent supervisor.
func WriteDiffText(w io.Writer, d Diff, opts DiffTextOptions) error {
	var b strings.Builder
	p := opts.Palette
	writeDiffWarnings(&b, p, d, opts)
	fmt.Fprintf(&b, "%s %s %s  (%s -> %s)\n",
		p.verdictName(d.Verdict.From), arrow(d.Verdict.Changed), p.verdictName(d.Verdict.To),
		labelOr(opts.OldLabel, "old"), labelOr(opts.NewLabel, "new"))
	fmt.Fprintf(&b, "module %s  mode=%s\n", subjectModule(d), subjectMode(d))
	writeDiffCounts(&b, p, d)
	writeClaimTransitions(&b, p, d)
	writeDiffBucket(&b, p, "introduced", d.Introduced)
	writeDiffBucket(&b, p, "fixed", d.Fixed)
	writeDiffBucket(&b, p, "remaining", d.Remaining)
	return flush(w, b.String())
}

func writeDiffWarnings(b *strings.Builder, p Palette, d Diff, opts DiffTextOptions) {
	if d.SubjectMismatch {
		fmt.Fprintf(b, "%s\n", p.warn(fmt.Sprintf(
			"warning: different subjects (module %s vs %s, mode %s vs %s); fingerprints "+
				"identify findings within one subject, so these counts are mechanical",
			orUnknown(d.Old.Module), orUnknown(d.New.Module),
			orUnknown(d.Old.Mode), orUnknown(d.New.Mode))))
	}
	for _, s := range []struct {
		label   string
		subject DiffSubject
	}{
		{labelOr(opts.OldLabel, "old"), d.Old},
		{labelOr(opts.NewLabel, "new"), d.New},
	} {
		if !s.subject.Truncated {
			continue
		}
		fmt.Fprintf(b, "%s\n", p.warn(fmt.Sprintf(
			"warning: %s declares its evidence truncated (%d rows carried, %d omitted); "+
				"this compares the rows it carries, not the runs",
			s.label, s.subject.Total, s.subject.Omitted)))
	}
}

func writeDiffCounts(b *strings.Builder, p Palette, d Diff) {
	fmt.Fprintf(b, "\nfixed %d, introduced %d, %d remaining\n",
		d.Counts.Fixed.Total, d.Counts.Introduced.Total, d.Counts.Remaining.Total)
	for _, row := range []struct {
		name  string
		split DiffSplit
	}{
		{"fixed", d.Counts.Fixed},
		{"introduced", d.Counts.Introduced},
		{"remaining", d.Counts.Remaining},
	} {
		line := fmt.Sprintf("  %-11s %5d  (%d blocking, %d advisory)",
			row.name, row.split.Total, row.split.Blocking, row.split.Advisory)
		if row.name == "introduced" && row.split.Blocking > 0 {
			fmt.Fprintf(b, "%s\n", p.bad(line))
			continue
		}
		fmt.Fprintf(b, "%s\n", line)
	}
}

func writeClaimTransitions(b *strings.Builder, p Palette, d Diff) {
	moved := make([]ClaimTransition, 0, len(d.Claims))
	for _, c := range d.Claims {
		if c.Changed {
			moved = append(moved, c)
		}
	}
	if len(moved) == 0 {
		fmt.Fprintf(b, "\n%s\n", p.dim("no claim changed state"))
		return
	}
	b.WriteString("\nclaims that moved:\n")
	for _, c := range moved {
		fmt.Fprintf(b, "  %-22s %s -> %s\n", c.Dimension, orUnknown(c.From), orUnknown(c.To))
	}
}

func writeDiffBucket(b *strings.Builder, p Palette, name string, groups []DiffGroup) {
	if len(groups) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", name)
	for _, g := range groups {
		fmt.Fprintf(b, "  %-16s %d blocking, %d advisory\n",
			consequenceName(g.Consequence), g.Blocking, g.Advisory)
		for _, r := range g.Rules {
			fmt.Fprintf(b, "    %-22s %4d  %s\n",
				r.RuleID, r.Total, p.dim(fingerprintList(r.Fingerprints)))
		}
	}
}

func fingerprintList(prints []string) string {
	if len(prints) <= diffFingerprintsShown {
		return strings.Join(prints, " ")
	}
	return strings.Join(prints[:diffFingerprintsShown], " ") +
		fmt.Sprintf(" and %d more", len(prints)-diffFingerprintsShown)
}

func consequenceName(c string) string {
	if c == "" {
		return "unclassified"
	}
	return c
}

func arrow(changed bool) string {
	if changed {
		return "->"
	}
	return "=="
}

func labelOr(label, fallback string) string {
	if label == "" {
		return fallback
	}
	return label
}

func orUnknown(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// subjectModule and subjectMode name the shared subject, or say outright that
// there is not one. Printing only the newer report's module would let a
// comparison of two different repositories read like a burn-down of one.
func subjectModule(d Diff) string {
	if d.Old.Module != d.New.Module {
		return orUnknown(d.Old.Module) + " vs " + orUnknown(d.New.Module)
	}
	return orUnknown(d.New.Module)
}

func subjectMode(d Diff) string {
	if d.Old.Mode != d.New.Mode {
		return orUnknown(d.Old.Mode) + " vs " + orUnknown(d.New.Mode)
	}
	return orUnknown(d.New.Mode)
}

// verdictName colours a verdict read out of a document, where it is a string
// this binary did not necessarily produce.
func (p Palette) verdictName(v string) string {
	return p.verdict(admission.Verdict(v))
}
