// Package evidence defines the normalized finding model that every check in
// the harness produces, plus stable fingerprinting and base/head comparison.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Severity ranks a finding for human presentation. It never decides the verdict;
// Classification does.
type Severity string

// Severity levels emitted by the harness.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// State records how a finding at head relates to the base snapshot. A single
// field is enough: "new" means absent at base, "preexisting" means present at
// both, "fixed" means present at base only. A separate base-side field would
// carry no information the head-side state does not already imply.
type State string

// Finding states relative to the base snapshot.
const (
	StateNew         State = "new"
	StatePreexisting State = "preexisting"
	StateFixed       State = "fixed"
	// StateUncompared is the zero value: the run performed no base comparison,
	// so every finding is judged on its own.
	StateUncompared State = ""
)

// Classification decides whether a finding can block admission.
type Classification string

// Classifications used by the decision rule.
const (
	ClassificationRequired Classification = "required"
	ClassificationAdvisory Classification = "advisory"
)

// FingerprintLength is the hex length of a truncated evidence fingerprint.
const FingerprintLength = 16

// Evidence is a single normalized finding. Values are immutable once the
// coordinator has assigned states; checks return them by value.
type Evidence struct {
	Fingerprint    string         `json:"fingerprint"`
	RuleID         string         `json:"ruleId"`
	PolicySource   string         `json:"policySource"`
	Tool           string         `json:"tool"`
	ToolVersion    string         `json:"toolVersion,omitempty"`
	Severity       Severity       `json:"severity"`
	File           string         `json:"file,omitempty"`
	Line           int            `json:"line,omitempty"`
	Column         int            `json:"column,omitempty"`
	Package        string         `json:"package,omitempty"`
	Message        string         `json:"message"`
	State          State          `json:"state,omitempty"`
	Classification Classification `json:"classification"`
	DocURL         string         `json:"docUrl,omitempty"`
}

// NormalizeMessage collapses whitespace and strips volatile substrings so that
// the same underlying defect hashes identically across runs and machines.
func NormalizeMessage(msg string) string {
	return strings.Join(strings.Fields(msg), " ")
}

// Fingerprint derives the stable identity of a finding. Line and column are
// deliberately excluded: unrelated edits shift them without changing identity.
func Fingerprint(ruleID, file, pkg, message string, occurrence int) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		ruleID,
		file,
		pkg,
		NormalizeMessage(message),
		strconv.Itoa(occurrence),
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:FingerprintLength]
}

// AssignFingerprints fills in the Fingerprint of every item, numbering
// occurrences within each (rule, file, package, message) group in the order the
// slice already establishes. Callers must sort deterministically first.
func AssignFingerprints(items []Evidence) {
	counts := make(map[string]int, len(items))
	for i := range items {
		key := strings.Join([]string{
			items[i].RuleID,
			items[i].File,
			items[i].Package,
			NormalizeMessage(items[i].Message),
		}, "\x00")
		occurrence := counts[key]
		counts[key] = occurrence + 1
		items[i].Fingerprint = Fingerprint(
			items[i].RuleID, items[i].File, items[i].Package, items[i].Message, occurrence,
		)
	}
}

// SortPresentation orders evidence by rule ID, file, line, column, then
// fingerprint so repeated runs render byte-identically.
func SortPresentation(items []Evidence) {
	sort.SliceStable(items, func(i, j int) bool {
		return lessPresentation(items[i], items[j])
	})
}

// SortIdentity orders evidence by the fields that feed the fingerprint. It runs
// before fingerprint assignment so occurrence indexes are reproducible.
func SortIdentity(items []Evidence) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		am, bm := NormalizeMessage(a.Message), NormalizeMessage(b.Message)
		if am != bm {
			return am < bm
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
}

func lessPresentation(a, b Evidence) bool {
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Column != b.Column {
		return a.Column < b.Column
	}
	return a.Fingerprint < b.Fingerprint
}

// Finalize sorts by identity, assigns fingerprints, then sorts for
// presentation. It is the single entry point that turns raw check output into a
// deterministic evidence set.
func Finalize(items []Evidence) []Evidence {
	out := make([]Evidence, len(items))
	copy(out, items)
	SortIdentity(out)
	AssignFingerprints(out)
	SortPresentation(out)
	return out
}

// Comparison is the result of diffing a base evidence set against head.
type Comparison struct {
	New         []Evidence
	Preexisting []Evidence
	Fixed       []Evidence
}

// Compare diffs two finalized evidence sets by fingerprint. Head-only findings
// are new, shared findings are pre-existing debt, base-only findings are fixed.
func Compare(base, head []Evidence) Comparison {
	baseByPrint := make(map[string]Evidence, len(base))
	for _, e := range base {
		baseByPrint[e.Fingerprint] = e
	}
	seen := make(map[string]bool, len(head))

	var cmp Comparison
	for _, e := range head {
		seen[e.Fingerprint] = true
		if _, ok := baseByPrint[e.Fingerprint]; ok {
			e.State = StatePreexisting
			cmp.Preexisting = append(cmp.Preexisting, e)
			continue
		}
		e.State = StateNew
		cmp.New = append(cmp.New, e)
	}
	for _, e := range base {
		if seen[e.Fingerprint] {
			continue
		}
		e.State = StateFixed
		cmp.Fixed = append(cmp.Fixed, e)
	}
	return cmp
}
