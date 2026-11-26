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

// Origin says where a finding sits relative to the change, which is a different
// question from State. State is identity against the base snapshot: did this
// finding exist before? Origin is location against the diff: is this in code the
// change wrote? A report of a branch needs both, and neither implies the other:
// a change can break a package it never edited, and a file it did edit can carry
// debt older than the change.
//
// The values are ordered from the change outward, and the distance matters. A
// two-valued axis is too coarse: it puts a whole package's debt in the same
// bucket as the lines the author typed, and it gives a reviewer no way to ask
// the question they actually have, which is what this change wrote.
type Origin string

// Finding origins relative to the change under verification, nearest first.
const (
	// OriginAddedLine is a finding on a line the change wrote.
	OriginAddedLine Origin = "added-line"
	// OriginChangedFile is a finding in a file the change edited, on a line that
	// predates it.
	OriginChangedFile Origin = "changed-file"
	// OriginChangedPackage is a finding in a package that holds a changed file,
	// in a file the change did not touch.
	OriginChangedPackage Origin = "changed-package"
	// OriginUntouched is anything else the run had in scope.
	OriginUntouched Origin = "untouched"
	// OriginUnscoped is the zero value: there was no diff to attribute against,
	// which is every audit and every run without a base revision.
	OriginUnscoped Origin = ""
)

// InChange reports a finding located in code the change wrote or edited.
func (o Origin) InChange() bool {
	return o == OriginAddedLine || o == OriginChangedFile
}

// WrittenByChange reports a finding on a line the change wrote, or one the run
// could not place, which is treated as the change's throughout.
func (o Origin) WrittenByChange() bool {
	return o == OriginAddedLine || o == OriginUnscoped
}

// OutsideChange reports a finding the run placed, and placed away from the code
// the change wrote or edited.
//
// A finding the run could not place is not outside anything, and is treated as
// the change's throughout: the honest handling of what the harness does not know
// is never to use it as grounds for leniency.
func (o Origin) OutsideChange() bool {
	return o == OriginChangedPackage || o == OriginUntouched
}

// Classification decides whether a finding can block admission.
type Classification string

// Classifications used by the decision rule.
const (
	ClassificationRequired Classification = "required"
	ClassificationAdvisory Classification = "advisory"
)

// FingerprintLength is the hex length of a truncated evidence fingerprint.
const FingerprintLength = 16

// Remediation is the exact action that closes a finding, for the findings whose
// fix a tool can state rather than guess.
//
// It carries a command and a summary and nothing else: no positions, no byte
// offsets, no patch text. Everything volatile stays out, so the field cannot
// make two runs over an unchanged tree differ, and it is not part of the
// fingerprint, so it cannot change what base and head have in common.
type Remediation struct {
	Command string `json:"command"`
	Summary string `json:"summary,omitempty"`
}

// Evidence is a single normalized finding. Values are immutable once the
// coordinator has assigned states; checks return them by value.
type Evidence struct {
	Fingerprint  string   `json:"fingerprint"`
	RuleID       string   `json:"ruleId"`
	PolicySource string   `json:"policySource"`
	Tool         string   `json:"tool"`
	ToolVersion  string   `json:"toolVersion,omitempty"`
	Severity     Severity `json:"severity"`
	File         string   `json:"file,omitempty"`
	Line         int      `json:"line,omitzero"`
	Column       int      `json:"column,omitzero"`
	Package      string   `json:"package,omitempty"`
	Message      string   `json:"message"`
	// Identity is what makes two findings the same finding, for the producers
	// that know their own answer. Where it is empty the message decides, which is
	// the right inference for a scanner whose message is the finding; where a
	// message carries a timestamp, a goroutine dump, or anything else that moves
	// between runs, inferring identity from it renames the finding every run and a
	// flaky test starts reading as a regression.
	Identity string `json:"identity,omitempty"`
	State    State  `json:"state,omitempty"`
	// Origin is decoration, never identity: it says where the finding sits
	// relative to the diff and never reaches the fingerprint, exactly as
	// Consequence does not.
	Origin         Origin         `json:"origin,omitempty"`
	Classification Classification `json:"classification"`
	// Consequence is what leaving this finding alone costs, taken from the rule
	// and, where a rule covers several remedies, refined by RemedyClass. It orders
	// the document; it never decides the verdict.
	Consequence string `json:"consequence,omitempty"`
	// RemedyClass names the shape of the fix for rules whose findings do not all
	// have the same one. It is what turns hundreds of unchecked-error rows into a
	// handful of decisions.
	RemedyClass string       `json:"remedyClass,omitempty"`
	DocURL      string       `json:"docUrl,omitempty"`
	Fix         *Remediation `json:"fix,omitzero"`
}

// Consequence classes, as they appear on a finding. They are spelled here
// because the finding model is what carries them across every package; the
// policy registry names the same four values as a typed enum and is where a
// rule's class is decided.
const (
	ConsequenceSilentLoss     = "silent-loss"
	ConsequenceUnsafeBehavior = "unsafe-behavior"
	ConsequenceStructural     = "structural"
	ConsequenceHygiene        = "hygiene"
)

// ConsequenceRank orders the classes for presentation. Anything unrecognised,
// the empty string included, sorts last.
func ConsequenceRank(c string) int {
	switch c {
	case ConsequenceSilentLoss:
		return 0
	case ConsequenceUnsafeBehavior:
		return 1
	case ConsequenceStructural:
		return 2
	case ConsequenceHygiene:
		return 3
	default:
		return 4
	}
}

// NormalizeMessage collapses whitespace and strips volatile substrings so that
// the same underlying defect hashes identically across runs and machines.
func NormalizeMessage(msg string) string {
	return strings.Join(strings.Fields(msg), " ")
}

// Fingerprint derives the stable identity of a finding. Line and column are
// deliberately excluded: unrelated edits shift them without changing identity.
func Fingerprint(ruleID, file, pkg, message string, occurrence int) string {
	return fingerprintOf(ruleID, file, pkg, identityMessage(message), occurrence)
}

func fingerprintOf(ruleID, file, pkg, identity string, occurrence int) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		ruleID,
		file,
		pkg,
		identity,
		strconv.Itoa(occurrence),
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:FingerprintLength]
}

// identityOf is what a finding is named by: the identity its producer stated,
// or the part of its message that says which finding it is.
func identityOf(e Evidence) string {
	if e.Identity != "" {
		return e.Identity
	}
	return identityMessage(e.Message)
}

// identityMessage reduces a message to the part that says which finding it is:
// whitespace collapsed, every run of digits masked.
//
// The numbers a message carries are measurements, and a measurement moves while
// the finding stays the same one: a function still over the complexity budget
// at 27 instead of 30, a line number that shifted, a value a failing test
// printed. Leaving them in the identity made every such move look like a brand
// new finding, which blocks a change for partly repairing old debt and lets a
// gate punish an improvement. Masking them is the same reasoning that already
// keeps line and column out.
//
// One pass and one allocation: this runs for every finding of every run, and a
// benchmark in this package holds it to that.
func identityMessage(message string) string {
	var out strings.Builder
	out.Grow(len(message))
	// Text is copied a run at a time rather than a character at a time: this is
	// the hot path of every report, and the bytes it skips (whitespace and
	// digits) are all ASCII, so scanning bytes stays correct for UTF-8 input.
	copied, inDigits, pendingSpace := 0, false, false
	emit := func(end int) {
		if end <= copied {
			return
		}
		if pendingSpace && out.Len() > 0 {
			out.WriteByte(' ')
		}
		pendingSpace = false
		out.WriteString(message[copied:end])
	}
	for i := range len(message) {
		switch c := message[i]; {
		case isSpaceByte(c):
			emit(i)
			copied, inDigits = i+1, false
			pendingSpace = out.Len() > 0
		case c >= '0' && c <= '9':
			emit(i)
			copied = i + 1
			if !inDigits {
				if pendingSpace && out.Len() > 0 {
					out.WriteByte(' ')
					pendingSpace = false
				}
				out.WriteByte('#')
				inDigits = true
			}
		case inDigits:
			copied, inDigits = i, false
		}
	}
	emit(len(message))
	return out.String()
}

func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// identified pairs a finding with its identity, so the identity is computed
// once per finding instead of twice per comparison.
type identified struct {
	item     Evidence
	identity string
}

// assignFingerprints numbers occurrences within each identity group in the
// order the slice already establishes, so a repeated finding keeps a stable
// name. Callers must sort deterministically first.
func assignFingerprints(items []identified) {
	counts := make(map[string]int, len(items))
	for i := range items {
		key := strings.Join([]string{
			items[i].item.RuleID,
			items[i].item.File,
			items[i].item.Package,
			items[i].identity,
		}, "\x00")
		occurrence := counts[key]
		counts[key] = occurrence + 1
		items[i].item.Fingerprint = fingerprintOf(
			items[i].item.RuleID, items[i].item.File, items[i].item.Package,
			items[i].identity, occurrence)
	}
}

// SortPresentation orders evidence by consequence class, then by rule ID, file,
// line, column and fingerprint so repeated runs render byte-identically.
//
// Consequence leads because the document is read in order and a consumer that
// allocates effort by position should meet the silent data loss before the
// typography. It is presentation only: sortIdentity, which decides occurrence
// indexes and therefore fingerprints, must never learn about it, or every
// repeated finding would be renamed by a change to a rule's class.
func SortPresentation(items []Evidence) {
	sort.SliceStable(items, func(i, j int) bool {
		return lessPresentation(items[i], items[j])
	})
}

// sortIdentity orders findings by the fields that feed the fingerprint. It runs
// before fingerprint assignment so occurrence indexes are reproducible.
func sortIdentity(items []identified) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.item.RuleID != b.item.RuleID {
			return a.item.RuleID < b.item.RuleID
		}
		if a.item.File != b.item.File {
			return a.item.File < b.item.File
		}
		if a.item.Package != b.item.Package {
			return a.item.Package < b.item.Package
		}
		if a.identity != b.identity {
			return a.identity < b.identity
		}
		if a.item.Line != b.item.Line {
			return a.item.Line < b.item.Line
		}
		return a.item.Column < b.item.Column
	})
}

func lessPresentation(a, b Evidence) bool {
	if ra, rb := ConsequenceRank(a.Consequence), ConsequenceRank(b.Consequence); ra != rb {
		return ra < rb
	}
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
	indexed := make([]identified, len(items))
	for i, item := range items {
		indexed[i] = identified{item: item, identity: identityOf(item)}
	}
	sortIdentity(indexed)
	assignFingerprints(indexed)

	out := make([]Evidence, len(indexed))
	for i, entry := range indexed {
		out[i] = entry.item
	}
	SortPresentation(out)
	return out
}

// Realign renames a base evidence set into the coordinate system of head, so a
// file the change moved keeps the findings it already had.
//
// The file is part of a finding's identity. Without this, moving a file makes
// every finding in it absent at base and therefore new, which blocks; and makes
// every base twin absent at head and therefore fixed, which credits a repair
// nobody performed. A branch that reorganises code would be rejected for defects
// it did not introduce.
//
// The base side is rewritten rather than the head side, and the set is
// renumbered afterwards, because head's fingerprints are the ones the report
// publishes and a reader has to be able to look one up. Renaming only moves
// findings between identity groups; a finding whose file the map does not name
// keeps its group, its occurrence index and therefore its fingerprint.
func Realign(items []Evidence, renames map[string]string) []Evidence {
	if len(renames) == 0 || len(items) == 0 {
		return items
	}
	moved := make([]Evidence, 0, len(items))
	touched := false
	for _, e := range items {
		if to, ok := renames[e.File]; ok && to != e.File {
			e.File = to
			touched = true
		}
		moved = append(moved, e)
	}
	if !touched {
		return items
	}
	return Finalize(moved)
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
