// Package policy holds the embedded rule registry, the pinned Uber Go Style
// Guide mapping, and the resolution of project configuration into an effective
// policy. Policy data is immutable and checked in; nothing is fetched at
// runtime.
package policy

import (
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// UberGuideCommit pins the revision of github.com/uber-go/guide that every
// UBER-* registry entry cites. It is recorded in every JSON report.
const UberGuideCommit = "1d60a91aa5e87d443002e23c21903c49489dbde5"

// UberGuideBaseURL is the anchor-less prefix of every UBER-* documentation URL.
const UberGuideBaseURL = "https://github.com/uber-go/guide/blob/" + UberGuideCommit + "/style.md"

// Classification records how a rule participates in the verdict. Only required
// and advisory are reachable from evidence; the remaining values document rules
// the harness knowingly does not automate.
type Classification string

// Rule classifications.
const (
	ClassRequired      Classification = "required"
	ClassAdvisory      Classification = "advisory"
	ClassManual        Classification = "manual"
	ClassNotApplicable Classification = "not-applicable"
	ClassSuperseded    Classification = "superseded"
)

// Lifecycle describes the maturity of a rule inside the harness.
type Lifecycle string

// Rule lifecycles.
const (
	LifecycleExperimental Lifecycle = "experimental"
	LifecycleAdvisory     Lifecycle = "advisory"
	LifecycleRequired     Lifecycle = "required"
	LifecycleDeprecated   Lifecycle = "deprecated"
)

// Consequence says what goes wrong if a finding is left alone. It is triage
// data, never verdict data: the decision rule reads Classification and nothing
// else, and no consequence class makes a required rule advisory or the reverse.
//
// It exists because consequence is wildly uneven inside a single rule set. A
// discarded write to a compliance audit trail and a typographic em dash are
// both "required", and a consumer that allocates effort by count starts with
// whichever is cheapest to emit. The class is the document's own answer to
// "what should I fix first".
type Consequence string

// Consequence classes, in the order a reader should work them.
const (
	// ConsequenceSilentLoss covers data or errors that disappear without a trace:
	// a discarded domain write, a failure returned as nil, an unread iteration
	// error. Nothing observes the loss, so nothing but this finding reports it.
	ConsequenceSilentLoss Consequence = evidence.ConsequenceSilentLoss
	// ConsequenceUnsafeBehavior covers code that can misbehave, exhaust a
	// resource, or be exploited, and the inline suppressions that keep such a
	// finding out of sight.
	ConsequenceUnsafeBehavior Consequence = evidence.ConsequenceUnsafeBehavior
	// ConsequenceStructural covers the shape of the codebase and of its evidence:
	// complexity, globals, layering, broken API contracts, weakened tests.
	ConsequenceStructural Consequence = evidence.ConsequenceStructural
	// ConsequenceHygiene covers findings whose cost is legibility alone.
	ConsequenceHygiene Consequence = evidence.ConsequenceHygiene
)

// ConsequenceRank orders the classes for presentation. An unrecognised or empty
// class sorts last, so evidence from a rule outside the registry never displaces
// evidence the registry can speak for.
func ConsequenceRank(c Consequence) int {
	return evidence.ConsequenceRank(string(c))
}

// ValidConsequence reports whether a class is one of the four the model defines.
func ValidConsequence(c Consequence) bool {
	return ConsequenceRank(c) < 4
}

// Pack names composing the default strict policy.
const (
	PackGoCore            = "go/core"
	PackGoFix             = "go/fix"
	PackGolangciStrict    = "golangci/strict"
	PackUberGuide         = "uber/guide"
	PackAgentHygiene      = "agent/hygiene"
	PackTestEffectiveness = "tests/effectiveness"
)

// Rule is one checked-in policy entry. Rules are data, never behaviour.
type Rule struct {
	ID                  string
	Title               string
	Pack                string
	Classification      Classification
	Lifecycle           Lifecycle
	Consequence         Consequence
	Rationale           string
	Enforcement         string
	DocURL              string
	PinnedCommit        string
	GoVersionConstraint string
	// Pattern is the compliant shape, for the rules whose remediation an operator
	// would otherwise have to design from scratch. Empty for rules whose fix is
	// obvious once the rationale is read.
	Pattern string
}

// EvidenceClassification projects a rule classification onto the two values
// that can appear on evidence. Anything not required is advisory in reports.
func (r Rule) EvidenceClassification() evidence.Classification {
	if r.Classification == ClassRequired {
		return evidence.ClassificationRequired
	}
	return evidence.ClassificationAdvisory
}

// Registry returns every checked-in rule, sorted by ID. The slice is freshly
// built on each call so callers cannot mutate shared policy data.
func Registry() []Rule {
	rules := make([]Rule, 0, 128)
	rules = append(rules, goCoreRules()...)
	rules = append(rules, gofixRules()...)
	rules = append(rules, agentHygieneRules()...)
	rules = append(rules, testEffectivenessRules()...)
	rules = append(rules, golangciRules()...)
	rules = append(rules, riskRules()...)
	rules = append(rules, UberRules()...)
	sortRules(rules)
	return rules
}

// Lookup finds a rule by exact ID.
func Lookup(id string) (Rule, bool) {
	for _, r := range Registry() {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

func sortRules(rules []Rule) {
	slices.SortFunc(rules, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
}

// MandatoryRuleIDs lists rules that project configuration can never downgrade
// or except away. They encode the harness's reason to exist.
func MandatoryRuleIDs() []string {
	return []string{
		RuleSuppressNolint,
		RuleSuppressStaticcheck,
		RuleSuppressNosec,
		RuleSuppressRevive,
		RulePolicyEdit,
		RulePolicyGrant,
		RuleCommentEmDash,
		RuleCompile,
	}
}

// UngrandfatherableRuleIDs lists the rules that block on a pre-existing
// finding as well: everywhere in an audit, and on the lines the change wrote
// in a change gate, where a directive the change rewrote or moved is the
// change's however old it is.
func UngrandfatherableRuleIDs() []string {
	return []string{
		RuleSuppressNolint,
		RuleSuppressStaticcheck,
		RuleSuppressNosec,
		RuleSuppressRevive,
		RulePolicyEdit,
		RulePolicyGrant,
		RuleCommentEmDash,
	}
}

// IsUngrandfatherable reports whether pre-existing evidence for a rule still
// blocks admission.
func IsUngrandfatherable(ruleID string) bool {
	return slices.Contains(UngrandfatherableRuleIDs(), ruleID)
}
