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
	Rationale           string
	Enforcement         string
	DocURL              string
	PinnedCommit        string
	GoVersionConstraint string
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

// UngrandfatherableRuleIDs lists rules that block whenever they are in scope,
// even when identical evidence exists at the base revision.
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
