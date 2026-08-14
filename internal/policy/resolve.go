package policy

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// ResolvedPolicy is the effective policy for one run: the embedded registry
// plus any strictness raised and any exceptions granted by project
// configuration. It is read-only once resolved.
type ResolvedPolicy struct {
	packs      []string
	rules      map[string]Rule
	exceptions []Exception
	now        time.Time
}

// Resolve composes the embedded packs with optional project configuration.
// Configuration may raise a rule's classification and grant scoped exceptions;
// it can never lower a mandatory rule.
func Resolve(cfg Config, now time.Time) (ResolvedPolicy, error) {
	rules := make(map[string]Rule, 128)
	for _, r := range Registry() {
		rules[r.ID] = r
	}
	for _, ovr := range cfg.Overrides {
		rule, ok := rules[ovr.RuleID]
		if !ok {
			return ResolvedPolicy{}, fmt.Errorf("goharness.yaml: unknown rule %q", ovr.RuleID)
		}
		if rule.Classification == ClassRequired && ovr.Classification == ClassAdvisory {
			return ResolvedPolicy{}, fmt.Errorf("goharness.yaml: rule %q is required and cannot be downgraded", ovr.RuleID)
		}
		rule.Classification = ovr.Classification
		rules[ovr.RuleID] = rule
	}
	for _, exc := range cfg.Exceptions {
		if _, ok := rules[exc.RuleID]; !ok {
			return ResolvedPolicy{}, fmt.Errorf("goharness.yaml: exception references unknown rule %q", exc.RuleID)
		}
	}
	return ResolvedPolicy{
		packs: []string{
			PackGoCore, PackGolangciStrict, PackUberGuide,
			PackAgentHygiene, PackTestEffectiveness,
		},
		rules:      rules,
		exceptions: cfg.Exceptions,
		now:        now,
	}, nil
}

// Packs lists the policy packs composing this policy.
func (p ResolvedPolicy) Packs() []string {
	out := make([]string, len(p.packs))
	copy(out, p.packs)
	return out
}

// Rule looks up an effective rule by ID.
func (p ResolvedPolicy) Rule(id string) (Rule, bool) {
	r, ok := p.rules[id]
	return r, ok
}

// Decorate stamps policy metadata onto raw check output: classification, the
// owning pack, and the documentation URL. Unknown rule IDs stay advisory so an
// unmapped linter can never block a change on policy the operator never saw.
func (p ResolvedPolicy) Decorate(e evidence.Evidence) evidence.Evidence {
	rule, ok := p.rules[e.RuleID]
	if !ok {
		e.PolicySource = PackGolangciStrict
		e.Classification = evidence.ClassificationAdvisory
		return e
	}
	e.PolicySource = rule.Pack
	e.Classification = rule.EvidenceClassification()
	if e.DocURL == "" {
		e.DocURL = rule.DocURL
	}
	if guide := UberRulesEnforcedBy(rule.ID); len(guide) == 1 {
		e.PolicySource = rule.Pack + "+" + guide[0].ID
	}
	if p.excepted(e) {
		e.Classification = evidence.ClassificationAdvisory
	}
	return e
}

func (p ResolvedPolicy) excepted(e evidence.Evidence) bool {
	for _, exc := range p.exceptions {
		if exc.RuleID != e.RuleID {
			continue
		}
		if !p.now.Before(exc.Expires.AddDate(0, 0, 1)) {
			continue
		}
		if scopeMatches(exc.Scope, e.File) {
			return true
		}
	}
	return false
}

func scopeMatches(scope, file string) bool {
	if scope == "" || file == "" {
		return false
	}
	scope = strings.TrimSuffix(scope, "...")
	if strings.HasSuffix(scope, "/") {
		return strings.HasPrefix(file, scope)
	}
	if scope == file {
		return true
	}
	matched, err := path.Match(scope, file)
	return err == nil && matched
}
