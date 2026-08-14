package policy_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

func TestRegistryEntriesAreComplete(t *testing.T) {
	rules := policy.Registry()
	if len(rules) < 40 {
		t.Fatalf("registry has only %d rules; the packs are not all wired up", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.ID] {
			t.Fatalf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Rationale == "" || r.Enforcement == "" || r.DocURL == "" {
			t.Fatalf("rule %q is missing required metadata: %+v", r.ID, r)
		}
		if r.Pack == "" || r.Classification == "" || r.Lifecycle == "" {
			t.Fatalf("rule %q is missing classification metadata: %+v", r.ID, r)
		}
	}
}

func TestRegistryIsSortedByID(t *testing.T) {
	rules := policy.Registry()
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	if !slices.IsSorted(ids) {
		t.Fatalf("registry is not sorted: %v", ids)
	}
}

func TestUberRulesCitePinnedCommit(t *testing.T) {
	rules := policy.UberRules()
	if len(rules) < 20 {
		t.Fatalf("only %d Uber rules registered", len(rules))
	}
	for _, r := range rules {
		if r.PinnedCommit != policy.UberGuideCommit {
			t.Fatalf("rule %q pins %q, want %q", r.ID, r.PinnedCommit, policy.UberGuideCommit)
		}
		if !strings.HasPrefix(r.DocURL, policy.UberGuideBaseURL+"#") {
			t.Fatalf("rule %q doc URL %q does not anchor into the pinned guide", r.ID, r.DocURL)
		}
		if !strings.HasPrefix(r.ID, "UBER-") {
			t.Fatalf("guide rule has non-UBER ID %q", r.ID)
		}
	}
}

func TestUberEnforcementReferencesRealRules(t *testing.T) {
	for _, r := range policy.UberRules() {
		if r.Enforcement == "manual" || !strings.Contains(r.Enforcement, "-") {
			continue
		}
		if _, ok := policy.Lookup(r.Enforcement); !ok {
			t.Fatalf("rule %q claims enforcement by unknown rule %q", r.ID, r.Enforcement)
		}
	}
}

func TestLoopVariableRuleIsSuperseded(t *testing.T) {
	rule, ok := policy.Lookup("UBER-LOO-001")
	if !ok {
		t.Fatal("UBER-LOO-001 is not registered")
	}
	if rule.Classification != policy.ClassSuperseded {
		t.Fatalf("classification = %q, want superseded", rule.Classification)
	}
	if rule.GoVersionConstraint != ">=1.22" {
		t.Fatalf("go constraint = %q, want >=1.22", rule.GoVersionConstraint)
	}
}

// TestEnabledLintersMatchEmbeddedConfig keeps the Go-side rule registry and the
// embedded YAML from drifting apart, which would silently produce evidence with
// no policy entry.
func TestEnabledLintersMatchEmbeddedConfig(t *testing.T) {
	fromConfig := enabledLintersInYAML(t, string(tool.StrictConfig()))
	fromRegistry := policy.EnabledLinters()
	if !slices.Equal(fromConfig, fromRegistry) {
		t.Fatalf("embedded config enables %v but the registry describes %v", fromConfig, fromRegistry)
	}
	for _, name := range fromRegistry {
		if _, ok := policy.Lookup("GCL-" + name); !ok {
			t.Fatalf("linter %q has no GCL- rule in the registry", name)
		}
	}
}

func enabledLintersInYAML(t *testing.T, cfg string) []string {
	t.Helper()
	var out []string
	inEnable := false
	for line := range strings.SplitSeq(cfg, "\n") {
		switch {
		case strings.TrimSpace(line) == "enable:":
			inEnable = true
		case inEnable && strings.HasPrefix(line, "    - "):
			out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "    - ")))
		case inEnable && strings.TrimSpace(line) != "":
			inEnable = false
		}
	}
	if len(out) == 0 {
		t.Fatal("no enabled linters found in the embedded config")
	}
	return out
}

func TestSuppressionRulesAreMandatoryAndUngrandfatherable(t *testing.T) {
	for _, id := range []string{policy.RuleSuppressNolint, policy.RuleSuppressStaticcheck, policy.RuleCommentEmDash} {
		if !slices.Contains(policy.MandatoryRuleIDs(), id) {
			t.Fatalf("%s is not mandatory", id)
		}
		if !policy.IsUngrandfatherable(id) {
			t.Fatalf("%s can be grandfathered as pre-existing debt", id)
		}
	}
	if policy.IsUngrandfatherable("GCL-errcheck") {
		t.Fatal("GCL-errcheck should be grandfatherable as pre-existing debt")
	}
}

func TestParseConfigAcceptsTheDocumentedShape(t *testing.T) {
	cfg, err := policy.ParseConfig([]byte(`
# a comment
exceptions:
  - rule: GCL-gosec
    scope: internal/legacy/
    reason: scheduled for rewrite in Q3
    owner: platform-team
    expires: 2030-01-31
rules:
  - id: GCL-modernize
    classification: required
`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Exceptions) != 1 || cfg.Exceptions[0].Owner != "platform-team" {
		t.Fatalf("exceptions = %+v", cfg.Exceptions)
	}
	if len(cfg.Overrides) != 1 || cfg.Overrides[0].Classification != policy.ClassRequired {
		t.Fatalf("overrides = %+v", cfg.Overrides)
	}
}

func TestParseConfigRejectsIncompleteExceptions(t *testing.T) {
	cases := map[string]string{
		"missing owner":   "exceptions:\n  - rule: GCL-gosec\n    scope: a/\n    reason: r\n    expires: 2030-01-01\n",
		"missing expiry":  "exceptions:\n  - rule: GCL-gosec\n    scope: a/\n    reason: r\n    owner: o\n",
		"bad expiry":      "exceptions:\n  - rule: GCL-gosec\n    scope: a/\n    reason: r\n    owner: o\n    expires: soon\n",
		"unknown section": "surprises:\n  - id: x\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.ParseConfig([]byte(src)); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestMandatoryRulesCannotBeExceptedOrDowngraded(t *testing.T) {
	_, err := policy.ParseConfig([]byte(
		"exceptions:\n  - rule: GH-SUPPRESS-001\n    scope: a/\n    reason: r\n    owner: o\n    expires: 2030-01-01\n"))
	if err == nil {
		t.Fatal("an exception for a mandatory rule was accepted")
	}

	cfg := policy.Config{Overrides: []policy.RuleOverride{
		{RuleID: policy.RuleCommentEmDash, Classification: policy.ClassAdvisory},
	}}
	if _, err := policy.Resolve(cfg, time.Now()); err == nil {
		t.Fatal("a required rule was downgraded to advisory")
	}
}

func TestDecorateAppliesClassificationAndScopedExceptions(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := policy.Config{Exceptions: []policy.Exception{{
		RuleID: "GCL-gosec", Scope: "internal/legacy/", Reason: "r", Owner: "o",
		Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}}}
	resolved, err := policy.Resolve(cfg, now)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	inScope := resolved.Decorate(evidence.Evidence{RuleID: "GCL-gosec", File: "internal/legacy/a.go"})
	if inScope.Classification != evidence.ClassificationAdvisory {
		t.Fatalf("excepted finding classification = %q, want advisory", inScope.Classification)
	}
	outOfScope := resolved.Decorate(evidence.Evidence{RuleID: "GCL-gosec", File: "internal/current/a.go"})
	if outOfScope.Classification != evidence.ClassificationRequired {
		t.Fatalf("out-of-scope finding classification = %q, want required", outOfScope.Classification)
	}
	if outOfScope.DocURL == "" || outOfScope.PolicySource == "" {
		t.Fatalf("decoration left metadata empty: %+v", outOfScope)
	}
}

func TestExpiredExceptionsStopApplying(t *testing.T) {
	cfg := policy.Config{Exceptions: []policy.Exception{{
		RuleID: "GCL-gosec", Scope: "a/", Reason: "r", Owner: "o",
		Expires: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}}}
	resolved, err := policy.Resolve(cfg, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := resolved.Decorate(evidence.Evidence{RuleID: "GCL-gosec", File: "a/x.go"})
	if got.Classification != evidence.ClassificationRequired {
		t.Fatalf("expired exception still applies: %q", got.Classification)
	}
}

func TestUnknownRuleIDsStayAdvisory(t *testing.T) {
	resolved, err := policy.Resolve(policy.Config{}, time.Now())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := resolved.Decorate(evidence.Evidence{RuleID: "GCL-someLinterWeNeverEnabled", File: "a.go"})
	if got.Classification != evidence.ClassificationAdvisory {
		t.Fatalf("unmapped rule classification = %q, want advisory", got.Classification)
	}
}
