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

// TestEveryRuleCarriesAConsequence keeps the consequence mapping total the way
// the dimension mapping is. A rule with no class sorts last and tells a reader
// nothing about what it costs to leave alone, which is the one thing the class
// exists to say.
func TestEveryRuleCarriesAConsequence(t *testing.T) {
	t.Parallel()
	counts := map[policy.Consequence]int{}
	for _, r := range policy.Registry() {
		if !policy.ValidConsequence(r.Consequence) {
			t.Errorf("rule %s has consequence %q, which is not one of the four classes", r.ID, r.Consequence)
			continue
		}
		counts[r.Consequence]++
	}
	for _, class := range []policy.Consequence{
		policy.ConsequenceSilentLoss, policy.ConsequenceUnsafeBehavior,
		policy.ConsequenceStructural, policy.ConsequenceHygiene,
	} {
		if counts[class] == 0 {
			t.Errorf("no rule is classified %s; a class no rule uses is a class the reader cannot trust", class)
		}
		t.Logf("%-16s %d rules", class, counts[class])
	}
}

// TestConsequenceRankOrdersTheClasses pins the order the report presents
// evidence in. Reordering it changes which findings a truncated report shows.
func TestConsequenceRankOrdersTheClasses(t *testing.T) {
	t.Parallel()
	ordered := []policy.Consequence{
		policy.ConsequenceSilentLoss, policy.ConsequenceUnsafeBehavior,
		policy.ConsequenceStructural, policy.ConsequenceHygiene,
	}
	for i := 1; i < len(ordered); i++ {
		if policy.ConsequenceRank(ordered[i-1]) >= policy.ConsequenceRank(ordered[i]) {
			t.Fatalf("%s does not rank before %s", ordered[i-1], ordered[i])
		}
	}
	if policy.ConsequenceRank("") <= policy.ConsequenceRank(policy.ConsequenceHygiene) {
		t.Fatal("an unclassified finding must sort after every classified one")
	}
	if policy.ValidConsequence("") || policy.ValidConsequence("invented") {
		t.Fatal("ValidConsequence accepted a class the model does not define")
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

// TestDuplicationIsCheckedOnce records why GCL-dupl is registered but never
// runs: two full passes were producing two advisory rows about one duplication.
// The entry stays so that evidence recorded before the change still resolves to
// a rule, and this test is what stops it being quietly re-enabled.
func TestDuplicationIsCheckedOnce(t *testing.T) {
	t.Parallel()
	rule, ok := policy.Lookup("GCL-dupl")
	if !ok {
		t.Fatal("GCL-dupl is not registered; a superseded rule keeps its entry")
	}
	if rule.Classification != policy.ClassSuperseded {
		t.Fatalf("classification = %q, want superseded", rule.Classification)
	}
	if slices.Contains(policy.EnabledLinters(), "dupl") {
		t.Fatal("dupl is still enabled, so duplication is computed twice")
	}
	if _, found := policy.Lookup(rule.Enforcement); !found {
		t.Fatalf("GCL-dupl names %q as its enforcement, which is not a registered rule", rule.Enforcement)
	}
	if !strings.Contains(rule.Rationale, "GH-DUP-001") {
		t.Fatal("the rationale does not name the rule that took over")
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

// TestPackageScopedEvidenceIsReachableByAnException covers the evidence that
// belongs to a package rather than to a line, of which a leaked goroutine is
// the standing example.
//
// Matching a scope against the file alone left such a finding unreachable by
// any exception, however narrow and well argued. That is not strictness: the
// rule is outside the mandatory core precisely because it was meant to be
// exceptable, and the gap was an accident of which field happened to be empty.
func TestPackageScopedEvidenceIsReachableByAnException(t *testing.T) {
	t.Parallel()
	cfg := policy.Config{Exceptions: []policy.Exception{{
		RuleID: policy.RuleGoroutineLeak, Scope: "example.com/x/internal/httpserver",
		Reason: "r", Owner: "o", Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}}}
	resolved, err := policy.Resolve(cfg, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	inScope := resolved.Decorate(evidence.Evidence{
		RuleID: policy.RuleGoroutineLeak, Package: "example.com/x/internal/httpserver"})
	if inScope.Classification != evidence.ClassificationAdvisory {
		t.Fatalf("a package-scoped finding was unreachable by its exception: %q", inScope.Classification)
	}
	outOfScope := resolved.Decorate(evidence.Evidence{
		RuleID: policy.RuleGoroutineLeak, Package: "example.com/x/internal/worker"})
	if outOfScope.Classification != evidence.ClassificationRequired {
		t.Fatalf("an exception reached a package it does not name: %q", outOfScope.Classification)
	}
	// The package is a fallback, never an alternative: a finding that names a
	// file is judged on that file, so an exception scoped to the package must not
	// reach a file the exception does not cover.
	elsewhere := resolved.Decorate(evidence.Evidence{
		RuleID: policy.RuleGoroutineLeak, File: "cmd/server/main.go",
		Package: "example.com/x/internal/httpserver"})
	if elsewhere.Classification != evidence.ClassificationRequired {
		t.Fatalf("a package scope excused a finding in a file it does not name: %q",
			elsewhere.Classification)
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

// TestMandatoryCoreDoesNotShrink pins the two sets that decide what no
// configuration and no history can excuse.
//
// Both are listed literally rather than counted, so removing a member is an
// edit to this test rather than a line inside a refactor, and the diff says out
// loud that the gate now accepts something it used to refuse. That is the
// review this repository wants: a draft of the 0.6 plan proposed dropping the
// em-dash rule from the ungrandfatherable set so that a large body of
// pre-existing findings would stop blocking, which would have let an agent
// launder exactly the signal the rule detects by committing before verifying.
// Adding a member is fine and needs only this list extended.
func TestMandatoryCoreDoesNotShrink(t *testing.T) {
	t.Parallel()
	wantMandatory := []string{
		policy.RuleSuppressNolint,
		policy.RuleSuppressStaticcheck,
		policy.RuleSuppressNosec,
		policy.RuleSuppressRevive,
		policy.RulePolicyEdit,
		policy.RulePolicyGrant,
		policy.RuleCommentEmDash,
		policy.RuleCompile,
	}
	wantUngrandfatherable := []string{
		policy.RuleSuppressNolint,
		policy.RuleSuppressStaticcheck,
		policy.RuleSuppressNosec,
		policy.RuleSuppressRevive,
		policy.RulePolicyEdit,
		policy.RulePolicyGrant,
		policy.RuleCommentEmDash,
	}
	assertCoversAll(t, "MandatoryRuleIDs", wantMandatory, policy.MandatoryRuleIDs())
	assertCoversAll(t, "UngrandfatherableRuleIDs", wantUngrandfatherable, policy.UngrandfatherableRuleIDs())
}

func assertCoversAll(t *testing.T, name string, want, got []string) {
	t.Helper()
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Fatalf("%s no longer contains %s; the gate now accepts what it refused, "+
				"which is a policy decision and needs its own justification, not a test edit", name, id)
		}
	}
}

// TestEveryMandatoryRuleIsRefusedAnException keeps the two halves of the core
// consistent: a rule listed as mandatory that configuration could still except
// away would be mandatory in name only.
func TestEveryMandatoryRuleIsRefusedAnException(t *testing.T) {
	t.Parallel()
	for _, id := range policy.MandatoryRuleIDs() {
		src := "exceptions:\n  - rule: " + id +
			"\n    scope: lib/\n    reason: testing the refusal\n    owner: harness\n    expires: 2099-01-01\n"
		if _, err := policy.ParseConfig([]byte(src)); err == nil {
			t.Fatalf("configuration was allowed to except the mandatory rule %s", id)
		}
	}
}
