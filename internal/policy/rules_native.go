package policy

// Rule IDs produced by the Go toolchain integrations and the native scanners.
const (
	RuleFormatGofmt         = "GH-FMT-001"
	RuleFormatGoimports     = "GH-FMT-002"
	RuleCompile             = "GH-BUILD-001"
	RuleModTidy             = "GH-MOD-001"
	RuleTestFailure         = "GH-TEST-FAIL"
	RuleVet                 = "GO-VET"
	RuleGovulncheck         = "GO-VULN"
	RuleSuppressNolint      = "GH-SUPPRESS-001"
	RuleSuppressStaticcheck = "GH-SUPPRESS-002"
	RuleSuppressNosec       = "GH-SUPPRESS-003"
	RuleSuppressRevive      = "GH-SUPPRESS-004"
	RulePolicyEdit          = "GH-POLICY-001"
	RuleGeneratedEdit       = "GH-POLICY-002"
	RulePolicyGrant         = "GH-POLICY-003"
	RuleCommentEmDash       = "GH-COMMENT-001"
	RuleCommentSize         = "GH-COMMENT-002"
	RuleCommentRestates     = "GH-COMMENT-003"
	RuleTestNoAssertion     = "GH-TEST-001"
	RuleTestSkipped         = "GH-TEST-002"
	RuleTestEmpty           = "GH-TEST-003"
	RuleTestTautology       = "GH-TEST-004"
	RuleTestIgnoredError    = "GH-TEST-005"
	RuleForwardingLayer     = "GH-SIMP-001"
	RuleSoleImplementation  = "GH-SIMP-002"
	RuleDeprecatedNoInline  = "GH-DEPRECATE-001"
)

const goDocFormat = "https://pkg.go.dev/cmd/gofmt"

func goCoreRules() []Rule {
	return []Rule{
		{
			ID:             RuleFormatGofmt,
			Title:          "Source is not gofmt-formatted",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceHygiene,
			Rationale:      "Canonical formatting removes diff noise and is the baseline every Go tool assumes.",
			Enforcement:    "go/format, check-only",
			DocURL:         goDocFormat,
		},
		{
			ID:             RuleFormatGoimports,
			Title:          "Imports are not goimports-normalized",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceHygiene,
			Rationale:      "Unsorted or unused import blocks indicate an edit that was never run through the standard tooling.",
			Enforcement:    "golang.org/x/tools/imports, check-only",
			DocURL:         "https://pkg.go.dev/golang.org/x/tools/cmd/goimports",
		},
		{
			ID:             RuleCompile,
			Title:          "Package does not compile",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceStructural,
			Rationale:      "A change that does not build cannot be judged on any other axis.",
			Enforcement:    "go/packages type checking and go build",
			DocURL:         "https://pkg.go.dev/cmd/go",
		},
		{
			ID:             RuleModTidy,
			Title:          "go.mod or go.sum is not tidy",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceStructural,
			Rationale:      "An untidy module graph hides unused or missing requirements and breaks reproducible builds.",
			Enforcement:    "go mod tidy -diff, check-only",
			DocURL:         "https://pkg.go.dev/cmd/go#hdr-Add_missing_and_remove_unused_modules",
		},
		{
			ID:             RuleVet,
			Title:          "go vet diagnostic",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "go vet is the official correctness analyzer; its diagnostics are almost never false positives.",
			Enforcement:    "go vet -json",
			DocURL:         "https://pkg.go.dev/cmd/vet",
		},
		{
			ID:             RuleTestFailure,
			Title:          "Test failed",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "A failing test in an affected package is direct evidence that the change is not admissible.",
			Enforcement:    "go test -json",
			DocURL:         "https://pkg.go.dev/cmd/go#hdr-Testing_flags",
		},
		{
			ID:             RuleGovulncheck,
			Title:          "Known vulnerability reachable from this module",
			Pack:           PackGoCore,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "Reachable known vulnerabilities are defects with public exploit paths.",
			Enforcement:    "govulncheck, deep mode only",
			DocURL:         "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
		},
	}
}

func agentHygieneRules() []Rule {
	rules := append(suppressionRules(), gateIntegrityRules()...)
	rules = append(rules, simplicityRules()...)
	return append(rules, migrationRules()...)
}

// migrationRules cover a deprecation the author left as manual work. Advisory
// and experimental: the harness asks for the directive, it does not yet refuse
// a change without one.
func migrationRules() []Rule {
	return []Rule{
		{
			ID:             RuleDeprecatedNoInline,
			Title:          "Deprecated declaration without a //go:fix inline directive",
			Pack:           PackAgentHygiene,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleExperimental,
			Consequence:    ConsequenceStructural,
			Rationale:      "A deprecation notice asks every caller to migrate by hand, and the shim then outlives the release it was written for. When the replacement is a single call or value, a //go:fix inline directive lets `go fix` perform that migration at every call site, in this module and in every consumer of it. Advisory because a scanner cannot see whether the author intends the substitution to be automatic.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         "https://go.dev/blog/gofix",
		},
	}
}

// hygieneDoc is the one place the agent-hygiene rules point a reader at.
const hygieneDoc = "https://github.com/ALIBRAGIMOV/goharness/blob/main/docs/architecture.md#native-checks-agent-hygiene"

func suppressionRules() []Rule {
	return []Rule{
		{
			ID:             RuleSuppressNolint,
			Title:          "Inline //nolint suppression directive",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "Suppressing a linter inline silences the evidence instead of fixing the defect; the harness forbids it outright and never grandfathers it.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleSuppressStaticcheck,
			Title:          "Inline //lint:ignore suppression directive",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "Same reasoning as //nolint: suppression must be a reviewed, centrally recorded exception, not an inline comment.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleSuppressNosec,
			Title:          "Inline #nosec suppression directive",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "A #nosec comment silences a security finding at the exact place it was reported; security exceptions must be reviewed centrally, not waved through inline.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleSuppressRevive,
			Title:          "Inline revive:disable suppression directive",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "revive:disable comments switch a linter off for a region of code; like every inline suppression the harness forbids them outright.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
	}
}

func gateIntegrityRules() []Rule {
	return []Rule{
		{
			ID:             RulePolicyEdit,
			Title:          "Change modifies the quality policy",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "A change that edits goharness.yaml or the task contract is altering its own admission gate; that requires an explicit human decision, recorded as allowPolicyEdit in the contract, never a silent edit.",
			Enforcement:    "changed-entry scan (internal/verify), head only",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RulePolicyGrant,
			Title:          "Change grants itself a contract permission",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceUnsafeBehavior,
			Rationale:      "Contract grants such as allowPolicyEdit and allowApiBreak weaken the gate, so they count only when they were committed at the base revision, before the change existed. A grant that appears in the working tree is a change authorising itself, and the harness never honours it.",
			Enforcement:    "contract merge (internal/admission), head only",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleGeneratedEdit,
			Title:          "Generated file edited directly",
			Pack:           PackAgentHygiene,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Consequence:    ConsequenceStructural,
			Rationale:      "A modified file carrying a Code generated header was probably edited by hand; the next generator run will silently erase the edit. Re-run the generator instead. Advisory because a legitimate regeneration looks identical to a hand edit.",
			Enforcement:    "changed-entry scan (internal/verify), head only",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleCommentEmDash,
			Title:          "Em dash U+2014 in a Go comment",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceHygiene,
			Rationale:      "Typographic em dashes do not occur in hand-written Go comments; they mark generated prose that was never reviewed.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleCommentSize,
			Title:          "Oversized documentation comment",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceHygiene,
			Rationale:      "Comments over thirty lines restate design documents inline and drift out of date; over fifteen lines is a warning.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleCommentRestates,
			Title:          "Comment restates the code it precedes",
			Pack:           PackAgentHygiene,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Consequence:    ConsequenceHygiene,
			Rationale:      "A comment that repeats the next statement carries no information and rots independently of the code.",
			Enforcement:    "native token-overlap heuristic (internal/analyze)",
			DocURL:         hygieneDoc,
		},
	}
}

// simplicityRules cover the structure a change adds without needing it. Both
// enter as advisory: the harness's own lifecycle says a rule earns required
// status by being right on real code, and the corpus run is where that is
// measured.
func simplicityRules() []Rule {
	const simplicityDoc = "https://github.com/ALIBRAGIMOV/goharness/blob/main/docs/admission-model.md#quality-dimensions-and-their-evidence"
	return []Rule{
		{
			ID:             RuleForwardingLayer,
			Title:          "Function only forwards its arguments",
			Pack:           PackAgentHygiene,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleExperimental,
			Consequence:    ConsequenceStructural,
			Rationale:      "A function whose body hands its arguments to another function unchanged adds a name and a hop, and every reader now opens two functions to learn what one does. Advisory because an interface implementation or a deprecation shim can look identical.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         simplicityDoc,
		},
		{
			ID:             RuleSoleImplementation,
			Title:          "Unexported interface with a single implementation",
			Pack:           PackAgentHygiene,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleExperimental,
			Consequence:    ConsequenceStructural,
			Rationale:      "An unexported interface that exactly one type in its own package satisfies describes a type that already exists. Go interfaces earn their keep at the consumer, with a second implementation or a test seam behind them; exported ones are excluded because they are a package's contract with the outside.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         simplicityDoc,
		},
	}
}

func testEffectivenessRules() []Rule {
	const testDoc = "https://github.com/ALIBRAGIMOV/goharness/blob/main/docs/architecture.md#native-checks-agent-hygiene"
	return []Rule{
		{
			ID:             RuleTestNoAssertion,
			Title:          "Test observes nothing",
			Pack:           PackTestEffectiveness,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceStructural,
			Rationale:      "A test without an assertion, error check, state observation, or panic expectation only proves the code did not crash.",
			Pattern:        testNoAssertionPattern,
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
		{
			ID:             RuleTestSkipped,
			Title:          "Test skips unconditionally",
			Pack:           PackTestEffectiveness,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceStructural,
			Rationale:      "An unconditional t.Skip as the first statement reports success for work that never ran.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
		{
			ID:             RuleTestEmpty,
			Title:          "Test body is empty",
			Pack:           PackTestEffectiveness,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceStructural,
			Rationale:      "An empty test inflates the test count and the coverage denominator while proving nothing.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
		{
			ID:             RuleTestTautology,
			Title:          "Assertion compares two identical constant expressions",
			Pack:           PackTestEffectiveness,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Consequence:    ConsequenceStructural,
			Rationale:      "A tautological comparison can never fail and therefore tests nothing.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
		{
			ID:             RuleTestIgnoredError,
			Title:          "Error discarded into the blank identifier inside a test",
			Pack:           PackTestEffectiveness,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Consequence:    ConsequenceStructural,
			Rationale:      "Discarding an error in a test hides setup failures and turns a broken test into a passing one.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
	}
}
