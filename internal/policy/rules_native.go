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
	RuleCommentEmDash       = "GH-COMMENT-001"
	RuleCommentSize         = "GH-COMMENT-002"
	RuleCommentRestates     = "GH-COMMENT-003"
	RuleTestNoAssertion     = "GH-TEST-001"
	RuleTestSkipped         = "GH-TEST-002"
	RuleTestEmpty           = "GH-TEST-003"
	RuleTestTautology       = "GH-TEST-004"
	RuleTestIgnoredError    = "GH-TEST-005"
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
			Rationale:      "Reachable known vulnerabilities are defects with public exploit paths.",
			Enforcement:    "govulncheck, deep mode only",
			DocURL:         "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
		},
	}
}

func agentHygieneRules() []Rule {
	const hygieneDoc = "https://github.com/ALIBRAGIMOV/goharness/blob/main/docs/architecture.md#native-checks-agent-hygiene"
	return []Rule{
		{
			ID:             RuleSuppressNolint,
			Title:          "Inline //nolint suppression directive",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
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
			Rationale:      "Same reasoning as //nolint: suppression must be a reviewed, centrally recorded exception, not an inline comment.",
			Enforcement:    "native comment scanner (internal/analyze)",
			DocURL:         hygieneDoc,
		},
		{
			ID:             RuleCommentEmDash,
			Title:          "Em dash U+2014 in a Go comment",
			Pack:           PackAgentHygiene,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
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
			Rationale:      "A comment that repeats the next statement carries no information and rots independently of the code.",
			Enforcement:    "native token-overlap heuristic (internal/analyze)",
			DocURL:         hygieneDoc,
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
			Rationale:      "A test without an assertion, error check, state observation, or panic expectation only proves the code did not crash.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
		{
			ID:             RuleTestSkipped,
			Title:          "Test skips unconditionally",
			Pack:           PackTestEffectiveness,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
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
			Rationale:      "Discarding an error in a test hides setup failures and turns a broken test into a passing one.",
			Enforcement:    "native AST scanner (internal/analyze)",
			DocURL:         testDoc,
		},
	}
}
