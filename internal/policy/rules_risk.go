package policy

// Rule IDs for the risk-activated native scanners and the base/head comparison
// producers introduced with the admission model.
const (
	RuleGoroutineLifetime = "GH-CONC-001"
	RuleGoroutineInLoop   = "GH-CONC-002"
	RuleTimerInLoop       = "GH-RES-001"
	RuleVariableChanBuf   = "GH-RES-002"
	RuleClientTimeout     = "GH-NET-001"
	RuleRequestContext    = "GH-NET-002"
	RuleUnboundedRetry    = "GH-NET-003"
	RuleTxNotResolved     = "GH-SQL-001"
	RuleMigrationRewrite  = "GH-SQL-002"
	RuleBannedPackageName = "GH-ARCH-001"
	RuleForbiddenImport   = "GH-ARCH-002"
	RuleComplexity        = "GH-CX-001"
	RuleNesting           = "GH-CX-002"
	RuleFunctionLength    = "GH-CX-003"
	RuleComplexityDelta   = "GH-MNT-001"
	RuleDocCoverageDelta  = "GH-MNT-002"
	RuleFanOutDelta       = "GH-MNT-003"
	RuleClone             = "GH-DUP-001"
	RuleAssertionRemoved  = "GH-WEAK-001"
	RuleSkipAdded         = "GH-WEAK-002"
	RuleTestDeleted       = "GH-WEAK-003"
	RuleToleranceWidened  = "GH-WEAK-004"
	RuleMutantsSurvived   = "GH-MUT-001"
	RuleAPIBreak          = "GH-API-001"
	RuleBenchTimeDelta    = "GH-PERF-001"
	RuleBenchAllocDelta   = "GH-PERF-002"
	RuleScopeViolation    = "GH-SCOPE-001"
)

// Policy packs introduced with the admission model.
const (
	PackRiskConcurrency = "risk/concurrency"
	PackRiskNetwork     = "risk/network"
	PackRiskPersistence = "risk/persistence"
	PackArchitecture    = "architecture/layout"
	PackMaintainability = "maintainability/metrics"
	PackDiffEvidence    = "diff/evidence"
	PackContract        = "contract/scope"
)

const modelDoc = "https://github.com/ALIBRAGIMOV/goharness/blob/main/docs/admission-model.md"

func riskRules() []Rule {
	return append(concurrencyRules(), append(networkRules(),
		append(persistenceRules(), append(architectureRules(),
			append(maintainabilityRules(), diffEvidenceRules()...)...)...)...)...)
}

func concurrencyRules() []Rule {
	return []Rule{
		{
			ID:             RuleGoroutineLifetime,
			Title:          "Goroutine has no discoverable termination path",
			Pack:           PackRiskConcurrency,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "A goroutine launched from a function that already holds a context, while ignoring that context and every other stop signal, cannot be stopped or waited for; its lifetime is unbounded by construction.",
			Enforcement:    "native concurrency scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleGoroutineInLoop,
			Title:          "Goroutine spawned in a loop without a bound",
			Pack:           PackRiskConcurrency,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Spawning one goroutine per iteration with no semaphore, errgroup limit, or token channel makes concurrency a function of input size rather than of available resources.",
			Enforcement:    "native concurrency scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleTimerInLoop,
			Title:          "time.After inside a loop",
			Pack:           PackRiskConcurrency,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "time.After allocates a timer that is not collected until it fires, so a loop accumulates timers for the whole duration of the longest one.",
			Enforcement:    "native resource scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleVariableChanBuf,
			Title:          "Channel buffer sized from a variable",
			Pack:           PackRiskConcurrency,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "A buffer whose size comes from input makes memory use a function of that input; the size deserves an explicit bound, but only the author knows whether one already applies.",
			Enforcement:    "native resource scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
	}
}

func networkRules() []Rule {
	return []Rule{
		{
			ID:             RuleClientTimeout,
			Title:          "HTTP client without a timeout",
			Pack:           PackRiskNetwork,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "An http.Client with a zero Timeout waits forever; one unresponsive peer then holds a caller, and eventually every caller, indefinitely.",
			Enforcement:    "native network scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleRequestContext,
			Title:          "Request built without a context",
			Pack:           PackRiskNetwork,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "http.NewRequest and the package-level helpers cannot be cancelled; the caller's deadline never reaches the transport.",
			Enforcement:    "native network scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleUnboundedRetry,
			Title:          "Retry loop with no attempt bound",
			Pack:           PackRiskNetwork,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "A retry loop that sleeps but never counts attempts turns a peer outage into an indefinite hold. Detecting the bound reliably needs intent, so this reports rather than blocks.",
			Enforcement:    "native network scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
	}
}

func persistenceRules() []Rule {
	return []Rule{
		{
			ID:             RuleTxNotResolved,
			Title:          "Transaction is neither committed nor rolled back",
			Pack:           PackRiskPersistence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "A transaction opened without a commit or rollback on every path holds locks and a pooled connection until the server times it out.",
			Enforcement:    "native persistence scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleMigrationRewrite,
			Title:          "Existing migration modified or deleted",
			Pack:           PackRiskPersistence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Migrations are append-only history: rewriting one that has already run leaves deployed databases in a state no migration path reproduces.",
			Enforcement:    "change-set inspection (internal/verify)",
			DocURL:         modelDoc,
		},
	}
}

func architectureRules() []Rule {
	return []Rule{
		{
			ID:             RuleBannedPackageName,
			Title:          "Package name carries no meaning",
			Pack:           PackArchitecture,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Names such as util, common, or manager describe no domain, so they accumulate unrelated code and become import magnets that defeat layering.",
			Enforcement:    "native architecture scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleForbiddenImport,
			Title:          "Import violates a declared dependency direction",
			Pack:           PackArchitecture,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Layering only holds if the direction is checked; the rules come from the project's own goharness.yaml, so the harness never invents an architecture.",
			Enforcement:    "native architecture scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleAPIBreak,
			Title:          "Exported API removed or changed incompatibly",
			Pack:           PackArchitecture,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Removing or re-signing an exported symbol breaks every dependent build. The contract may allow it deliberately with AllowAPIBreak; silence may not.",
			Enforcement:    "export-surface diff via go/types (internal/analyze)",
			DocURL:         modelDoc,
		},
	}
}

func maintainabilityRules() []Rule {
	return []Rule{
		{
			ID:             RuleComplexity,
			Title:          "Function exceeds the complexity budget",
			Pack:           PackMaintainability,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Past roughly twenty-five independent paths a function cannot be reasoned about or covered by tests in any complete way.",
			Enforcement:    "native metrics scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleNesting,
			Title:          "Function exceeds the nesting budget",
			Pack:           PackMaintainability,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Beyond five levels the reader must hold more context than the code makes visible; early returns or extraction restore it.",
			Enforcement:    "native metrics scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleFunctionLength,
			Title:          "Function is long",
			Pack:           PackMaintainability,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "Length alone is weak evidence: a long flat table is fine and a short dense function is not, so this informs review rather than blocking it.",
			Enforcement:    "native metrics scanner (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleComplexityDelta,
			Title:          "Change makes a function substantially more complex",
			Pack:           PackMaintainability,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "A single change adding ten or more independent paths to one function is a design decision that must be visible, not a side effect.",
			Enforcement:    "maintainability delta, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleDocCoverageDelta,
			Title:          "Exported documentation coverage decreased",
			Pack:           PackMaintainability,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "New exported symbols without doc comments erode the package's public contract gradually rather than all at once.",
			Enforcement:    "maintainability delta, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleFanOutDelta,
			Title:          "Package fan-out increased",
			Pack:           PackMaintainability,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "Each new import is a new coupling; a rising fan-out is the earliest measurable sign that a package is losing its focus.",
			Enforcement:    "maintainability delta, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleClone,
			Title:          "Changed code duplicates a nearby function body",
			Pack:           PackMaintainability,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "Copied logic drifts apart under maintenance. Whether the right answer is extraction or deliberate separation is a design call, so this reports.",
			Enforcement:    "native clone scanner (internal/analyze) alongside the dupl linter",
			DocURL:         modelDoc,
		},
	}
}

func diffEvidenceRules() []Rule {
	return []Rule{
		{
			ID:             RuleAssertionRemoved,
			Title:          "Assertion removed from a surviving test",
			Pack:           PackDiffEvidence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Deleting an assertion while the code it observed remains turns a test that could fail into one that cannot; it is the cheapest way to make a suite lie.",
			Enforcement:    "anti-weakening diff, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleSkipAdded,
			Title:          "Skip added to an existing test",
			Pack:           PackDiffEvidence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "A newly skipped test reports success for work that no longer runs.",
			Enforcement:    "anti-weakening diff, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleTestDeleted,
			Title:          "Test deleted while its subject survives",
			Pack:           PackDiffEvidence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Removing a test without removing what it tested silently reduces the evidence the suite can produce.",
			Enforcement:    "anti-weakening diff, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleToleranceWidened,
			Title:          "Numeric tolerance widened in a test",
			Pack:           PackDiffEvidence,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleAdvisory,
			Rationale:      "A loosened bound can be a correct recalibration or a way to hide a regression; the diff cannot tell which, so a human must.",
			Enforcement:    "anti-weakening diff, base against head (internal/analyze)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleMutantsSurvived,
			Title:          "No test observed any mutation of the changed code",
			Pack:           PackDiffEvidence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "If every deliberate defect injected into the changed functions still passes the suite, the tests execute the code without observing it.",
			Enforcement:    "overlay mutation engine (internal/verify)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleBenchTimeDelta,
			Title:          "Benchmark time regressed beyond the budget",
			Pack:           PackDiffEvidence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "A declared hot path that slows measurably beyond sample spread has regressed; the budget makes the acceptable amount explicit.",
			Enforcement:    "base/head benchmark comparison (internal/tool)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleBenchAllocDelta,
			Title:          "Benchmark allocations regressed beyond the budget",
			Pack:           PackDiffEvidence,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "Allocation counts are the least noisy performance signal Go exposes; a rise in them is a real change in behaviour.",
			Enforcement:    "base/head benchmark comparison (internal/tool)",
			DocURL:         modelDoc,
		},
		{
			ID:             RuleScopeViolation,
			Title:          "File changed outside the declared scope",
			Pack:           PackContract,
			Classification: ClassRequired,
			Lifecycle:      LifecycleRequired,
			Rationale:      "A contract that declares where a change may land is only meaningful if edits outside it are reported; unscoped edits are the usual shape of an accidental change.",
			Enforcement:    "scope conformance scan (internal/verify)",
			DocURL:         modelDoc,
		},
	}
}
