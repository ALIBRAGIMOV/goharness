package policy

import "strings"

type uberSpec struct {
	id             string
	title          string
	anchor         string
	classification Classification
	lifecycle      Lifecycle
	consequence    Consequence
	rationale      string
	enforcement    string
	goConstraint   string
}

// UberRules returns the checked-in mapping from Uber Go Style Guide sections to
// harness rule IDs, each citing the pinned guide commit.
func UberRules() []Rule {
	specs := uberSpecs()
	rules := make([]Rule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, Rule{
			ID:                  s.id,
			Title:               s.title,
			Pack:                PackUberGuide,
			Classification:      s.classification,
			Lifecycle:           s.lifecycle,
			Consequence:         s.consequence,
			Rationale:           s.rationale,
			Enforcement:         s.enforcement,
			DocURL:              UberGuideBaseURL + "#" + s.anchor,
			PinnedCommit:        UberGuideCommit,
			GoVersionConstraint: s.goConstraint,
		})
	}
	return rules
}

// UberRulesEnforcedBy returns the guide rules whose enforcement mechanism is the
// given harness rule ID, so a linter finding can cite its style-guide origin.
func UberRulesEnforcedBy(ruleID string) []Rule {
	var out []Rule
	for _, r := range UberRules() {
		if id, _ := EnforcementParts(r.Enforcement); id == ruleID {
			out = append(out, r)
		}
	}
	return out
}

// EnforcementParts splits an enforcement into the harness rule that produces the
// evidence and, for a rule that reports several checks under one ID (go vet,
// revive), the check inside it. A qualified enforcement still lists the guide
// rule under that ID, but it never labels the ID's evidence: most of what go vet
// reports is not a copied lock.
func EnforcementParts(enforcement string) (ruleID, check string) {
	ruleID, check, _ = strings.Cut(enforcement, " ")
	return ruleID, check
}

func uberSpecs() []uberSpec {
	return append(uberEnforcedSpecs(), uberManualSpecs()...)
}

func uberEnforcedSpecs() []uberSpec {
	return []uberSpec{
		{
			id: "UBER-ERR-001", title: "Handle every returned error", consequence: ConsequenceSilentLoss,
			anchor: "linting", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "The guide's minimum linter set includes errcheck, to ensure that errors are handled. An ignored error discards the only signal that an operation failed.",
			enforcement: "GCL-errcheck",
		},
		{
			id: "UBER-TYP-001", title: "Use the comma-ok form for type assertions", consequence: ConsequenceUnsafeBehavior,
			anchor: "handle-type-assertion-failures", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "A single-value type assertion panics on an unexpected dynamic type; the two-value form turns that into a handled branch.",
			enforcement: "GCL-forcetypeassert",
		},
		{
			id: "UBER-GLO-001", title: "Avoid mutable package-level globals", consequence: ConsequenceStructural,
			anchor: "avoid-mutable-globals", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Mutable globals couple unrelated code through hidden state and make tests order-dependent; dependency injection is the guide's prescribed alternative.",
			enforcement: "GCL-gochecknoglobals",
		},
		{
			id: "UBER-INI-001", title: "Avoid init() and its side effects", consequence: ConsequenceStructural,
			anchor: "avoid-init", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "init runs implicitly, in an order callers cannot control or observe, and cannot report an error.",
			enforcement: "GCL-gochecknoinits",
		},
		{
			id: "UBER-NAM-001", title: "Do not shadow built-in names", consequence: ConsequenceHygiene,
			anchor: "avoid-using-built-in-names", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Shadowing a predeclared identifier changes what surrounding code means without changing how it reads.",
			enforcement: "GCL-predeclared",
		},
		{
			id: "UBER-TAG-001", title: "Use field tags in marshaled structs", consequence: ConsequenceStructural,
			anchor: "use-field-tags-in-marshaled-structs", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Without tags the serialized form follows Go field names, so an internal rename silently breaks the wire format. musttag reports a marshaled field without a tag; go vet's structtag pass checks that the tags present are well formed.",
			enforcement: "GCL-musttag",
		},
		{
			id: "UBER-ERR-002", title: "Wrap errors with context", consequence: ConsequenceSilentLoss,
			anchor: "error-wrapping", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Comparisons and type checks must survive wrapping; %v formatting and == comparison break errors.Is and errors.As.",
			enforcement: "GCL-errorlint",
		},
		{
			id: "UBER-ERR-003", title: "Name sentinel errors Err* and error types *Error", consequence: ConsequenceHygiene,
			anchor: "error-naming", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Consistent naming makes the intended comparison strategy visible at the call site.",
			enforcement: "GCL-errname",
		},
		{
			id: "UBER-ERR-004", title: "Do not log and return the same error", consequence: ConsequenceStructural,
			anchor: "handle-errors-once", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Logging an error and returning it reports one incident many times. The guide asks a caller to handle each error once: match it, degrade and log it, or return it, and not two of these.",
			enforcement: "manual",
		},
		{
			id: "UBER-PAN-001", title: "Do not panic in library code", consequence: ConsequenceUnsafeBehavior,
			anchor: "dont-panic", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "A panic in a library removes the caller's ability to recover a request; return an error instead. No linter in the pinned golangci-lint set distinguishes library panics from main-package fatal paths reliably enough to block on.",
			enforcement: "manual",
		},
		{
			id: "UBER-EXI-001", title: "Call os.Exit or log.Fatal only from main", consequence: ConsequenceUnsafeBehavior,
			anchor: "exit-in-main", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Exiting outside main skips deferred cleanup and denies callers any recovery path. revive's deep-exit rule, enabled in the strict pack, reports os.Exit and log.Fatal outside main and init under the GCL-revive rule ID.",
			enforcement: "GCL-revive deep-exit",
		},
		{
			id: "UBER-STY-002", title: "Use typed atomic values", consequence: ConsequenceHygiene,
			anchor: "use-gouberorgatomic", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "The guide recommends go.uber.org/atomic because sync/atomic's functions on plain integers make it easy to forget the atomic operation on one access. Since Go 1.19 sync/atomic has typed values (atomic.Int64, atomic.Bool, atomic.Pointer) with the same guarantee and no dependency, and go fix's atomictypes analyzer reports the plain-integer form.",
			enforcement: GoFixRuleID("atomictypes"), goConstraint: ">=1.19",
		},
		{
			id: "UBER-GOR-001", title: "Don't fire-and-forget goroutines", consequence: ConsequenceUnsafeBehavior,
			anchor: "dont-fire-and-forget-goroutines", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Every goroutine needs a predictable time to stop and a way to wait for it. The guide recommends testing for leaks with goleak; the harness reads the runtime's own goroutineleak profile in the race run instead, and GH-CONC-001 reports a spawn whose termination path is not visible where it starts.",
			enforcement: RuleGoroutineLeak,
		},
		{
			id: "UBER-PKG-001", title: "Package names carry meaning", consequence: ConsequenceStructural,
			anchor: "package-names", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "The guide rejects common, util, shared and lib as bad, uninformative package names. GH-ARCH-001 refuses common, shared and util among its names; lib, the guide's fourth example, is not on its list.",
			enforcement: RuleBannedPackageName,
		},
		{
			id: "UBER-NST-001", title: "Reduce nesting", consequence: ConsequenceStructural,
			anchor: "reduce-nesting", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Handling errors and special cases first and returning early keeps the main path at the left margin. GH-CX-002 holds each function to a nesting budget.",
			enforcement: RuleNesting,
		},
		{
			id: "UBER-IMP-001", title: "Two import groups: standard library, then everything else", consequence: ConsequenceHygiene,
			anchor: "import-group-ordering", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "The guide's grouping is the one goimports applies by default, and GH-FMT-002 reports any file goimports would rewrite.",
			enforcement: RuleFormatGoimports,
		},
		{
			id: "UBER-PRF-001", title: "Prefer strconv over fmt", consequence: ConsequenceHygiene,
			anchor: "prefer-strconv-over-fmt", classification: ClassAdvisory, lifecycle: LifecycleExperimental,
			rationale:   "When converting primitives to and from strings, the guide measures strconv as faster than fmt, which formats through reflection and allocates.",
			enforcement: "GCL-perfsprint",
		},
		{
			id: "UBER-PRT-001", title: "Name printf-style functions with a trailing f", consequence: ConsequenceHygiene,
			anchor: "naming-printf-style-functions", classification: ClassAdvisory, lifecycle: LifecycleExperimental,
			rationale:   "The guide asks for a predefined Printf name where possible and otherwise a name ending in f, so go vet can be told to check the format string by name.",
			enforcement: "GCL-goprintffuncname",
		},
		{
			id: "UBER-LOO-001", title: "Loop variable capture in closures and goroutines", consequence: ConsequenceHygiene,
			anchor: "parallel-tests", classification: ClassSuperseded, lifecycle: LifecycleDeprecated,
			rationale:   "The guide asks parallel tests and goroutine-spawning loops to copy the loop variable. Go 1.22 gives each iteration its own variable, so the hazard no longer exists at the module's language version, and go fix's forvar analyzer reports the redundant copy.",
			enforcement: "language semantics, Go 1.22 and later", goConstraint: ">=1.22",
		},
	}
}

func uberManualSpecs() []uberSpec {
	return []uberSpec{
		{
			id: "UBER-CPY-001", title: "Copy slices and maps at boundaries", consequence: ConsequenceUnsafeBehavior,
			anchor: "copy-slices-and-maps-at-boundaries", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Storing or returning a caller-owned map or slice shares mutable state across an API boundary; deciding which boundaries are ownership transfers requires intent.",
			enforcement: "manual",
		},
		{
			id: "UBER-EMB-001", title: "Avoid embedding types in public structs", consequence: ConsequenceStructural,
			anchor: "avoid-embedding-types-in-public-structs", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Embedding leaks the implementation into the public API and freezes it against future change.",
			enforcement: "manual",
		},
		{
			id: "UBER-CHN-001", title: "Channel size is one or none", consequence: ConsequenceStructural,
			anchor: "channel-size-is-one-or-none", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Any capacity above one is a guess about producer and consumer rates that must be justified and measured.",
			enforcement: "manual",
		},
		{
			id: "UBER-MTX-001", title: "Zero-value mutexes are valid; never copy them", consequence: ConsequenceUnsafeBehavior,
			anchor: "zero-value-mutexes-are-valid", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "A copied lock protects nothing. go vet's copylocks pass detects this exactly, and the harness runs vet directly.",
			enforcement: RuleVet + " copylocks",
		},
		{
			id: "UBER-IFC-001", title: "Verify interface compliance at compile time", consequence: ConsequenceStructural,
			anchor: "verify-interface-compliance", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "A var _ Interface = (*Type)(nil) assertion turns a runtime surprise into a build error, but only the author knows which contracts matter.",
			enforcement: "manual",
		},
		{
			id: "UBER-ENU-001", title: "Start enums at one", consequence: ConsequenceStructural,
			anchor: "start-enums-at-one", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "A zero-valued enum member is indistinguishable from an unset field, so the zero value should mean unknown.",
			enforcement: "manual",
		},
		{
			id: "UBER-TIM-001", title: "Use time.Time and time.Duration for time", consequence: ConsequenceStructural,
			anchor: "use-time-to-handle-time", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Integer seconds and hand-rolled arithmetic lose units, monotonic readings, and daylight-saving correctness.",
			enforcement: "manual",
		},
		{
			id: "UBER-STY-001", title: "Avoid overly long lines", consequence: ConsequenceHygiene,
			anchor: "avoid-overly-long-lines", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "The guide recommends a soft limit of 99 characters and says code is allowed to exceed it, so the harness never blocks on line length.",
			enforcement: "manual",
		},
		{
			id: "UBER-TST-001", title: "Prefer table-driven tests", consequence: ConsequenceHygiene,
			anchor: "test-tables", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Tables help when cases share a shape; the guide warns against forcing them, so this stays a review prompt rather than a gate.",
			enforcement: "manual",
		},
		{
			id: "UBER-DEF-001", title: "Defer to clean up", consequence: ConsequenceUnsafeBehavior,
			anchor: "defer-to-clean-up", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Deferred cleanup survives every return path including panics; whether a resource needs it is a local judgement.",
			enforcement: "manual",
		},
	}
}
