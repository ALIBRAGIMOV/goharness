package policy

type uberSpec struct {
	id             string
	title          string
	anchor         string
	classification Classification
	lifecycle      Lifecycle
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
		if r.Enforcement == ruleID {
			out = append(out, r)
		}
	}
	return out
}

func uberSpecs() []uberSpec {
	return append(uberEnforcedSpecs(), uberManualSpecs()...)
}

func uberEnforcedSpecs() []uberSpec {
	return []uberSpec{
		{
			id: "UBER-ERR-001", title: "Handle every returned error",
			anchor: "handle-errors", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Ignoring an error discards the only signal that an operation failed; the guide permits discarding only with an explicit, justified decision.",
			enforcement: "GCL-errcheck",
		},
		{
			id: "UBER-TYP-001", title: "Use the comma-ok form for type assertions",
			anchor: "handle-type-assertion-failures", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "A single-value type assertion panics on an unexpected dynamic type; the two-value form turns that into a handled branch.",
			enforcement: "GCL-forcetypeassert",
		},
		{
			id: "UBER-GLO-001", title: "Avoid mutable package-level globals",
			anchor: "avoid-mutable-globals", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Mutable globals couple unrelated code through hidden state and make tests order-dependent; dependency injection is the guide's prescribed alternative.",
			enforcement: "GCL-gochecknoglobals",
		},
		{
			id: "UBER-INI-001", title: "Avoid init() and its side effects",
			anchor: "avoid-init", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "init runs implicitly, in an order callers cannot control or observe, and cannot report an error.",
			enforcement: "GCL-gochecknoinits",
		},
		{
			id: "UBER-NAM-001", title: "Do not shadow built-in names",
			anchor: "avoid-using-built-in-names", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Shadowing a predeclared identifier changes what surrounding code means without changing how it reads.",
			enforcement: "GCL-predeclared",
		},
		{
			id: "UBER-TAG-001", title: "Use field tags in marshaled structs",
			anchor: "use-field-tags-in-marshaled-structs", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Without tags the serialized form follows Go field names, so an internal rename silently breaks the wire format. Tag validity is checked by go vet's structtag pass, which the harness runs directly.",
			enforcement: RuleVet,
		},
		{
			id: "UBER-ERR-002", title: "Wrap errors with context",
			anchor: "error-wrapping", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "Comparisons and type checks must survive wrapping; %v formatting and == comparison break errors.Is and errors.As.",
			enforcement: "GCL-errorlint",
		},
		{
			id: "UBER-ERR-003", title: "Name sentinel errors Err* and error types *Error",
			anchor: "error-naming", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Consistent naming makes the intended comparison strategy visible at the call site.",
			enforcement: "GCL-errname",
		},
		{
			id: "UBER-ERR-004", title: "Do not log and return the same error",
			anchor: "handle-errors", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Logging and returning produces one incident reported many times; the guide asks callers to handle an error exactly once.",
			enforcement: "manual",
		},
		{
			id: "UBER-PAN-001", title: "Do not panic in library code",
			anchor: "dont-panic", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "A panic in a library removes the caller's ability to recover a request; return an error instead. No linter in the pinned golangci-lint set distinguishes library panics from main-package fatal paths reliably enough to block on.",
			enforcement: "manual",
		},
		{
			id: "UBER-EXI-001", title: "Call os.Exit or log.Fatal only from main",
			anchor: "exit-in-main", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Exiting outside main skips deferred cleanup and denies callers any recovery path. The pinned golangci-lint set offers no dedicated analyzer for this, so v0.1 records it as a manual review item rather than approximating it.",
			enforcement: "manual",
		},
		{
			id: "UBER-STY-002", title: "Prefer typed sync/atomic over go.uber.org/atomic",
			anchor: "use-gouberorgatomic", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Since Go 1.19 the standard library provides typed atomic values, so the guide's recommendation of an external package is satisfied by sync/atomic. The harness never requires adding a third-party dependency.",
			enforcement: "manual", goConstraint: ">=1.19",
		},
		{
			id: "UBER-LOO-001", title: "Loop variable capture in closures and goroutines",
			anchor: "dont-fire-and-forget-goroutines", classification: ClassSuperseded, lifecycle: LifecycleDeprecated,
			rationale:   "Go 1.22 gives each iteration its own loop variable, so the historical capture hazard no longer exists at the module's pinned language version.",
			enforcement: "language semantics, Go 1.22 and later", goConstraint: ">=1.22",
		},
	}
}

func uberManualSpecs() []uberSpec {
	return []uberSpec{
		{
			id: "UBER-GOR-001", title: "Goroutine lifetimes must be discoverable",
			anchor: "dont-fire-and-forget-goroutines", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Every goroutine needs a known stop condition and a way to wait for it; whether one exists is a design question no static analyzer answers.",
			enforcement: "manual",
		},
		{
			id: "UBER-CPY-001", title: "Copy slices and maps at boundaries",
			anchor: "copy-slices-and-maps-at-boundaries", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Storing or returning a caller-owned map or slice shares mutable state across an API boundary; deciding which boundaries are ownership transfers requires intent.",
			enforcement: "manual",
		},
		{
			id: "UBER-EMB-001", title: "Avoid embedding types in public structs",
			anchor: "avoid-embedding-types-in-public-structs", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Embedding leaks the implementation into the public API and freezes it against future change.",
			enforcement: "manual",
		},
		{
			id: "UBER-CHN-001", title: "Channel size is one or none",
			anchor: "channel-size-is-one-or-none", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Any capacity above one is a guess about producer and consumer rates that must be justified and measured.",
			enforcement: "manual",
		},
		{
			id: "UBER-MTX-001", title: "Zero-value mutexes are valid; never copy them",
			anchor: "zero-value-mutexes-are-valid", classification: ClassRequired, lifecycle: LifecycleRequired,
			rationale:   "A copied lock protects nothing. go vet's copylocks pass detects this exactly, and the harness runs vet directly.",
			enforcement: RuleVet,
		},
		{
			id: "UBER-IFC-001", title: "Verify interface compliance at compile time",
			anchor: "verify-interface-compliance", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "A var _ Interface = (*Type)(nil) assertion turns a runtime surprise into a build error, but only the author knows which contracts matter.",
			enforcement: "manual",
		},
		{
			id: "UBER-ENU-001", title: "Start enums at one",
			anchor: "start-enums-at-one", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "A zero-valued enum member is indistinguishable from an unset field, so the zero value should mean unknown.",
			enforcement: "manual",
		},
		{
			id: "UBER-TIM-001", title: "Use time.Time and time.Duration for time",
			anchor: "use-time-to-handle-time", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Integer seconds and hand-rolled arithmetic lose units, monotonic readings, and daylight-saving correctness.",
			enforcement: "manual",
		},
		{
			id: "UBER-STY-001", title: "Keep lines under 99 columns",
			anchor: "avoid-line-length", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "The guide calls this a soft limit and explicitly declines to make it mechanical, so the harness never blocks on it.",
			enforcement: "advisory, not mechanically enforced in v0.1",
		},
		{
			id: "UBER-TST-001", title: "Prefer table-driven tests",
			anchor: "test-tables", classification: ClassAdvisory, lifecycle: LifecycleAdvisory,
			rationale:   "Tables help when cases share a shape; the guide warns against forcing them, so this stays a review prompt rather than a gate.",
			enforcement: "manual",
		},
		{
			id: "UBER-DEF-001", title: "Defer to clean up",
			anchor: "defer-to-clean-up", classification: ClassManual, lifecycle: LifecycleAdvisory,
			rationale:   "Deferred cleanup survives every return path including panics; whether a resource needs it is a local judgement.",
			enforcement: "manual",
		},
	}
}
