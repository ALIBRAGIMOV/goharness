package policy

const golangciDocBase = "https://golangci-lint.run/docs/linters/configuration/#"

// RuleErrcheck is named because its findings are bucketed by remedy rather than
// treated as one undifferentiated class.
const RuleErrcheck = "GCL-errcheck"

// GolangciRuleID is the registry ID for one golangci-lint linter. The mapping
// is a prefix and nothing else, and it is spelled once so that a reader of a
// linter name and a reader of a rule ID can never drift apart.
func GolangciRuleID(linter string) string { return "GCL-" + linter }

type linterSpec struct {
	name           string
	title          string
	classification Classification
	consequence    Consequence
	rationale      string
	pattern        string
	// builtIn marks a pseudo-linter golangci-lint always reports under and
	// which therefore cannot appear in the enable list, though its findings
	// still need a registry entry.
	builtIn bool
	// experimental marks a linter that has not yet been measured on the corpus.
	// It runs and reports at advisory severity, and it is promoted on corpus
	// evidence or not at all.
	experimental bool
}

func golangciLinterSpecs() []linterSpec {
	return []linterSpec{
		{name: "asasalint", title: "A []any passed as one value to a variadic ...any", classification: ClassAdvisory, consequence: ConsequenceUnsafeBehavior, experimental: true,
			rationale: "Passing a []any where the callee takes ...any wraps the whole slice as a single argument, so a logger or formatter receives one value instead of many. The call compiles and does the wrong thing."},
		{name: "bidichk", title: "Unicode bidirectional control character in source", classification: ClassAdvisory, consequence: ConsequenceUnsafeBehavior, experimental: true,
			rationale: "Bidirectional control characters make source render differently from how the compiler reads it (CVE-2021-42574), so a reviewer approves text that is not the code that runs."},
		{name: "bodyclose", title: "HTTP response body is not closed", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "An unclosed response body leaks the connection and eventually exhausts the transport pool."},
		{name: "containedctx", title: "context.Context stored in a struct field", classification: ClassAdvisory, consequence: ConsequenceStructural, experimental: true,
			rationale: "The context package documentation says not to store a Context inside a struct type but to pass it explicitly to each function that needs it. A stored context outlives the call it was scoped to and hides which operation a cancellation reaches."},
		{name: "dupl", title: "Substantial duplicated code fragment", classification: ClassSuperseded, consequence: ConsequenceStructural,
			rationale: "GH-DUP-001 answers the same question from the harness's own parse of the scope, so enabling dupl bought a second full pass over every file for a second advisory row about the same duplication. The native scanner is the one kept because the project controls its threshold, can explain a finding through `goharness explain`, and reports against the shape of a function rather than a token window."},
		{name: "durationcheck", title: "Two time.Duration values multiplied together", classification: ClassAdvisory, consequence: ConsequenceUnsafeBehavior, experimental: true,
			rationale: "Multiplying two Durations multiplies their nanosecond counts: 5*time.Second times time.Second is about 158 years. One operand of a scaling has to be a plain number."},
		{name: "errcheck", title: "Returned error is unchecked", classification: ClassRequired, consequence: ConsequenceSilentLoss,
			rationale: "An unchecked error is the single most common way a Go defect reaches production.",
			pattern:   errcheckPattern},
		{name: "errname", title: "Sentinel error or error type is misnamed", classification: ClassAdvisory, consequence: ConsequenceHygiene,
			rationale: "Err/Error naming makes error values discoverable at call sites."},
		{name: "errorlint", title: "Error comparison or formatting breaks Go 1.13 wrapping", classification: ClassRequired, consequence: ConsequenceSilentLoss,
			rationale: "Comparing wrapped errors with == or formatting them with %v silently defeats errors.Is and errors.As."},
		{name: "fatcontext", title: "Context is nested inside a loop or a function literal", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "Re-deriving a context inside a loop grows the cancellation chain on every iteration and leaks."},
		{name: "forcetypeassert", title: "Type assertion without the comma-ok form", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "An unchecked type assertion panics at runtime on the first unexpected dynamic type."},
		{name: "gocheckcompilerdirectives", title: "Malformed //go: compiler directive", classification: ClassAdvisory, consequence: ConsequenceStructural, experimental: true,
			rationale: "A directive written with a space after the slashes, or with a misspelled name, is an ordinary comment to the toolchain, so the generate, embed or linkname it was meant to be silently does nothing."},
		{name: "gochecknoglobals", title: "Mutable package-level variable", classification: ClassRequired, consequence: ConsequenceStructural,
			rationale: "Mutable globals are shared state with no owner; they defeat testing and invite data races."},
		{name: "gochecknoinits", title: "init function present", classification: ClassRequired, consequence: ConsequenceStructural,
			rationale: "init runs before any caller can observe or order it, so side effects there are untestable."},
		{name: "goprintffuncname", title: "Printf-style function name does not end in f", classification: ClassAdvisory, consequence: ConsequenceHygiene, experimental: true,
			rationale: "The Uber Go Style Guide asks that a printf-style function end in f, so a reader knows its first argument is a format string and vet's printf check can be pointed at it by name."},
		{name: "gosec", title: "Security-sensitive construct", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "Static security findings are cheap to fix at authoring time and expensive afterwards."},
		{name: "ineffassign", title: "Assignment is never used", classification: ClassRequired, consequence: ConsequenceSilentLoss,
			rationale: "An ineffectual assignment usually means the intended value was written to the wrong variable."},
		{name: "makezero", title: "Slice declared with non-zero length is then appended to", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "make([]T, n) followed by append silently produces n zero values ahead of the real data."},
		{name: "modernize", title: "Construct has a simpler modern equivalent", classification: ClassAdvisory, consequence: ConsequenceHygiene,
			rationale: "Modern standard library and language features remove hand-rolled loops and helpers."},
		{name: "musttag", title: "Field in a (un)marshaled struct lacks a tag", classification: ClassRequired, consequence: ConsequenceStructural,
			rationale: "Untagged fields serialize under Go identifiers, coupling the wire format to internal naming."},
		{name: "nilerr", title: "Returns nil after checking that an error is non-nil", classification: ClassRequired, consequence: ConsequenceSilentLoss,
			rationale: "Checking err != nil and then returning nil discards the failure entirely."},
		{name: "nilnesserr", title: "Returns a different nil error after a non-nil check", classification: ClassRequired, consequence: ConsequenceSilentLoss,
			rationale: "The same defect as nilerr with an extra layer of indirection."},
		{name: "nilnil", title: "Returns both a nil value and a nil error", classification: ClassRequired, consequence: ConsequenceStructural,
			rationale: "A nil result with a nil error forces every caller to invent a third case."},
		{name: "noctx", title: "Request or command built without a context", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "Work without a context cannot be cancelled and has no deadline."},
		{name: "perfsprint", title: "fmt used for a conversion strconv performs directly", classification: ClassAdvisory, consequence: ConsequenceHygiene, experimental: true,
			rationale: "The Uber Go Style Guide prefers strconv over fmt for converting primitives to and from strings: fmt formats through reflection and allocates where strconv does neither. Only the conversions are reported; string concatenation and error construction are left alone."},
		{name: "predeclared", title: "Identifier shadows a Go predeclared name", classification: ClassRequired, consequence: ConsequenceHygiene,
			rationale: "Shadowing names such as len, cap, or new makes the surrounding code mean something other than it reads."},
		{name: "reassign", title: "Another package's variable is reassigned", classification: ClassAdvisory, consequence: ConsequenceUnsafeBehavior, experimental: true,
			rationale: "Assigning to another package's exported variable, such as io.EOF, changes behaviour for every caller in the binary from a line none of them can see."},
		{name: "recvcheck", title: "Methods of one type mix pointer and value receivers", classification: ClassAdvisory, consequence: ConsequenceStructural, experimental: true,
			rationale: "The Go FAQ asks for consistency: if some methods of a type need a pointer receiver, the rest should take one too, so the method set is the same however the type is used. A value receiver beside mutating pointer methods also copies state a caller expects to be shared."},
		{name: "revive", title: "Defect-oriented revive rule violation", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "Only revive's defect rules are enabled (atomic misuse, identical branches, value-receiver mutation, WaitGroup by value, data races in closures, unconditional recursion, os.Exit outside main); each one reports code that misbehaves, not code that reads unusually."},
		{name: "rowserrcheck", title: "sql.Rows.Err is not checked", classification: ClassRequired, consequence: ConsequenceSilentLoss,
			rationale: "Iteration errors surface only through Rows.Err; skipping it turns a query failure into an empty result."},
		{name: "sqlclosecheck", title: "sql.Rows or sql.Stmt is not closed", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "Unclosed statements and row sets hold database connections open until the pool is exhausted."},
		{name: "staticcheck", title: "staticcheck diagnostic", classification: ClassRequired, consequence: ConsequenceUnsafeBehavior,
			rationale: "staticcheck's rule set is high-precision and covers correctness, simplification, and API misuse."},
		{name: "testableexamples", title: "Example function has no output comment", classification: ClassAdvisory, consequence: ConsequenceStructural, experimental: true,
			rationale: "The testing package compiles an Example without an output comment but never runs it, so it documents behaviour no test executes."},
		{name: "testifylint", title: "Incorrect testify usage", classification: ClassRequired, consequence: ConsequenceStructural,
			rationale: "Misused testify assertions report the wrong side as expected or never fail at all."},
		{
			name: "typecheck", title: "Package failed to type-check",
			classification: ClassRequired, consequence: ConsequenceStructural, builtIn: true,
			rationale: "golangci-lint reports its own compile failures under this name; a package that does not build cannot be judged on anything else.",
		},
		{name: "unused", title: "Unused identifier", classification: ClassRequired, consequence: ConsequenceStructural,
			rationale: "Unreferenced code is either dead or evidence of an unfinished edit."},
		{name: "usestdlibvars", title: "Literal duplicates a standard library constant", classification: ClassAdvisory, consequence: ConsequenceHygiene,
			rationale: "Standard library constants remove typos in HTTP methods, status codes, and time layouts."},
		{name: "usetesting", title: "Test uses an os or context call the testing package replaces", classification: ClassAdvisory, consequence: ConsequenceHygiene, experimental: true,
			rationale: "t.TempDir, t.Setenv, t.Chdir and t.Context are scoped to the test and undone by the framework; os.MkdirTemp, os.Setenv, os.Chdir and context.Background leak into the next test unless every path cleans up by hand."},
	}
}

// EnabledLinters returns the golangci-lint linters the embedded strict
// configuration enables, in configuration order. A pseudo-linter cannot appear
// there, and neither can a superseded one: its registry entry survives so that
// evidence recorded under the old configuration still resolves to a rule, but
// running it would only pay twice for one answer.
func EnabledLinters() []string {
	specs := golangciLinterSpecs()
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.builtIn || s.classification == ClassSuperseded {
			continue
		}
		names = append(names, s.name)
	}
	return names
}

func golangciRules() []Rule {
	specs := golangciLinterSpecs()
	rules := make([]Rule, 0, len(specs))
	for _, s := range specs {
		lifecycle := lifecycleFor(s.classification)
		if s.experimental {
			lifecycle = LifecycleExperimental
		}
		rules = append(rules, Rule{
			ID:             "GCL-" + s.name,
			Title:          s.title,
			Pack:           PackGolangciStrict,
			Classification: s.classification,
			Lifecycle:      lifecycle,
			Consequence:    s.consequence,
			Rationale:      s.rationale,
			Pattern:        s.pattern,
			Enforcement:    enforcementFor(s),
			DocURL:         golangciDocBase + s.name,
		})
	}
	return rules
}

func lifecycleFor(c Classification) Lifecycle {
	switch c {
	case ClassAdvisory:
		return LifecycleAdvisory
	case ClassSuperseded:
		return LifecycleDeprecated
	default:
		return LifecycleRequired
	}
}

// enforcementFor names what actually produces a finding for this rule today. A
// superseded linter no longer runs, so claiming it as the enforcement would put
// a falsehood in the registry and in every `explain` of it.
func enforcementFor(s linterSpec) string {
	if s.classification == ClassSuperseded {
		return RuleClone
	}
	return "golangci-lint linter " + s.name
}
