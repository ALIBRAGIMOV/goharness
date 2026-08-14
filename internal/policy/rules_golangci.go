package policy

const golangciDocBase = "https://golangci-lint.run/docs/linters/configuration/#"

type linterSpec struct {
	name           string
	title          string
	classification Classification
	rationale      string
	// builtIn marks a pseudo-linter golangci-lint always reports under and
	// which therefore cannot appear in the enable list, though its findings
	// still need a registry entry.
	builtIn bool
}

func golangciLinterSpecs() []linterSpec {
	return []linterSpec{
		{name: "bodyclose", title: "HTTP response body is not closed", classification: ClassRequired,
			rationale: "An unclosed response body leaks the connection and eventually exhausts the transport pool."},
		{name: "dupl", title: "Substantial duplicated code fragment", classification: ClassAdvisory,
			rationale: "Copied logic drifts apart under maintenance; whether to extract or keep the copies separate is a design call."},
		{name: "errcheck", title: "Returned error is unchecked", classification: ClassRequired,
			rationale: "An unchecked error is the single most common way a Go defect reaches production."},
		{name: "errname", title: "Sentinel error or error type is misnamed", classification: ClassAdvisory,
			rationale: "Err/Error naming makes error values discoverable at call sites."},
		{name: "errorlint", title: "Error comparison or formatting breaks Go 1.13 wrapping", classification: ClassRequired,
			rationale: "Comparing wrapped errors with == or formatting them with %v silently defeats errors.Is and errors.As."},
		{name: "fatcontext", title: "Context is nested inside a loop or a function literal", classification: ClassRequired,
			rationale: "Re-deriving a context inside a loop grows the cancellation chain on every iteration and leaks."},
		{name: "forcetypeassert", title: "Type assertion without the comma-ok form", classification: ClassRequired,
			rationale: "An unchecked type assertion panics at runtime on the first unexpected dynamic type."},
		{name: "gochecknoglobals", title: "Mutable package-level variable", classification: ClassRequired,
			rationale: "Mutable globals are shared state with no owner; they defeat testing and invite data races."},
		{name: "gochecknoinits", title: "init function present", classification: ClassRequired,
			rationale: "init runs before any caller can observe or order it, so side effects there are untestable."},
		{name: "gosec", title: "Security-sensitive construct", classification: ClassRequired,
			rationale: "Static security findings are cheap to fix at authoring time and expensive afterwards."},
		{name: "ineffassign", title: "Assignment is never used", classification: ClassRequired,
			rationale: "An ineffectual assignment usually means the intended value was written to the wrong variable."},
		{name: "makezero", title: "Slice declared with non-zero length is then appended to", classification: ClassRequired,
			rationale: "make([]T, n) followed by append silently produces n zero values ahead of the real data."},
		{name: "modernize", title: "Construct has a simpler modern equivalent", classification: ClassAdvisory,
			rationale: "Modern standard library and language features remove hand-rolled loops and helpers."},
		{name: "musttag", title: "Field in a (un)marshaled struct lacks a tag", classification: ClassRequired,
			rationale: "Untagged fields serialize under Go identifiers, coupling the wire format to internal naming."},
		{name: "nilerr", title: "Returns nil after checking that an error is non-nil", classification: ClassRequired,
			rationale: "Checking err != nil and then returning nil discards the failure entirely."},
		{name: "nilnesserr", title: "Returns a different nil error after a non-nil check", classification: ClassRequired,
			rationale: "The same defect as nilerr with an extra layer of indirection."},
		{name: "nilnil", title: "Returns both a nil value and a nil error", classification: ClassRequired,
			rationale: "A nil result with a nil error forces every caller to invent a third case."},
		{name: "noctx", title: "Request or command built without a context", classification: ClassRequired,
			rationale: "Work without a context cannot be cancelled and has no deadline."},
		{name: "predeclared", title: "Identifier shadows a Go predeclared name", classification: ClassRequired,
			rationale: "Shadowing names such as len, cap, or new makes the surrounding code mean something other than it reads."},
		{name: "rowserrcheck", title: "sql.Rows.Err is not checked", classification: ClassRequired,
			rationale: "Iteration errors surface only through Rows.Err; skipping it turns a query failure into an empty result."},
		{name: "sqlclosecheck", title: "sql.Rows or sql.Stmt is not closed", classification: ClassRequired,
			rationale: "Unclosed statements and row sets hold database connections open until the pool is exhausted."},
		{name: "staticcheck", title: "staticcheck diagnostic", classification: ClassRequired,
			rationale: "staticcheck's rule set is high-precision and covers correctness, simplification, and API misuse."},
		{name: "testifylint", title: "Incorrect testify usage", classification: ClassRequired,
			rationale: "Misused testify assertions report the wrong side as expected or never fail at all."},
		{
			name: "typecheck", title: "Package failed to type-check",
			classification: ClassRequired, builtIn: true,
			rationale: "golangci-lint reports its own compile failures under this name; a package that does not build cannot be judged on anything else.",
		},
		{name: "unused", title: "Unused identifier", classification: ClassRequired,
			rationale: "Unreferenced code is either dead or evidence of an unfinished edit."},
		{name: "usestdlibvars", title: "Literal duplicates a standard library constant", classification: ClassAdvisory,
			rationale: "Standard library constants remove typos in HTTP methods, status codes, and time layouts."},
	}
}

// EnabledLinters returns the golangci-lint linters the embedded strict
// configuration enables, in configuration order.
func EnabledLinters() []string {
	specs := golangciLinterSpecs()
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.builtIn {
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
		lifecycle := LifecycleRequired
		if s.classification == ClassAdvisory {
			lifecycle = LifecycleAdvisory
		}
		rules = append(rules, Rule{
			ID:             "GCL-" + s.name,
			Title:          s.title,
			Pack:           PackGolangciStrict,
			Classification: s.classification,
			Lifecycle:      lifecycle,
			Rationale:      s.rationale,
			Enforcement:    "golangci-lint linter " + s.name,
			DocURL:         golangciDocBase + s.name,
		})
	}
	return rules
}
