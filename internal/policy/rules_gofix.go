package policy

// GoFixRulePrefix is the rule ID prefix for findings the go fix analyzer suite
// produces. Each analyzer reports under its own ID, as golangci-lint linters do.
const GoFixRulePrefix = "GO-FIX-"

const goFixDoc = "https://pkg.go.dev/cmd/fix"

// fixAnalyzerSpec is one analyzer of the go fix suite as policy data. Enabling
// an analyzer is a policy decision recorded here, never a runtime flag: the set
// the harness runs has to be readable, reviewable, and impossible for a project
// configuration to widen.
type fixAnalyzerSpec struct {
	name      string
	title     string
	rationale string
	// consequence is the class the analyzer's findings belong to. The excluded
	// analyzers leave it empty: they produce no rule, so there is nothing to
	// classify.
	consequence Consequence
	// excluded holds the reason an analyzer of the suite is deliberately not
	// run. An excluded analyzer gets no registry entry, so it can never produce
	// evidence, and the reason stays next to the decision.
	excluded string
}

// goFixAnalyzerSpecs lists every analyzer registered by the pinned toolchain's
// fix tool, enabled or not. A toolchain upgrade that adds an analyzer leaves it
// absent here, which the analyzer validation reports rather than silently
// running it.
func goFixAnalyzerSpecs() []fixAnalyzerSpec {
	return append(goFixSimplicitySpecs(), append(goFixMigrationSpecs(), goFixExcludedSpecs()...)...)
}

// goFixSimplicitySpecs are the modernizers: each replaces a hand-rolled
// construct with the standard library or language feature that now expresses it.
func goFixSimplicitySpecs() []fixAnalyzerSpec {
	return []fixAnalyzerSpec{
		{name: "any", consequence: ConsequenceHygiene, title: "interface{} where any says the same thing",
			rationale: "any has been the spelling since Go 1.18; interface{} is the older form of an identical type."},
		{name: "fmtappendf", consequence: ConsequenceHygiene, title: "[]byte(fmt.Sprintf(...)) instead of fmt.Appendf",
			rationale: "The conversion allocates a string only to copy it into a byte slice."},
		{name: "forvar", consequence: ConsequenceHygiene, title: "Redundant re-declaration of a loop variable",
			rationale: "x := x inside a loop body has been unnecessary since Go 1.22 gave each iteration its own variable."},
		{name: "mapsloop", consequence: ConsequenceHygiene, title: "Explicit loop over a map that the maps package expresses",
			rationale: "maps.Copy, maps.Keys and their siblings say what the loop is for in one line."},
		{name: "minmax", consequence: ConsequenceHygiene, title: "if/else that computes a minimum or a maximum",
			rationale: "min and max are builtins; the three-line form hides which value wins."},
		{name: "newexpr", consequence: ConsequenceHygiene, title: "Helper function that only wraps a value in a pointer",
			rationale: "Go 1.26's new(expr) removes the generic pointer helper every codebase used to carry."},
		{name: "rangeint", consequence: ConsequenceHygiene, title: "Three-clause for loop counting to a bound",
			rationale: "for i := range n states the bound once instead of three times."},
		{name: "reflecttypefor", consequence: ConsequenceHygiene, title: "reflect.TypeOf on a zero value instead of TypeFor",
			rationale: "reflect.TypeFor[T]() names the type directly and cannot be handed the wrong value."},
		{name: "slicescontains", consequence: ConsequenceHygiene, title: "Loop that searches a slice for a value",
			rationale: "slices.Contains and slices.ContainsFunc replace a loop whose only result is a boolean."},
		{name: "slicessort", consequence: ConsequenceHygiene, title: "sort.Slice on a slice of basic types",
			rationale: "slices.Sort is faster and removes a comparison function that can be written backwards."},
		{name: "stditerators", consequence: ConsequenceHygiene, title: "Len/At iteration over a standard library collection",
			rationale: "Iterator methods remove index arithmetic that can run off the end."},
		{name: "stringsbuilder", consequence: ConsequenceHygiene, title: "String concatenation with += in a loop",
			rationale: "Repeated concatenation is quadratic; strings.Builder is linear."},
		{name: "stringscut", consequence: ConsequenceHygiene, title: "strings.Index followed by slicing",
			rationale: "strings.Cut returns the two halves and whether the separator was there, which is what the index was for."},
		{name: "stringscutprefix", consequence: ConsequenceHygiene, title: "HasPrefix followed by TrimPrefix",
			rationale: "strings.CutPrefix does the test and the trim once instead of scanning twice."},
		{name: "stringsseq", consequence: ConsequenceHygiene, title: "Ranging over strings.Split or strings.Fields",
			rationale: "SplitSeq and FieldsSeq iterate without allocating the intermediate slice."},
		{name: "testingcontext", consequence: ConsequenceHygiene, title: "context.WithCancel in a test instead of t.Context",
			rationale: "t.Context is cancelled when the test ends, so the test cannot leak the goroutines it started."},
		{name: "waitgroup", consequence: ConsequenceHygiene, title: "wg.Add(1) / go / defer wg.Done() around a goroutine",
			rationale: "wg.Go pairs the counter with the goroutine, which is the pairing this trio gets wrong when it is edited."},
	}
}

// goFixMigrationSpecs are the analyzers about moving off something: an API its
// author marked for automatic migration, or a build constraint syntax the
// toolchain stopped reading.
func goFixMigrationSpecs() []fixAnalyzerSpec {
	return []fixAnalyzerSpec{
		{name: "inline", consequence: ConsequenceStructural, title: "Call of an API its author marked //go:fix inline",
			rationale: "A //go:fix inline directive is the author saying this call site can be migrated mechanically and safely. Staying on the old spelling is debt with a published, one-command fix; the inliner refuses any rewrite that would change behaviour, including argument evaluation order."},
		{name: "plusbuild", consequence: ConsequenceStructural, title: "Obsolete // +build constraint",
			rationale: "Only //go:build is read since Go 1.18. The leftover line is a second source of truth that no tool checks against the first."},
		{name: "hostport", consequence: ConsequenceUnsafeBehavior, title: "Address for net.Dial built by formatting",
			rationale: "fmt.Sprintf(\"%s:%d\", host, port) produces an unusable address for any IPv6 host; net.JoinHostPort does not."},
	}
}

// goFixExcludedSpecs are the analyzers of the suite the harness does not run,
// each with the reason it is off.
func goFixExcludedSpecs() []fixAnalyzerSpec {
	return []fixAnalyzerSpec{
		{
			name:     "buildtag",
			title:    "Malformed build constraint",
			excluded: "go vet runs this same analyzer, and one defect must not arrive under two rule IDs; this is why the govet linter is off in the golangci configuration too.",
		},
		{
			name:     "omitzero",
			title:    "omitempty on a struct-typed field",
			excluded: "Its own documentation states that replacing omitempty with omitzero changes what json.Marshal emits. A gate may report a defect; it may not push a semantic change.",
		},
	}
}

// GoFixAnalyzers returns the analyzer names the harness enables, sorted by the
// order they are declared in. The runner passes exactly these as flags.
func GoFixAnalyzers() []string {
	specs := goFixAnalyzerSpecs()
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.excluded != "" {
			continue
		}
		names = append(names, s.name)
	}
	return names
}

// GoFixKnownAnalyzers returns every analyzer the registry knows about, enabled
// or excluded. Validation against the toolchain uses it to tell an analyzer the
// harness declined from one it has never heard of.
func GoFixKnownAnalyzers() []string {
	specs := goFixAnalyzerSpecs()
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.name)
	}
	return names
}

// GoFixRuleID returns the rule ID one go fix analyzer reports under.
func GoFixRuleID(analyzer string) string {
	return GoFixRulePrefix + analyzer
}

func gofixRules() []Rule {
	specs := goFixAnalyzerSpecs()
	rules := make([]Rule, 0, len(specs))
	for _, s := range specs {
		if s.excluded != "" {
			continue
		}
		rules = append(rules, Rule{
			ID:             GoFixRuleID(s.name),
			Title:          s.title,
			Pack:           PackGoFix,
			Classification: ClassAdvisory,
			Lifecycle:      LifecycleExperimental,
			Consequence:    s.consequence,
			Rationale:      s.rationale + " The fix is machine-applicable: the toolchain produces the exact edit.",
			Enforcement:    "go fix -json, analyzer " + s.name + " (run `go tool fix help " + s.name + "`)",
			DocURL:         goFixDoc,
		})
	}
	return rules
}
