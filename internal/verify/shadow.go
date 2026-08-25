package verify

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// PolicyShadow is what a repository's own lint configuration hides from itself,
// measured against the strict pack and attributed with this run's findings.
//
// It is a report section and never a claim. A repository's lint configuration
// is not a defect in its code, and a gate that rejected a change over someone's
// .golangci.yml would spend more trust than the section earns. Nothing in this
// file reaches a verdict, an exit code, or a claim.
type PolicyShadow struct {
	// File is the configuration this section read, relative to the module root.
	File string
	// Analysed is false when a configuration exists in a form this scan does not
	// read, or could not be read at all. Reason then says which.
	Analysed bool
	Reason   string
	Entries  []ShadowEntry
}

// ShadowEntry is one detected mechanism, with the findings that live behind it.
type ShadowEntry struct {
	ID        string
	Mechanism string
	Detail    string
	RuleIDs   []string
	// Attributed says whether Findings is an exact count of this run's findings
	// that the local configuration would not have produced. Where the producing
	// tool words two different defects identically, no count can be exact, and
	// this section states that rather than printing a number it cannot support.
	Attributed bool
	Findings   int
	Note       string
}

// detectPolicyShadow reads the repository's golangci-lint configuration and
// states the shadow it casts, or reports why it could not.
func detectPolicyShadow(root string, items []evidence.Evidence) *PolicyShadow {
	name, src, err := readGolangciConfig(root)
	switch {
	case name == "":
		return nil
	case err != nil:
		return &PolicyShadow{File: name, Reason: "the configuration could not be read: " + err.Error()}
	case !tool.IsYAMLConfigName(name):
		return &PolicyShadow{File: name, Reason: "only the YAML forms of a golangci-lint " +
			"configuration are analysed, and this one is not written in YAML"}
	}
	shadow := &PolicyShadow{File: name, Analysed: true}
	for _, s := range tool.DetectGolangciShadows(src, tool.StrictPackLinters()) {
		shadow.Entries = append(shadow.Entries, attributeShadow(s, items))
	}
	return shadow
}

// readGolangciConfig finds the configuration golangci-lint would read at the
// module root, in golangci's own resolution order.
func readGolangciConfig(root string) (name string, src []byte, err error) {
	for _, candidate := range tool.GolangciConfigNames() {
		data, readErr := os.ReadFile(filepath.Join(root, candidate))
		if readErr == nil {
			return candidate, data, nil
		}
		if !errors.Is(readErr, os.ErrNotExist) {
			return candidate, nil, readErr
		}
	}
	return "", nil, nil
}

func attributeShadow(s tool.Shadow, items []evidence.Evidence) ShadowEntry {
	entry := ShadowEntry{
		ID: s.ID, Mechanism: s.Mechanism, Detail: s.Detail,
		RuleIDs: ruleIDsFor(s.Linters),
	}
	switch s.ID {
	case tool.ShadowLintersOff:
		entry.Attributed = true
		entry.Findings = countFindings(items, entry.RuleIDs, nil)
	case tool.ShadowTestExclusion:
		entry.Attributed = true
		entry.Findings = countFindings(items, entry.RuleIDs, isTestFile)
	case tool.ShadowCheckBlank:
		// errcheck words an explicit blank discard and an unchecked call
		// identically, so the findings this mechanism hides cannot be separated
		// from the ones it does not. The total is given as the upper bound it is,
		// named as such, rather than printed as if it were the shadow.
		total := countFindings(items, entry.RuleIDs, nil)
		entry.Note = "errcheck reports a blank discard and an unchecked call in the same " +
			"words, so the share behind this mechanism cannot be counted exactly; the " +
			"run's " + strconv.Itoa(total) + " unchecked-error finding(s) are its upper bound"
	default:
		// A mechanism added without an attribution rule reports no count rather
		// than the wrong one. Silence is the safe direction here: an unexplained
		// number in this section is worse than an absent one.
		entry.Note = "this mechanism has no attribution rule, so no count is claimed for it"
	}
	return entry
}

func ruleIDsFor(linters []string) []string {
	out := make([]string, 0, len(linters))
	for _, linter := range linters {
		out = append(out, policy.GolangciRuleID(linter))
	}
	return out
}

func countFindings(items []evidence.Evidence, ruleIDs []string, where func(evidence.Evidence) bool) int {
	wanted := make(map[string]bool, len(ruleIDs))
	for _, id := range ruleIDs {
		wanted[id] = true
	}
	count := 0
	for _, e := range items {
		if wanted[e.RuleID] && (where == nil || where(e)) {
			count++
		}
	}
	return count
}

func isTestFile(e evidence.Evidence) bool {
	return strings.HasSuffix(e.File, "_test.go")
}
