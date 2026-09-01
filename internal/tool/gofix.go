package tool

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
)

// FixDiagnostic is one finding of the go fix analyzer suite, together with the
// mechanical edit the toolchain would apply to close it.
type FixDiagnostic struct {
	Analyzer   string
	Package    string
	File       string
	Line       int
	Column     int
	Message    string
	FixSummary string
	Edits      int
}

// RunGoFix reports what the go fix analyzers would change, without changing
// anything.
//
// The -json flag is what makes that true. The go command applies fixes to the
// source tree unless it is asked for JSON or for a diff, so this is the single
// place that builds the argument vector, it always passes -json, and it never
// passes -fix or -diff. A test asserts exactly that, because the failure mode
// is not a wrong verdict but a rewritten worktree.
func RunGoFix(
	ctx context.Context, runner Runner, dir string, patterns, analyzers []string,
) ([]FixDiagnostic, error) {
	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: GoFixArgs(patterns, analyzers)})
	if err != nil {
		return nil, err
	}
	diags, parseErr := parseFixJSON(res.Stdout)
	if parseErr != nil {
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("go fix exited %d: %s",
				res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
		}
		return nil, parseErr
	}
	if res.ExitCode != 0 && len(diags) == 0 {
		return nil, fmt.Errorf("go fix exited %d without diagnostics: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 20)))
	}
	return diags, nil
}

// GoFixArgs builds the go fix invocation for one scope. It is exported so the
// read-only property can be asserted directly rather than inferred from a
// captured command.
func GoFixArgs(patterns, analyzers []string) []string {
	args := make([]string, 0, len(analyzers)+len(patterns)+2)
	args = append(args, "fix", "-json")
	for _, name := range analyzers {
		args = append(args, "-"+name)
	}
	return append(args, patterns...)
}

func parseFixJSON(stream string) ([]FixDiagnostic, error) {
	entries, err := decodeAnalysisJSON(stream)
	if err != nil {
		return nil, err
	}
	var out []FixDiagnostic
	for _, entry := range entries {
		if entry.Failure != "" {
			return nil, fmt.Errorf("fix analyzer %s failed on %s: %s",
				entry.Analyzer, entry.Package, entry.Failure)
		}
		for _, d := range entry.Diagnostics {
			file, line, col := splitPosition(d.Posn)
			summary, edits := firstSuggestedFix(d.SuggestedFixes)
			out = append(out, FixDiagnostic{
				Analyzer:   entry.Analyzer,
				Package:    entry.Package,
				File:       file,
				Line:       line,
				Column:     col,
				Message:    d.Message,
				FixSummary: summary,
				Edits:      edits,
			})
		}
	}
	return out, nil
}

// firstSuggestedFix summarises the edit the analyzer offers. Only the first is
// reported: where an analyzer offers a choice, picking one for the reader would
// be the harness making a decision it has no basis for.
func firstSuggestedFix(fixes []analysisSuggestedFix) (summary string, edits int) {
	if len(fixes) == 0 {
		return "", 0
	}
	return fixes[0].Message, len(fixes[0].Edits)
}

// FixAnalyzerSupport is what the installed toolchain says about the analyzer
// set the policy declares.
type FixAnalyzerSupport struct {
	// Missing are analyzers the policy enables that this toolchain does not
	// register. Running with one would fail on an undefined flag.
	Missing []string
	// Unregistered are analyzers the toolchain offers that the policy has never
	// classified. They are reported, never run: an analyzer arriving with a
	// toolchain upgrade is a decision for a person, not a silent widening.
	Unregistered []string
}

// InspectFixAnalyzers asks the fix tool which analyzers it registers and
// compares that with the policy. It loads no packages, so it costs one short
// process and can run before every fix check.
func InspectFixAnalyzers(
	ctx context.Context, runner Runner, dir string, enabled, known []string,
) (FixAnalyzerSupport, error) {
	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: []string{"tool", "fix", "-flags"}})
	if err != nil {
		return FixAnalyzerSupport{}, err
	}
	if res.ExitCode != 0 {
		return FixAnalyzerSupport{}, fmt.Errorf("go tool fix -flags exited %d: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 10)))
	}
	registered, err := parseFixAnalyzerFlags(res.Stdout)
	if err != nil {
		return FixAnalyzerSupport{}, err
	}
	return compareFixAnalyzers(registered, enabled, known), nil
}

func compareFixAnalyzers(registered, enabled, known []string) FixAnalyzerSupport {
	var support FixAnalyzerSupport
	for _, name := range enabled {
		if !slices.Contains(registered, name) {
			support.Missing = append(support.Missing, name)
		}
	}
	for _, name := range registered {
		if !slices.Contains(known, name) {
			support.Unregistered = append(support.Unregistered, name)
		}
	}
	slices.Sort(support.Missing)
	slices.Sort(support.Unregistered)
	return support
}

// fixAnalyzerUsagePrefix and fixAnalyzerUsageSuffix bracket the usage text the
// analysis framework generates for the flag that enables an analyzer, which is
// what tells those flags apart from the driver's own.
const (
	fixAnalyzerUsagePrefix = "enable "
	fixAnalyzerUsageSuffix = " analysis"
)

func parseFixAnalyzerFlags(stream string) ([]string, error) {
	var flags []struct {
		Name  string `json:"Name"`
		Usage string `json:"Usage"`
	}
	if err := json.Unmarshal([]byte(stream), &flags); err != nil {
		return nil, fmt.Errorf("decoding go tool fix -flags output: %w", err)
	}
	var names []string
	for _, f := range flags {
		if !strings.HasPrefix(f.Usage, fixAnalyzerUsagePrefix) {
			continue
		}
		usage := strings.TrimSuffix(strings.TrimPrefix(f.Usage, fixAnalyzerUsagePrefix), fixAnalyzerUsageSuffix)
		// Go 1.27 quotes the analyzer name in the usage text; Go 1.26 did not.
		if strings.Trim(usage, `"`) == f.Name {
			names = append(names, f.Name)
		}
	}
	slices.Sort(names)
	return names, nil
}
