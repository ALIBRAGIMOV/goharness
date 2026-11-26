// Package cli dispatches subcommands, parses flags with the standard library,
// constructs the single injected logger, and maps outcomes onto the harness
// exit codes.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// Version is the harness version recorded in every report.
const Version = "0.11.0"

// Exit codes. They are the harness's contract with any caller.
const (
	ExitAdmitted     = 0
	ExitRejected     = 1
	ExitInconclusive = 2
	ExitAborted      = 130
)

// DefaultVerifyTimeout bounds a change admission run. Repository audits are
// unbounded by default because their cost scales with the codebase.
//
// Twenty minutes because ten was not enough for this harness to judge its own
// release commit on a CI runner: the race suite of a repository whose tests
// build git fixtures and run the full pipeline is six minutes on its own. A
// timeout bounds cost and never quality, so the budget is set where a real
// change on a real repository fits, and the report says where the time went.
const DefaultVerifyTimeout = 20 * time.Minute

// Streams are the output sinks a command writes to.
type Streams struct {
	Out io.Writer
	Err io.Writer
}

// Main dispatches one invocation and returns the process exit code.
func Main(ctx context.Context, args []string, streams Streams) int {
	if len(args) == 0 {
		p := newPrinter(streams.Err)
		p.printf("%s", usageText)
		return ExitInconclusive
	}
	command, rest := args[0], args[1:]
	if wantsHelp(rest) {
		p := newPrinter(streams.Out)
		p.printf("%s", commandUsage(command))
		return exitFor(p, ExitAdmitted)
	}
	switch command {
	case "fast", "verify", "audit":
		return runVerification(ctx, command, rest, streams)
	case "setup":
		return runSetup(ctx, rest, streams)
	case "tools":
		return runTools(ctx, rest, streams)
	case "fix":
		return runFix(ctx, rest, streams)
	case "explain":
		return runExplain(rest, streams)
	case "diff":
		return runDiff(rest, streams)
	case "doctor":
		return runDoctor(ctx, rest, streams)
	case "skill":
		return runSkill(ctx, rest, streams)
	case "version":
		return runVersion(streams)
	case "help", "-h", "--help":
		return runHelp(rest, streams)
	default:
		return unknownCommand(command, streams)
	}
}

// runHelp serves both the bare global usage and per-command help, so
// "goharness help verify" and "goharness verify -h" print the same text.
func runHelp(args []string, streams Streams) int {
	if len(args) == 0 {
		p := newPrinter(streams.Out)
		p.printf("%s", usageText)
		return exitFor(p, ExitAdmitted)
	}
	topic := args[0]
	if !hasCommandUsage(topic) {
		p := newPrinter(streams.Err)
		p.linef("no help topic for %q", topic)
		if suggestions := nearest(topic, knownCommands(), 3); len(suggestions) > 0 {
			p.linef("did you mean: %s", strings.Join(suggestions, ", "))
			p.linef("try: goharness help %s", suggestions[0])
		}
		return ExitInconclusive
	}
	p := newPrinter(streams.Out)
	p.printf("%s", commandUsage(topic))
	return exitFor(p, ExitAdmitted)
}

func wantsHelp(args []string) bool {
	return slices.Contains(args, "-h") || slices.Contains(args, "--help")
}

func unknownCommand(command string, streams Streams) int {
	p := newPrinter(streams.Err)
	p.linef("unknown command %q", command)
	if suggestions := nearest(command, knownCommands(), 3); len(suggestions) > 0 {
		p.linef("did you mean: %s", strings.Join(suggestions, ", "))
		p.linef("try: goharness %s", suggestions[0])
	} else {
		p.printf("\n%s", usageText)
	}
	return ExitInconclusive
}

// exitFor downgrades a success code when output could not be written, so a
// caller never reads a verdict the harness failed to deliver.
func exitFor(p *printer, code int) int {
	if p.failure() != nil {
		return ExitInconclusive
	}
	return code
}

type verifyFlags struct {
	asJSON      bool
	agent       bool
	quiet       bool
	noColor     bool
	logJSON     bool
	explainPlan bool
	noCache     bool
	baseline    bool
	verbosity   int
	dir         string
	base        string
	contract    string
	evidence    string
	reportPath  string
	limit       int
	jobs        int
	timeout     time.Duration
}

// Evidence rendering modes for --evidence.
const (
	evidenceFull = "full"
	evidenceDiff = "diff"
	evidenceNew  = "new"
	evidenceTop  = "top"
)

// evidenceModes lists the accepted values in the order the help prints them.
func evidenceModes() []string {
	return []string{evidenceFull, evidenceDiff, evidenceNew, evidenceTop}
}

// defaultEvidence is the view a mode renders when the flag is absent.
//
// verify is a gate on one change, so its report is about that change. audit and
// fast are about the repository, where narrowing to a diff would answer a
// question nobody asked.
func defaultEvidence(mode verify.Mode) string {
	if mode == verify.ModeVerify {
		return evidenceDiff
	}
	return evidenceFull
}

// DefaultEvidenceLimit is how many findings "--evidence top" keeps. A full
// report of a large repository runs past a megabyte of JSON, which is a whole
// context window for the agents that read it; the ordered top of the set
// plus the summary is a few tens of kilobytes and every omitted row remains
// resolvable by fingerprint.
const DefaultEvidenceLimit = 100

// reportOptions turns the flags into a rendering limit, rejecting a mode the
// document has no meaning for rather than quietly rendering something else.
func (f *verifyFlags) reportOptions() (report.Options, error) {
	switch f.evidence {
	case evidenceFull:
		return report.Options{Scope: report.ScopeFull}, nil
	case evidenceDiff:
		return report.Options{Scope: report.ScopeDiff}, nil
	case evidenceNew:
		return report.Options{Scope: report.ScopeNew}, nil
	case evidenceTop:
		if f.limit <= 0 {
			return report.Options{}, fmt.Errorf("--evidence-limit must be positive, got %d", f.limit)
		}
		return report.Options{Scope: report.ScopeFull, EvidenceLimit: f.limit}, nil
	default:
		return report.Options{}, fmt.Errorf("unknown --evidence mode %q; use one of %s",
			f.evidence, strings.Join(evidenceModes(), ", "))
	}
}

func bindVerifyFlags(fs *flag.FlagSet, mode verify.Mode) *verifyFlags {
	f := &verifyFlags{}
	fs.BoolVar(&f.asJSON, "json", false, "emit the goharness.report/v2 JSON document")
	fs.BoolVar(&f.agent, "agent", false, "machine protocol: JSON on stdout, human text on stderr")
	fs.BoolVar(&f.quiet, "quiet", false, "reduce output to the verdict line")
	fs.BoolVar(&f.noColor, "no-color", false, "never colourise output")
	fs.BoolVar(&f.logJSON, "log-json", false, "emit diagnostic logs as JSON instead of console format")
	fs.BoolVar(&f.explainPlan, "explain-plan", false, "print the obligation set and exit")
	fs.BoolVar(&f.noCache, "no-cache", false, "recompute the base snapshot instead of reusing cached evidence")
	fs.StringVar(&f.dir, "dir", ".", "directory inside the module to verify")
	fs.StringVar(&f.base, "base", "", "explicit base revision for comparison (verify only)")
	fs.StringVar(&f.contract, "contract", "", "task contract file")
	fs.StringVar(&f.reportPath, "report", "",
		"write the JSON document to `FILE` instead of stdout")
	fs.StringVar(&f.evidence, "evidence", defaultEvidence(mode),
		"which findings the report carries: "+strings.Join(evidenceModes(), ", "))
	fs.IntVar(&f.limit, "evidence-limit", DefaultEvidenceLimit,
		"how many findings `--evidence top` keeps, in consequence order")
	fs.IntVar(&f.jobs, "jobs", 0, "checks to run at once; zero means one per CPU")
	fs.BoolFunc("v", "enable INFO diagnostics", func(string) error { f.verbosity = max(f.verbosity, 1); return nil })
	fs.BoolFunc("vv", "enable DEBUG diagnostics", func(string) error { f.verbosity = 2; return nil })

	timeout := DefaultVerifyTimeout
	if mode == verify.ModeAudit {
		timeout = 0
		// Only audit binds it, so every other command rejects it as an unknown
		// flag rather than accepting a request it would silently not honour.
		fs.BoolVar(&f.baseline, "baseline", false,
			"after the audit, record its blocking findings as acknowledged debt in "+
				policy.DebtFileName+" (writes one file; commit it for it to take effect)")
	}
	fs.DurationVar(&f.timeout, "timeout", timeout, "wall-clock budget for the run; zero means unlimited")
	return f
}

func runVerification(ctx context.Context, command string, args []string, streams Streams) int {
	errOut := newPrinter(streams.Err)
	mode, ok := verify.ParseMode(command)
	if !ok {
		errOut.linef("unknown mode %q", command)
		return ExitInconclusive
	}
	fs := flag.NewFlagSet("goharness "+command, flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	flags := bindVerifyFlags(fs, mode)
	if err := fs.Parse(args); err != nil {
		errOut.printf("\n%s", commandUsage(command))
		return ExitInconclusive
	}
	if flags.base != "" && mode != verify.ModeVerify {
		errOut.linef("--base applies to `verify` only; %s does not compare against a base", command)
		errOut.linef("try: goharness verify --base %s", flags.base)
		return ExitInconclusive
	}
	if flags.jobs < 0 {
		errOut.linef("--jobs must be zero or a positive count, got %d", flags.jobs)
		return ExitInconclusive
	}

	logger := newLogger(streams.Err, LogOptions{Verbosity: flags.verbosity, JSON: flags.logJSON})
	reportOut, textOut := streams.Out, streams.Out
	if flags.agent {
		textOut = streams.Err
	}
	bar := newProgress(streams.Err, !flags.quiet && !flags.agent)

	result, err := verify.Run(ctx, Version, verify.Options{
		Mode: mode, Dir: flags.dir, Base: flags.base, ContractPath: flags.contract,
		Timeout: flags.timeout, Limit: int64(flags.jobs), Logger: logger, Progress: bar.Handle,
		PlanOnly: flags.explainPlan, NoCache: flags.noCache,
	})
	bar.Clear()
	if err != nil {
		errOut.linef("goharness %s: %v", command, err)
		if errors.Is(err, verify.ErrNotAModule) {
			errOut.linef("run goharness from inside a Go module, or pass --dir")
		}
		return ExitInconclusive
	}
	if flags.explainPlan {
		return explainPlan(streams, result)
	}
	code := renderResult(renderInput{
		streams: streams, errOut: errOut, command: command, flags: flags,
		result: result, reportOut: reportOut, textOut: textOut,
	})
	if !flags.baseline {
		return code
	}
	// Recording happens only once the run is complete and rendered: verification
	// is read-only, and a write from inside it would make the worktree guard
	// report, correctly, that the tree changed while it was being judged.
	return recordBaseline(textOut, result, code)
}

type renderInput struct {
	streams   Streams
	errOut    *printer
	command   string
	flags     *verifyFlags
	result    verify.Result
	reportOut io.Writer
	textOut   io.Writer
}

func renderResult(in renderInput) int {
	opts, err := in.flags.reportOptions()
	if err != nil {
		in.errOut.linef("goharness %s: %v", in.command, err)
		return ExitInconclusive
	}
	// --report moves the document off stdout. A run over a large repository takes
	// minutes, and the bridges an agent reaches the harness through give up well
	// inside that; redirecting a shell was the only way to keep the JSON, which
	// is not available to a caller that is not a shell.
	jsonOut, closeJSON, err := in.jsonSink()
	if err != nil {
		in.errOut.linef("goharness %s: %v", in.command, err)
		return ExitInconclusive
	}
	code := in.render(jsonOut, opts)
	if closeErr := closeJSON(); closeErr != nil {
		in.errOut.linef("goharness %s: %v", in.command, closeErr)
		return ExitInconclusive
	}
	return code
}

// jsonSink is where the JSON document goes, and how to finish writing it.
func (in renderInput) jsonSink() (io.Writer, func() error, error) {
	if in.flags.reportPath == "" {
		return in.reportOut, func() error { return nil }, nil
	}
	file, err := os.Create(in.flags.reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the report file: %w", err)
	}
	return file, func() error {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("writing the report file: %w", closeErr)
		}
		return nil
	}, nil
}

// render writes whatever this invocation asked for and returns the exit code.
//
// A --report file is written whatever the mode: a caller that named a file wants
// the document there, and leaving it empty because the run was not --json would
// be answering a different question than the one asked.
func (in renderInput) render(jsonOut io.Writer, opts report.Options) int {
	wantJSON := in.flags.agent || in.flags.asJSON || in.flags.reportPath != ""
	if wantJSON {
		if err := report.WriteJSONWithOptions(jsonOut, Version, in.result, opts); err != nil {
			in.errOut.linef("goharness %s: %v", in.command, err)
			return ExitInconclusive
		}
	}
	textOut := in.reportOut
	switch {
	case in.flags.agent:
		textOut = in.textOut
	case in.flags.asJSON && in.flags.reportPath == "":
		return in.result.Decision.Verdict.ExitCode()
	}
	if err := writeText(textOut, in.result, in.flags, opts.Scope); err != nil {
		in.errOut.linef("goharness %s: %v", in.command, err)
		return ExitInconclusive
	}
	return in.result.Decision.Verdict.ExitCode()
}

func writeText(w io.Writer, result verify.Result, flags *verifyFlags, scope report.Scope) error {
	return report.WriteTextWithOptions(w, Version, result, report.TextOptions{
		Palette: paletteFor(w, flags.noColor),
		Quiet:   flags.quiet,
		Scope:   scope,
	})
}

func explainPlan(streams Streams, result verify.Result) int {
	p := newPrinter(streams.Out)
	p.linef("verification plan for mode %s", result.Mode)
	p.linef("contract: %s", result.Contract.Source)
	if len(result.Risks.Active) == 0 {
		p.linef("risk domains: none detected")
	} else {
		for _, domain := range result.Risks.Active {
			p.linef("risk %s:", domain)
			for _, reason := range result.Risks.ReasonsFor(domain) {
				p.linef("    %s", reason)
			}
		}
	}
	p.linef("\nobligations (%d):", len(result.Plan.Obligations))
	for _, o := range result.Plan.Obligations {
		p.linef("  %-22s claim=%-22s producer=%-22s %s", o.Kind, o.Claim, o.Producer, o.Because)
	}
	p.linef("\nchecks: %s", strings.Join(result.Execution.CheckIDs(), ", "))
	return exitFor(p, ExitAdmitted)
}

func runExplain(args []string, streams Streams) int {
	errOut := newPrinter(streams.Err)
	fs := flag.NewFlagSet("goharness explain", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	reportPath := fs.String("report", "",
		"the goharness.report/v2 document to resolve a fingerprint against")
	// Flags are parsed around the positional argument rather than only before it:
	// "explain FINGERPRINT --report r.json" is the order a reader writes, and a
	// command that silently ignored the flag there would resolve nothing and say
	// the fingerprint was an unknown rule.
	id, ok := singlePositional(fs, args)
	if !ok {
		errOut.printf("%s", commandUsage("explain"))
		return ExitInconclusive
	}
	rule, found := policy.Lookup(id)
	if !found {
		return explainFingerprint(id, *reportPath, streams, errOut)
	}
	return explainRule(rule, newPrinter(streams.Out))
}

// singlePositional parses flags that appear on either side of the one operand a
// command takes, and reports whether it got exactly one.
func singlePositional(fs *flag.FlagSet, args []string) (string, bool) {
	var operands []string
	for remaining := args; ; {
		if err := fs.Parse(remaining); err != nil {
			return "", false
		}
		if fs.NArg() == 0 {
			break
		}
		operands = append(operands, fs.Arg(0))
		remaining = fs.Args()[1:]
	}
	if len(operands) != 1 {
		return "", false
	}
	return operands[0], true
}

// explainFingerprint resolves one row of a report by its fingerprint.
//
// This is what makes a truncated document usable rather than merely smaller:
// every omitted finding stays addressable, so an agent can hold the summary and
// still ask about any single row it did not receive.
func explainFingerprint(id, reportPath string, streams Streams, errOut *printer) int {
	if reportPath == "" {
		errOut.linef("unknown rule %q", id)
		if suggestions := suggestRules(id); len(suggestions) > 0 {
			errOut.linef("did you mean: %s", strings.Join(suggestions, ", "))
			errOut.linef("try: goharness explain %s", suggestions[0])
			return ExitInconclusive
		}
		errOut.linef("if this is an evidence fingerprint, name the report it came from:")
		errOut.linef("try: goharness explain %s --report report.json", id)
		return ExitInconclusive
	}
	finding, err := findingInReport(reportPath, id)
	if err != nil {
		errOut.linef("goharness explain: %v", err)
		return ExitInconclusive
	}

	out := newPrinter(streams.Out)
	out.linef("%s  %s", finding.Fingerprint, finding.RuleID)
	out.linef("location:       %s", locationOf(finding))
	out.linef("message:        %s", finding.Message)
	out.linef("consequence:    %s", orNone(finding.Consequence))
	if finding.RemedyClass != "" {
		out.linef("remedy class:   %s", finding.RemedyClass)
	}
	out.linef("state:          %s", orNone(string(finding.State)))
	out.linef("blocking:       %t", finding.Blocking)
	if finding.Fix != nil {
		out.linef("fix:            %s", finding.Fix.Command)
	}
	rule, ok := policy.Lookup(finding.RuleID)
	if !ok {
		out.linef("\nthis finding's rule %q is not in the registry, so it is advisory", finding.RuleID)
		return exitFor(out, ExitAdmitted)
	}
	out.linef("")
	return explainRule(rule, out)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func locationOf(f report.Finding) string {
	switch {
	case f.File != "" && f.Line > 0:
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	case f.File != "":
		return f.File
	case f.Package != "":
		return "package " + f.Package
	default:
		return "(none recorded)"
	}
}

// findingInReport reads one evidence row out of a report document. The whole
// document is decoded rather than streamed: a report is a file on disk that the
// caller just produced, and a partial parse would be a second way to be wrong
// about what it says.
func findingInReport(path, fingerprint string) (report.Finding, error) {
	doc, err := readDocument(path)
	if err != nil {
		return report.Finding{}, err
	}
	for _, f := range doc.Evidence {
		if f.Fingerprint == fingerprint {
			return f, nil
		}
	}
	if doc.EvidenceOmitted == 0 {
		return report.Finding{}, fmt.Errorf(
			"no finding with fingerprint %s in %s, and that report withheld nothing, "+
				"so the fingerprint is not from this run", fingerprint, path)
	}
	return report.Finding{}, fmt.Errorf(
		"no finding with fingerprint %s in %s; that report was written with "+
			"--evidence %s and withheld %d row(s), which it records as evidenceOmitted; "+
			"`--evidence full` always writes every row",
		fingerprint, path, orNone(doc.EvidenceScope), doc.EvidenceOmitted)
}

func explainRule(rule policy.Rule, out *printer) int {
	out.linef("%s  %s", rule.ID, rule.Title)
	out.linef("pack:           %s", rule.Pack)
	if dim, found := admission.DimensionOf(rule.ID); found {
		out.linef("dimension:      %s", dim)
	}
	out.linef("classification: %s", rule.Classification)
	out.linef("consequence:    %s", rule.Consequence)
	out.linef("lifecycle:      %s", rule.Lifecycle)
	out.linef("enforcement:    %s", rule.Enforcement)
	if rule.GoVersionConstraint != "" {
		out.linef("go constraint:  %s", rule.GoVersionConstraint)
	}
	if rule.PinnedCommit != "" {
		out.linef("pinned commit:  %s", rule.PinnedCommit)
	}
	out.linef("documentation:  %s", rule.DocURL)
	out.linef("\nrationale:\n%s", indent(rule.Rationale, "  "))
	if fixer, ok := analyze.FixerFor(rule.ID); ok {
		out.linef("mechanical fix:\n%s", indent("goharness fix --rule "+fixer.RuleID+
			"\n"+fixer.Summary, "  "))
	}
	// A rule that tells an operator only why it fired leaves every reader to
	// design the target idiom from scratch, and they will do it differently.
	if rule.Pattern != "" {
		out.linef("compliant pattern:\n%s", indent(rule.Pattern, "  "))
	}
	if enforced := policy.UberRulesEnforcedBy(rule.ID); len(enforced) > 0 {
		out.linef("enforces these Uber Go Style Guide rules:")
		for _, u := range enforced {
			out.linef("  %s  %s", u.ID, u.Title)
		}
	}
	return exitFor(out, ExitAdmitted)
}

// suggestRules offers the nearest rule IDs, preferring substring matches so a
// partial ID such as "SUPPRESS" finds both suppression rules.
func suggestRules(id string) []string {
	upper := strings.ToUpper(id)
	var contains []string
	all := make([]string, 0, 128)
	for _, r := range policy.Registry() {
		all = append(all, r.ID)
		if strings.Contains(strings.ToUpper(r.ID), upper) && len(contains) < 5 {
			contains = append(contains, r.ID)
		}
	}
	if len(contains) > 0 {
		return contains
	}
	return nearest(id, all, 3)
}

func runVersion(streams Streams) int {
	out := newPrinter(streams.Out)
	out.linef("goharness %s", Version)
	out.linef("go:              %s", tool.GoVersion())
	out.linef("golangci-lint:   %s (exact pin)", tool.GolangciLintPin)
	out.linef("x/vuln:          %s (embedded)", tool.XVulnVersion())
	out.linef("leak check:      %s, from the toolchain above", leakcheck.Method)
	out.linef("go fix:          %d analyzers, from the toolchain above", len(policy.GoFixAnalyzers()))
	out.linef("uber guide:      %s", policy.UberGuideCommit)
	out.linef("report schema:   %s", report.SchemaID)
	return exitFor(out, ExitAdmitted)
}

// Run is the process entry point used by cmd/goharness.
func Run(ctx context.Context) int {
	return Main(ctx, os.Args[1:], Streams{Out: os.Stdout, Err: os.Stderr})
}
