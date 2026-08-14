// Package cli dispatches subcommands, parses flags with the standard library,
// constructs the single injected logger, and maps outcomes onto the harness
// exit codes.
package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// Version is the harness version recorded in every report.
const Version = "0.3.0"

// Exit codes. They are the harness's contract with any caller.
const (
	ExitAdmitted     = 0
	ExitRejected     = 1
	ExitInconclusive = 2
	ExitAborted      = 130
)

// DefaultVerifyTimeout bounds a change admission run. Repository audits are
// unbounded by default because their cost scales with the codebase.
const DefaultVerifyTimeout = 10 * time.Minute

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
	case "fast", "verify", "audit", "deep":
		return runVerification(ctx, command, rest, streams)
	case "setup":
		return runSetup(ctx, rest, streams)
	case "tools":
		return runTools(ctx, rest, streams)
	case "explain":
		return runExplain(rest, streams)
	case "doctor":
		return runDoctor(ctx, rest, streams)
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
		p.line("no help topic for %q", topic)
		if suggestions := nearest(topic, knownCommands(), 3); len(suggestions) > 0 {
			p.line("did you mean: %s", strings.Join(suggestions, ", "))
			p.line("try: goharness help %s", suggestions[0])
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
	p.line("unknown command %q", command)
	if suggestions := nearest(command, knownCommands(), 3); len(suggestions) > 0 {
		p.line("did you mean: %s", strings.Join(suggestions, ", "))
		p.line("try: goharness %s", suggestions[0])
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
	verbosity   int
	dir         string
	base        string
	contract    string
	timeout     time.Duration
}

func bindVerifyFlags(fs *flag.FlagSet, mode verify.Mode) *verifyFlags {
	f := &verifyFlags{}
	fs.BoolVar(&f.asJSON, "json", false, "emit the goharness.report/v2 JSON document")
	fs.BoolVar(&f.agent, "agent", false, "machine protocol: JSON on stdout, human text on stderr")
	fs.BoolVar(&f.quiet, "quiet", false, "reduce output to the verdict line")
	fs.BoolVar(&f.noColor, "no-color", false, "never colourise output")
	fs.BoolVar(&f.logJSON, "log-json", false, "emit diagnostic logs as JSON instead of console format")
	fs.BoolVar(&f.explainPlan, "explain-plan", false, "print the obligation set and exit")
	fs.StringVar(&f.dir, "dir", ".", "directory inside the module to verify")
	fs.StringVar(&f.base, "base", "", "explicit base revision for comparison (verify only)")
	fs.StringVar(&f.contract, "contract", "", "task contract file")
	fs.BoolFunc("v", "enable INFO diagnostics", func(string) error { f.verbosity = max(f.verbosity, 1); return nil })
	fs.BoolFunc("vv", "enable DEBUG diagnostics", func(string) error { f.verbosity = 2; return nil })

	timeout := DefaultVerifyTimeout
	if mode == verify.ModeAudit {
		timeout = 0
	}
	fs.DurationVar(&f.timeout, "timeout", timeout, "wall-clock budget for the run; zero means unlimited")
	return f
}

func runVerification(ctx context.Context, command string, args []string, streams Streams) int {
	errOut := newPrinter(streams.Err)
	mode, ok := verify.ParseMode(command)
	if !ok {
		errOut.line("unknown mode %q", command)
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
		errOut.line("--base applies to `verify` only; %s does not compare against a base", command)
		errOut.line("try: goharness verify --base %s", flags.base)
		return ExitInconclusive
	}
	if command == "deep" {
		errOut.line("note: `deep` is deprecated and now runs `audit`; use `goharness audit`")
	}

	logger := newLogger(streams.Err, LogOptions{
		Verbosity: flags.verbosity, JSON: flags.logJSON, Quiet: flags.agent,
	})
	reportOut, textOut := streams.Out, streams.Out
	if flags.agent {
		textOut = streams.Err
	}
	bar := newProgress(streams.Err, !flags.quiet && !flags.agent)

	result, err := verify.Run(ctx, Version, verify.Options{
		Mode: mode, Dir: flags.dir, Base: flags.base, ContractPath: flags.contract,
		Timeout: flags.timeout, Logger: logger, Progress: bar.Handle,
		PlanOnly: flags.explainPlan,
	})
	bar.Clear()
	if syncErr := syncLogger(logger); syncErr != nil {
		errOut.line("goharness %s: %v", command, syncErr)
	}
	if err != nil {
		errOut.line("goharness %s: %v", command, err)
		if errors.Is(err, verify.ErrNotAModule) {
			errOut.line("run goharness from inside a Go module, or pass --dir")
		}
		return ExitInconclusive
	}
	if flags.explainPlan {
		return explainPlan(streams, result)
	}
	return renderResult(renderInput{
		streams: streams, errOut: errOut, command: command, flags: flags,
		result: result, reportOut: reportOut, textOut: textOut,
	})
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
	if in.flags.agent {
		if err := report.WriteJSON(in.reportOut, Version, in.result); err != nil {
			in.errOut.line("goharness %s: %v", in.command, err)
			return ExitInconclusive
		}
		if err := writeText(in.textOut, in.result, in.flags); err != nil {
			in.errOut.line("goharness %s: %v", in.command, err)
			return ExitInconclusive
		}
		return in.result.Decision.Verdict.ExitCode()
	}
	if in.flags.asJSON {
		if err := report.WriteJSON(in.reportOut, Version, in.result); err != nil {
			in.errOut.line("goharness %s: %v", in.command, err)
			return ExitInconclusive
		}
		return in.result.Decision.Verdict.ExitCode()
	}
	if err := writeText(in.reportOut, in.result, in.flags); err != nil {
		in.errOut.line("goharness %s: %v", in.command, err)
		return ExitInconclusive
	}
	return in.result.Decision.Verdict.ExitCode()
}

func writeText(w io.Writer, result verify.Result, flags *verifyFlags) error {
	return report.WriteTextWithOptions(w, Version, result, report.TextOptions{
		Palette: paletteFor(w, flags.noColor),
		Quiet:   flags.quiet,
	})
}

func explainPlan(streams Streams, result verify.Result) int {
	p := newPrinter(streams.Out)
	p.line("verification plan for mode %s", result.Mode)
	p.line("contract: %s", result.Contract.Source)
	if len(result.Risks.Active) == 0 {
		p.line("risk domains: none detected")
	} else {
		for _, domain := range result.Risks.Active {
			p.line("risk %s:", domain)
			for _, reason := range result.Risks.ReasonsFor(domain) {
				p.line("    %s", reason)
			}
		}
	}
	p.line("\nobligations (%d):", len(result.Plan.Obligations))
	for _, o := range result.Plan.Obligations {
		p.line("  %-22s claim=%-22s producer=%-22s %s", o.Kind, o.Claim, o.Producer, o.Because)
	}
	p.line("\nchecks: %s", strings.Join(result.Execution.CheckIDs(), ", "))
	return exitFor(p, ExitAdmitted)
}

func runExplain(args []string, streams Streams) int {
	errOut := newPrinter(streams.Err)
	fs := flag.NewFlagSet("goharness explain", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	if err := fs.Parse(args); err != nil {
		return ExitInconclusive
	}
	if fs.NArg() != 1 {
		errOut.printf("%s", commandUsage("explain"))
		return ExitInconclusive
	}
	id := fs.Arg(0)
	rule, ok := policy.Lookup(id)
	if !ok {
		errOut.line("unknown rule %q", id)
		if suggestions := suggestRules(id); len(suggestions) > 0 {
			errOut.line("did you mean: %s", strings.Join(suggestions, ", "))
			errOut.line("try: goharness explain %s", suggestions[0])
		}
		return ExitInconclusive
	}

	out := newPrinter(streams.Out)
	out.line("%s  %s", rule.ID, rule.Title)
	out.line("pack:           %s", rule.Pack)
	if dim, found := admission.DimensionOf(rule.ID); found {
		out.line("dimension:      %s", dim)
	}
	out.line("classification: %s", rule.Classification)
	out.line("lifecycle:      %s", rule.Lifecycle)
	out.line("enforcement:    %s", rule.Enforcement)
	if rule.GoVersionConstraint != "" {
		out.line("go constraint:  %s", rule.GoVersionConstraint)
	}
	if rule.PinnedCommit != "" {
		out.line("pinned commit:  %s", rule.PinnedCommit)
	}
	out.line("documentation:  %s", rule.DocURL)
	out.line("\nrationale:\n%s", indent(rule.Rationale, "  "))
	if enforced := policy.UberRulesEnforcedBy(rule.ID); len(enforced) > 0 {
		out.line("enforces these Uber Go Style Guide rules:")
		for _, u := range enforced {
			out.line("  %s  %s", u.ID, u.Title)
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
	out.line("goharness %s", Version)
	out.line("go:              %s", tool.GoVersion())
	out.line("golangci-lint:   %s (exact pin)", tool.GolangciLintPin)
	out.line("uber guide:      %s", policy.UberGuideCommit)
	out.line("report schema:   %s", report.SchemaID)
	return exitFor(out, ExitAdmitted)
}

// Run is the process entry point used by cmd/goharness.
func Run(ctx context.Context) int {
	return Main(ctx, os.Args[1:], Streams{Out: os.Stdout, Err: os.Stderr})
}
