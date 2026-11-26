package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ALIBRAGIMOV/goharness/internal/report"
)

// runDiff compares two reports of the same subject on fingerprint identity.
//
// It is the one command that reads no repository at all: two documents in, one
// comparison out, no git, no cache, no worktree. That is what makes it usable
// as progress accounting by something that did not perform either run.
func runDiff(args []string, streams Streams) int {
	errOut := newPrinter(streams.Err)
	fs := flag.NewFlagSet("goharness diff", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	asJSON := fs.Bool("json", false, "emit the goharness.diff/v1 JSON document")
	noColor := fs.Bool("no-color", false, "never colourise output")
	allowMismatch := fs.Bool("allow-scope-mismatch", false,
		"compare reports written under different --evidence scopes anyway")
	if err := fs.Parse(args); err != nil {
		errOut.printf("\n%s", commandUsage("diff"))
		return report.DiffExitError
	}
	if fs.NArg() != 2 {
		errOut.linef("goharness diff takes exactly two reports, got %d", fs.NArg())
		errOut.printf("\n%s", commandUsage("diff"))
		return report.DiffExitError
	}

	oldPath, newPath := fs.Arg(0), fs.Arg(1)
	oldDoc, err := readDocument(oldPath)
	if err != nil {
		errOut.linef("goharness diff: %v", err)
		return report.DiffExitError
	}
	newDoc, err := readDocument(newPath)
	if err != nil {
		errOut.linef("goharness diff: %v", err)
		return report.DiffExitError
	}

	d := report.CompareDocuments(oldDoc, newDoc)
	if err := writeDiff(streams.Out, d, *asJSON, *noColor, oldPath, newPath); err != nil {
		errOut.linef("goharness diff: %v", err)
		return report.DiffExitError
	}
	// A comparison of two different views of the evidence is arithmetic, not a
	// burn-down: rows the narrower report never carried come out as repairs.
	// Warning and returning a clean exit code hands a number nobody should act on
	// to whatever automated the comparison.
	if d.Old.Scope != d.New.Scope && !*allowMismatch {
		errOut.linef("goharness diff: %s was written with --evidence %s and %s with %s, "+
			"so what one carries the other never did", oldPath, orNone(d.Old.Scope),
			newPath, orNone(d.New.Scope))
		errOut.linef("rerun both with the same --evidence, or pass --allow-scope-mismatch " +
			"to read the counts as the mechanical comparison they are")
		return report.DiffExitError
	}
	return d.ExitCode
}

func writeDiff(w io.Writer, d report.Diff, asJSON, noColor bool, oldPath, newPath string) error {
	if asJSON {
		return report.WriteDiffJSON(w, d)
	}
	return report.WriteDiffText(w, d, report.DiffTextOptions{
		Palette: paletteFor(w, noColor), OldLabel: oldPath, NewLabel: newPath,
	})
}

func readDocument(path string) (report.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return report.Document{}, fmt.Errorf("reading the report: %w", err)
	}
	return report.ParseDocument(path, data)
}
