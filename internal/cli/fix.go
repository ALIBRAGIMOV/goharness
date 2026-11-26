package cli

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/analyze"
	"github.com/ALIBRAGIMOV/goharness/internal/repo"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// runFix applies the mechanical remediation for one rule.
//
// It is a write command, deliberately separate from every verification command:
// verify, audit and fast are read-only and must never reach this code, so a
// verdict can never be produced by a run that also edited the tree. Admission
// re-verifies afterwards like any other change.
func runFix(ctx context.Context, args []string, streams Streams) int {
	flags := flag.NewFlagSet("goharness fix", flag.ContinueOnError)
	flags.SetOutput(streams.Err)
	rule := flags.String("rule", "", "the rule to fix")
	dryRun := flags.Bool("dry-run", false, "print a unified diff instead of writing files")
	dir := flags.String("dir", ".", "directory inside the module to fix")
	if err := flags.Parse(args); err != nil {
		return ExitInconclusive
	}
	errOut := newPrinter(streams.Err)
	if *rule == "" {
		errOut.linef("goharness fix: --rule is required")
		listFixableRules(errOut)
		return ExitInconclusive
	}
	fixer, ok := analyze.FixerFor(*rule)
	if !ok {
		errOut.linef("goharness fix: no fixer for rule %q", *rule)
		listFixableRules(errOut)
		errOut.linef("run `goharness explain %s` for what the rule asks for", *rule)
		return ExitInconclusive
	}

	r, err := repo.Discover(ctx, repo.ExecGit{Runner: tool.ExecRunner{}}, *dir)
	if err != nil {
		errOut.linef("goharness fix: %v", err)
		return ExitInconclusive
	}
	files, err := goFilesUnder(r.Root)
	if err != nil {
		errOut.linef("goharness fix: %v", err)
		return ExitInconclusive
	}
	return applyFixer(fixOptions{
		fixer: fixer, root: r.Root, files: files, dryRun: *dryRun,
		out: newPrinter(streams.Out), errOut: errOut,
	})
}

type fixOptions struct {
	fixer  analyze.Fixer
	root   string
	files  []string
	dryRun bool
	out    *printer
	errOut *printer
}

func applyFixer(in fixOptions) int {
	changedFiles, changes := 0, 0
	for _, rel := range in.files {
		full := filepath.Join(in.root, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil {
			in.errOut.linef("goharness fix: %v", err)
			return ExitInconclusive
		}
		src, err := os.ReadFile(full)
		if err != nil {
			in.errOut.linef("goharness fix: %v", err)
			return ExitInconclusive
		}
		// A file that does not parse is the compile check's finding, not this
		// command's: rewriting one would mean guessing where its comments are.
		rewritten, replaced, parsed := in.fixer.Rewrite(rel, src)
		if !parsed || replaced == 0 {
			continue
		}
		changedFiles++
		changes += replaced
		if in.dryRun {
			in.out.printf("%s", unifiedDiff(rel, src, rewritten))
			continue
		}
		if err := os.WriteFile(full, rewritten, info.Mode().Perm()); err != nil {
			in.errOut.linef("goharness fix: writing %s: %v", rel, err)
			return ExitInconclusive
		}
		in.out.linef("%s: %d replacement(s)", rel, replaced)
	}
	verb := "rewrote"
	if in.dryRun {
		verb = "would rewrite"
	}
	in.out.linef("%s %s: %s %d change(s) in %d file(s)", in.fixer.RuleID, in.fixer.Summary, verb, changes, changedFiles)
	if !in.dryRun && changedFiles > 0 {
		in.out.linef("re-run `goharness verify --agent`; a fix is not evidence")
	}
	return exitFor(in.out, ExitAdmitted)
}

func listFixableRules(p *printer) {
	p.linef("rules goharness can fix:")
	for _, f := range analyze.Fixers() {
		p.linef("  %-16s %s", f.RuleID, f.Summary)
	}
}

// goFilesUnder lists the module's Go files in slash form, skipping the
// directories the go command never builds from. Their contents are not this
// module's code, so rewriting them would be editing someone else's tree.
func goFilesUnder(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path == root {
				return nil
			}
			if name == "testdata" || name == "vendor" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing Go files under %s: %w", root, err)
	}
	return out, nil
}

// diffContext is how many unchanged lines surround a hunk.
const diffContext = 3

// unifiedDiff renders a line-oriented diff of a rewrite.
//
// Every fixer this command carries substitutes within a line and never adds or
// removes one, so a positional comparison is exact rather than an approximation
// of one. A rewrite that did change the line count would make that untrue, so
// the whole file is shown instead of a wrong diff.
func unifiedDiff(rel string, before, after []byte) string {
	oldLines, newLines := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", rel, rel)
	if len(oldLines) != len(newLines) {
		fmt.Fprintf(&b, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
		for _, line := range oldLines {
			fmt.Fprintf(&b, "-%s\n", line)
		}
		for _, line := range newLines {
			fmt.Fprintf(&b, "+%s\n", line)
		}
		return b.String()
	}
	for _, h := range hunksOf(oldLines, newLines) {
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", h.start+1, h.end-h.start, h.start+1, h.end-h.start)
		for i := h.start; i < h.end; i++ {
			if oldLines[i] == newLines[i] {
				fmt.Fprintf(&b, " %s\n", oldLines[i])
				continue
			}
			fmt.Fprintf(&b, "-%s\n+%s\n", oldLines[i], newLines[i])
		}
	}
	return b.String()
}

type hunk struct{ start, end int }

// hunksOf groups changed lines that are close enough to share their context.
func hunksOf(oldLines, newLines []string) []hunk {
	var out []hunk
	for i := range oldLines {
		if oldLines[i] == newLines[i] {
			continue
		}
		start, end := max(i-diffContext, 0), min(i+diffContext+1, len(oldLines))
		if n := len(out); n > 0 && start <= out[n-1].end {
			out[n-1].end = end
			continue
		}
		out = append(out, hunk{start: start, end: end})
	}
	return out
}
