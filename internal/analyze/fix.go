package analyze

import (
	"bytes"
	"go/format"
	"go/token"

	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// Fixer is one rule whose remediation the harness performs itself.
//
// A rule whose fix is mechanical should ship with the mechanism, or the rule
// turns into a policy argument the first time a repository has a thousand
// findings of it. Rewrite reports whether it could read the file at all;
// admission still re-verifies afterwards, so a fixer is a convenience and never
// evidence.
type Fixer struct {
	RuleID  string
	Summary string
	Rewrite func(relPath string, src []byte) (out []byte, replaced int, parsed bool)
}

// Fixers returns every rule the harness can fix, freshly built so callers
// cannot mutate a shared table.
func Fixers() []Fixer {
	return []Fixer{
		{
			RuleID: policy.RuleCommentEmDash,
			Summary: "rewrite the em dash to a plain hyphen in comments only, " +
				"leaving string literals untouched",
			Rewrite: rewriteEmDashComments,
		},
	}
}

// FixerFor returns the fixer for a rule ID, if the harness has one.
func FixerFor(ruleID string) (Fixer, bool) {
	for _, f := range Fixers() {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return Fixer{}, false
}

// emDashBytes is the UTF-8 encoding of the forbidden rune, derived from the
// same escaped constant the scanner uses so this file contains no U+2014
// either. A function rather than a package variable: the harness allows no
// mutable package state, and a slice is mutable however it is used.
func emDashBytes() []byte { return []byte(string(EmDash)) }

// plainHyphen is what an em dash becomes.
const plainHyphen = "-"

// rewriteEmDashComments replaces em dashes inside Go comments and nowhere else.
//
// The spans come from the parser, so a string literal that contains the same
// rune is untouched by construction rather than by a pattern that tries to
// recognise one. That property is what makes the fixer safe to run over a
// repository whose literals carry client-facing copy. The edit is spliced into
// the original bytes rather than printed from the syntax tree, because printing
// would rewrite formatting the author chose and the fix would stop being one.
func rewriteEmDashComments(relPath string, src []byte) ([]byte, int, bool) {
	fset := token.NewFileSet()
	file, parsed := parseFile(fset, relPath, src)
	if !parsed {
		return nil, 0, false
	}
	var out []byte
	replaced, prev := 0, 0
	for _, group := range file.Comments {
		for _, c := range group.List {
			start, end := fset.Position(c.Pos()).Offset, fset.Position(c.End()).Offset
			if start < prev || end > len(src) {
				continue
			}
			text := src[start:end]
			hits := bytes.Count(text, emDashBytes())
			if hits == 0 {
				continue
			}
			out = append(out, src[prev:start]...)
			out = append(out, bytes.ReplaceAll(text, emDashBytes(), []byte(plainHyphen))...)
			replaced += hits
			prev = end
		}
	}
	if replaced == 0 {
		return src, 0, true
	}
	return reformatIfCanonical(src, append(out, src[prev:]...)), replaced, true
}

// reformatIfCanonical keeps a gofmt-clean file gofmt-clean.
//
// An em dash is three bytes and a hyphen is one, so a rewritten trailing comment
// can fall out of the alignment gofmt gives a run of them. Re-running the
// formatter closes that, but only where the file was already canonical: on a
// file that was not, reformatting would fold an unrelated change into the fix
// and the diff would stop being reviewable.
func reformatIfCanonical(original, rewritten []byte) []byte {
	canonical, err := format.Source(original)
	if err != nil || !bytes.Equal(canonical, original) {
		return rewritten
	}
	formatted, err := format.Source(rewritten)
	if err != nil {
		return rewritten
	}
	return formatted
}
