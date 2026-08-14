package analyze

import (
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strings"
	"unicode"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// EmDash is the rune the agent-hygiene pack forbids inside Go comments. It is
// written as an escape so that this source file itself contains no U+2014.
const EmDash = '\u2014'

// Documentation comment budgets, in lines.
const (
	docCommentAdvisoryLines = 15
	docCommentRequiredLines = 30
)

func (s *scanner) scanComments() {
	for _, group := range s.file.Comments {
		for _, c := range group.List {
			body := commentBody(c.Text)
			trimmed := strings.TrimLeft(body, " \t")
			switch {
			case strings.HasPrefix(trimmed, "nolint"):
				s.add(c.Pos(), policy.RuleSuppressNolint,
					"inline suppression directive //nolint is forbidden; fix the finding or record a scoped exception in goharness.yaml",
					evidence.SeverityError, false)
			case strings.HasPrefix(trimmed, "lint:ignore"), strings.HasPrefix(trimmed, "lint:file-ignore"):
				s.add(c.Pos(), policy.RuleSuppressStaticcheck,
					"inline suppression directive //lint:ignore is forbidden; fix the finding or record a scoped exception in goharness.yaml",
					evidence.SeverityError, false)
			case strings.HasPrefix(trimmed, "#nosec"):
				s.add(c.Pos(), policy.RuleSuppressNosec,
					"inline suppression directive #nosec is forbidden; fix the finding or record a scoped exception in goharness.yaml",
					evidence.SeverityError, false)
			case strings.HasPrefix(trimmed, "revive:disable"):
				s.add(c.Pos(), policy.RuleSuppressRevive,
					"inline suppression directive //revive:disable is forbidden; fix the finding or record a scoped exception in goharness.yaml",
					evidence.SeverityError, false)
			}
			if strings.ContainsRune(c.Text, EmDash) {
				s.add(c.Pos(), policy.RuleCommentEmDash,
					"comment contains the em dash U+2014; use a plain hyphen",
					evidence.SeverityError, false)
			}
		}
	}
}

func commentBody(text string) string {
	if rest, ok := strings.CutPrefix(text, "//"); ok {
		return rest
	}
	rest := strings.TrimPrefix(text, "/*")
	return strings.TrimSuffix(rest, "*/")
}

func (s *scanner) scanDocSizes() {
	for _, decl := range s.file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			s.checkDocSize(d.Doc, "func "+d.Name.Name)
		case *ast.GenDecl:
			s.checkDocSize(d.Doc, d.Tok.String()+" declaration")
		}
	}
	s.checkDocSize(s.file.Doc, "package "+s.file.Name.Name)
}

func (s *scanner) checkDocSize(doc *ast.CommentGroup, subject string) {
	if doc == nil {
		return
	}
	lines := countCommentLines(doc)
	switch {
	case lines > docCommentRequiredLines:
		s.add(doc.Pos(), policy.RuleCommentSize,
			commentSizeMessage(subject, lines, docCommentRequiredLines),
			evidence.SeverityError, false)
	case lines > docCommentAdvisoryLines:
		s.add(doc.Pos(), policy.RuleCommentSize,
			commentSizeMessage(subject, lines, docCommentAdvisoryLines),
			evidence.SeverityWarning, true)
	}
}

func commentSizeMessage(subject string, lines, budget int) string {
	return fmt.Sprintf("documentation comment on %s spans %d lines, over the budget of %d",
		subject, lines, budget)
}

func countCommentLines(doc *ast.CommentGroup) int {
	count := 0
	for _, c := range doc.List {
		count += strings.Count(c.Text, "\n") + 1
	}
	return count
}

// restatementRatio is the fraction of a comment's meaningful words that must
// also appear as identifiers in the following statement before the comment
// counts as a restatement.
const restatementRatio = 0.6

// restatementMinWords keeps the heuristic away from two-word notes, where a
// full overlap carries no signal.
const restatementMinWords = 3

// scanRestatements looks only at comments inside function bodies. Doc comments
// legitimately name the symbol they document, so including them would make the
// heuristic fire on correct documentation.
func (s *scanner) scanRestatements() {
	docPositions := map[token.Pos]bool{}
	ast.Inspect(s.file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.FuncDecl:
			if d.Doc != nil {
				docPositions[d.Doc.Pos()] = true
			}
		case *ast.GenDecl:
			if d.Doc != nil {
				docPositions[d.Doc.Pos()] = true
			}
		case *ast.Field:
			if d.Doc != nil {
				docPositions[d.Doc.Pos()] = true
			}
		}
		return true
	})
	if s.file.Doc != nil {
		docPositions[s.file.Doc.Pos()] = true
	}

	for _, decl := range s.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		s.checkBodyRestatements(fn.Body, docPositions)
	}
}

func (s *scanner) checkBodyRestatements(body *ast.BlockStmt, docPositions map[token.Pos]bool) {
	for _, group := range s.file.Comments {
		if group.Pos() < body.Pos() || group.End() > body.End() || docPositions[group.Pos()] {
			continue
		}
		stmt := followingStatement(body, group.End())
		if stmt == nil {
			continue
		}
		words := meaningfulWords(group.Text())
		if len(words) < restatementMinWords {
			continue
		}
		code := identifierWords(stmt)
		overlap := 0
		for _, w := range words {
			if code[w] {
				overlap++
			}
		}
		if float64(overlap)/float64(len(words)) >= restatementRatio {
			s.add(group.Pos(), policy.RuleCommentRestates,
				"comment repeats the identifiers of the statement it precedes and carries no additional information",
				evidence.SeverityInfo, true)
		}
	}
}

func followingStatement(body *ast.BlockStmt, after token.Pos) ast.Stmt {
	var best ast.Stmt
	ast.Inspect(body, func(n ast.Node) bool {
		stmt, ok := n.(ast.Stmt)
		if !ok || stmt.Pos() < after {
			return true
		}
		if best == nil || stmt.Pos() < best.Pos() {
			best = stmt
		}
		return true
	})
	return best
}

func meaningfulWords(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, word := range splitWords(text) {
		if isStopWord(word) || len(word) < 2 || seen[word] {
			continue
		}
		seen[word] = true
		out = append(out, word)
	}
	return out
}

func identifierWords(stmt ast.Stmt) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(stmt, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		for _, w := range splitWords(ident.Name) {
			out[w] = true
		}
		return true
	})
	return out
}

// splitWords lowercases and splits on both non-letter runes and camelCase
// boundaries so "readFile" and "read the file" share tokens.
func splitWords(s string) []string {
	var out []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			out = append(out, strings.ToLower(string(current)))
			current = nil
		}
	}
	prev := rune(0)
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			current = append(current, r)
		default:
			current = append(current, r)
		}
		prev = r
	}
	flush()
	return out
}

// stopWords carry no information about what code does, so they are removed
// before the overlap ratio is computed.
func stopWords() []string {
	return []string{
		"a", "an", "and", "are", "as", "at", "be", "but", "by", "do", "does",
		"for", "from", "here", "if", "in", "into", "is", "it", "its", "not",
		"of", "on", "or", "so", "that", "the", "then", "this", "to", "we",
		"when", "which", "while", "with", "you",
	}
}

func isStopWord(w string) bool {
	return slices.Contains(stopWords(), w)
}
