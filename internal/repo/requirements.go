package repo

import (
	"strings"
)

// Requirement is one module a go.mod file requires.
type Requirement struct {
	Path     string
	Version  string
	Indirect bool
	// Line is the 1-based line of the directive in the file it was read from.
	Line int
}

// ParseRequirements reads the require directives of a go.mod file, in both the
// single-line and the block form.
//
// The reader is deliberately narrow: it knows the two forms the go command
// writes and nothing else, the same restriction parseGoMod lives under. The
// alternative is a dependency on golang.org/x/mod, and adding a module to
// read the file that lists modules is the decision this rule exists to make
// visible.
func ParseRequirements(src string) []Requirement {
	var out []Requirement
	inBlock := false
	for n, raw := range strings.Split(src, "\n") {
		line, comment, _ := strings.Cut(raw, "//")
		fields := strings.Fields(line)
		switch {
		case inBlock && len(fields) == 1 && fields[0] == ")":
			inBlock = false
		case inBlock && len(fields) == 2:
			out = append(out, requirement(fields[0], fields[1], comment, n+1))
		case !inBlock && len(fields) == 2 && fields[0] == "require" && fields[1] == "(":
			inBlock = true
		case !inBlock && len(fields) == 3 && fields[0] == "require":
			out = append(out, requirement(fields[1], fields[2], comment, n+1))
		}
	}
	return out
}

func requirement(path, version, comment string, line int) Requirement {
	return Requirement{
		Path: path, Version: version, Line: line,
		Indirect: strings.HasPrefix(strings.TrimSpace(comment), "indirect"),
	}
}
