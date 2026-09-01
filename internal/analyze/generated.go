package analyze

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// generatedHeaderLimit bounds how much of a file is read looking for the
// marker. The convention places it above the package clause, so a file that has
// not declared itself generated within this much text never will.
const generatedHeaderLimit = 64 << 10

// IsGenerated reports whether a file carries the conventional
// `// Code generated ... DO NOT EDIT.` line before its package clause.
//
// The marker is a claim, not a fact: any author can type it. Callers use it to
// decide what a change is not responsible for, never to decide that code is
// correct.
func IsGenerated(tree fs.FS, rel string) (_ bool, err error) {
	file, err := tree.Open(rel)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", rel, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	lines := bufio.NewScanner(io.LimitReader(file, generatedHeaderLimit))
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		switch {
		case strings.HasPrefix(line, "package "):
			return false, nil
		case strings.HasPrefix(line, "// Code generated ") && strings.HasSuffix(line, " DO NOT EDIT."):
			return true, nil
		}
	}
	if scanErr := lines.Err(); scanErr != nil {
		return false, fmt.Errorf("reading %s: %w", rel, scanErr)
	}
	return false, nil
}
