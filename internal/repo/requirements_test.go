package repo

import (
	"slices"
	"testing"
)

const modFile = `module example.com/app

go 1.26

toolchain go1.26.6

require golang.org/x/sync v0.19.0

require (
	go.uber.org/zap v1.27.1
	golang.org/x/tools v0.41.0 // indirect
	// a comment inside the block is not a requirement
	golang.org/x/vuln v1.7.0
)

replace example.com/other => ../other

exclude golang.org/x/text v0.3.0
`

func TestParseRequirementsReadsBothForms(t *testing.T) {
	t.Parallel()
	want := []Requirement{
		{Path: "golang.org/x/sync", Version: "v0.19.0", Line: 7},
		{Path: "go.uber.org/zap", Version: "v1.27.1", Line: 10},
		{Path: "golang.org/x/tools", Version: "v0.41.0", Indirect: true, Line: 11},
		{Path: "golang.org/x/vuln", Version: "v1.7.0", Line: 13},
	}
	got := ParseRequirements(modFile)
	if !slices.Equal(got, want) {
		t.Fatalf("ParseRequirements =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseRequirementsIgnoresEverythingElse(t *testing.T) {
	t.Parallel()
	src := "module example.com/app\n\ngo 1.26\n\nreplace a => b\n\nrequire (\n)\n"
	if got := ParseRequirements(src); len(got) != 0 {
		t.Fatalf("ParseRequirements found requirements in a file with none: %+v", got)
	}
}
