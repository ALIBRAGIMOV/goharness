package tool_test

import (
	"slices"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// The scan behind these cases is deliberately partial. A .golangci.yml in the
// wild is arbitrary YAML, and the cost of a wrong shadow is higher than the cost
// of a missing one: a number in front of an operator that their own file does
// not support loses more trust than saying nothing. So the guards here come in
// pairs, and the must-not-fire half matters as much as the other.

func shadowByID(shadows []tool.Shadow, id string) (tool.Shadow, bool) {
	for _, s := range shadows {
		if s.ID == id {
			return s, true
		}
	}
	return tool.Shadow{}, false
}

func detect(src string) []tool.Shadow {
	return tool.DetectGolangciShadows([]byte(src), tool.StrictPackLinters())
}

// TestStrictPackLintersComeFromTheEmbeddedConfig keeps the comparison honest:
// the set a shadow is measured against is the set the harness actually runs.
func TestStrictPackLintersComeFromTheEmbeddedConfig(t *testing.T) {
	linters := tool.StrictPackLinters()
	for _, want := range []string{"errcheck", "gosec", "gochecknoglobals", "staticcheck"} {
		if !slices.Contains(linters, want) {
			t.Fatalf("strict pack linters = %v, want %s among them", linters, want)
		}
	}
	if !slices.IsSorted(linters) {
		t.Fatalf("strict pack linters are not sorted: %v", linters)
	}
}

const v1Config = `run:
  tests: true
linters:
  disable-all: true
  enable:
    - errcheck
    - staticcheck
linters-settings:
  errcheck:
    check-type-assertions: true
issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - errcheck
        - gosec
`

const v2Config = `version: "2"
linters:
  default: none
  enable:
    - errcheck
    - gosec
  settings:
    errcheck:
      check-blank: true
  exclusions:
    rules:
      - path: ".*_test\\.go"
        linters: [errcheck]
`

func TestDetectGolangciShadowsReadsBothLayouts(t *testing.T) {
	for name, src := range map[string]string{"v1": v1Config, "v2": v2Config} {
		t.Run(name, func(t *testing.T) {
			shadows := detect(src)
			off, ok := shadowByID(shadows, tool.ShadowLintersOff)
			if !ok {
				t.Fatalf("no disabled-linter shadow: %+v", shadows)
			}
			// gochecknoglobals is in the strict pack and in neither enable list.
			if !slices.Contains(off.Linters, "gochecknoglobals") {
				t.Fatalf("disabled linters = %v", off.Linters)
			}
			if slices.Contains(off.Linters, "errcheck") {
				t.Fatalf("a linter the config enables was reported as off: %v", off.Linters)
			}
			exclusion, ok := shadowByID(shadows, tool.ShadowTestExclusion)
			if !ok {
				t.Fatalf("no test-file exclusion shadow: %+v", shadows)
			}
			if !slices.Contains(exclusion.Linters, "errcheck") {
				t.Fatalf("test exclusion linters = %v", exclusion.Linters)
			}
		})
	}
}

// TestCheckBlankShadowFollowsTheSetting is the pair that decides whether this
// section can be trusted at all: it fires where the setting is absent and stays
// silent where the repository already asks for it.
func TestCheckBlankShadowFollowsTheSetting(t *testing.T) {
	if _, ok := shadowByID(detect(v1Config), tool.ShadowCheckBlank); !ok {
		t.Fatal("check-blank absent from the config produced no shadow")
	}
	if s, ok := shadowByID(detect(v2Config), tool.ShadowCheckBlank); ok {
		t.Fatalf("a config that sets check-blank was reported as shadowing it: %+v", s)
	}
	// errcheck off entirely is the disabled-linter shadow's business, not this
	// one's; reporting both would count the same silence twice.
	offEntirely := "linters:\n  default: none\n  enable:\n    - staticcheck\n"
	if s, ok := shadowByID(detect(offEntirely), tool.ShadowCheckBlank); ok {
		t.Fatalf("check-blank was reported for a config that does not run errcheck: %+v", s)
	}
}

// TestNarrowedTestExclusionIsNotReported is the false-positive guard: an
// exclusion that also matches on message text silences some findings in test
// files, not all of them, so no exact count exists and none is claimed.
func TestNarrowedTestExclusionIsNotReported(t *testing.T) {
	src := `linters:
  enable:
    - errcheck
issues:
  exclude-rules:
    - path: _test\.go
      text: "Error return value of .Close"
      linters:
        - errcheck
`
	if s, ok := shadowByID(detect(src), tool.ShadowTestExclusion); ok {
		t.Fatalf("a narrowed exclusion was reported as a whole-file shadow: %+v", s)
	}
}

// TestConfigWithNoDetectableShadowStaysSilent is the other half of the same
// discipline. A configuration that turns nothing off and excludes nothing must
// produce no disabled-linter or exclusion entry, whatever else it contains.
func TestConfigWithNoDetectableShadowStaysSilent(t *testing.T) {
	src := `version: "2"
linters:
  settings:
    errcheck:
      check-blank: true
formatters:
  enable:
    - gofmt
`
	for _, id := range []string{tool.ShadowLintersOff, tool.ShadowTestExclusion, tool.ShadowCheckBlank} {
		if s, ok := shadowByID(detect(src), id); ok {
			t.Fatalf("a configuration with nothing to report produced %s: %+v", id, s)
		}
	}
}

// TestExclusionWithoutLinterListShadowsEverything covers the shape that silences
// the most and says the least: a test-file rule naming no linters excludes them
// all, which is exactly what the field report's subject had.
func TestExclusionWithoutLinterListShadowsEverything(t *testing.T) {
	src := `linters:
  enable:
    - errcheck
issues:
  exclude-rules:
    - path: _test\.go
`
	s, ok := shadowByID(detect(src), tool.ShadowTestExclusion)
	if !ok {
		t.Fatal("an exclusion naming no linters produced no shadow")
	}
	if len(s.Linters) != len(tool.StrictPackLinters()) {
		t.Fatalf("exclusion shadow covers %d linters, want the whole strict pack", len(s.Linters))
	}
}

// TestStrictPackDoesNotShadowItself is the sanity check on the whole comparison:
// the harness's own configuration must not read as hiding anything from the
// harness, and its one test-file exclusion has to be reported honestly.
func TestStrictPackDoesNotShadowItself(t *testing.T) {
	shadows := detect(string(tool.StrictConfig()))
	if s, ok := shadowByID(shadows, tool.ShadowLintersOff); ok {
		t.Fatalf("the strict pack reads as disabling its own linters: %+v", s)
	}
	if s, ok := shadowByID(shadows, tool.ShadowCheckBlank); ok {
		t.Fatalf("the strict pack reads as leaving check-blank off: %+v", s)
	}
	s, ok := shadowByID(shadows, tool.ShadowTestExclusion)
	if !ok {
		t.Fatal("the strict pack's own test-file exclusion went unreported")
	}
	if !slices.Contains(s.Linters, "gochecknoglobals") || slices.Contains(s.Linters, "errcheck") {
		t.Fatalf("the strict pack's test exclusion reads as %v", s.Linters)
	}
}
