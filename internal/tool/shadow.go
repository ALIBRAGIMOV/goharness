package tool

import (
	"slices"
	"strconv"
	"strings"
)

// GolangciConfigNames lists the configuration file names golangci-lint reads at
// a module root, in its own resolution order.
func GolangciConfigNames() []string {
	return []string{".golangci.yml", ".golangci.yaml", ".golangci.json", ".golangci.toml"}
}

// IsYAMLConfigName reports whether a configuration file is one of the two forms
// the shadow scan can read. The JSON and TOML forms are declared unanalysed
// rather than guessed at.
func IsYAMLConfigName(name string) bool {
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

// Shadow identifiers.
const (
	// ShadowLintersOff covers linters the strict pack requires and the local
	// configuration turns off, by an explicit disable or by defaulting off.
	ShadowLintersOff = "linters-disabled"
	// ShadowTestExclusion covers an exclusion rule aimed at test files.
	ShadowTestExclusion = "test-file-exclusion"
	// ShadowCheckBlank covers errcheck running without check-blank, which makes
	// an explicit `_ =` discard legal.
	ShadowCheckBlank = "errcheck-check-blank"
)

// Shadow is one mechanism by which a repository's own lint configuration hides
// findings the strict pack reports. It is an observation about configuration,
// never a defect in code: nothing here reaches a verdict.
type Shadow struct {
	ID        string
	Mechanism string
	Detail    string
	Linters   []string
}

// StrictPackLinters lists the linters the embedded strict configuration
// enables, read from that configuration so the two can never disagree.
func StrictPackLinters() []string {
	cfg := parseGolangciShape(StrictConfig())
	return slices.Sorted(slices.Values(cfg.enabled))
}

// DetectGolangciShadows reports the shadows a repository's golangci-lint
// configuration casts over the strict pack.
//
// The scan is line-based and deliberately incomplete. A .golangci.yml in the
// wild is arbitrary YAML with several equivalent spellings across the v1 and v2
// layouts, and a shadow reported on a guess would be worse than no section at
// all: it would put a number in front of an operator that their own file does
// not support. Only positively recognised shapes are reported, so silence here
// means "not detected", never "not present".
func DetectGolangciShadows(src []byte, strict []string) []Shadow {
	cfg := parseGolangciShape(src)
	var out []Shadow
	if s, ok := disabledShadow(cfg, strict); ok {
		out = append(out, s)
	}
	if s, ok := testExclusionShadow(cfg, strict); ok {
		out = append(out, s)
	}
	if s, ok := checkBlankShadow(cfg, strict); ok {
		out = append(out, s)
	}
	return out
}

// golangciShape is the handful of facts the scan extracts. Everything else in
// the file is deliberately not modelled.
type golangciShape struct {
	sawLinters bool
	defaultOff bool
	enabled    []string
	disabled   []string
	// checkBlankOn records that errcheck's check-blank was positively set true.
	checkBlankOn bool
	// testExclusions are the exclusion rules aimed at test files, each with the
	// linters it silences; an empty list means the rule silences all of them.
	testExclusions []testExclusion
}

type testExclusion struct {
	pattern string
	linters []string
	all     bool
}

// cfgLine is one significant line: its indentation, its content, and whether it
// opens a list item.
type cfgLine struct {
	indent int
	text   string
	item   bool
}

func scanLines(src []byte) []cfgLine {
	var out []cfgLine
	for raw := range strings.SplitSeq(string(src), "\n") {
		line := strings.TrimRight(raw, "\r")
		body := strings.TrimSpace(line)
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		out = append(out, cfgLine{
			indent: len(line) - len(strings.TrimLeft(line, " \t")),
			text:   body,
			item:   strings.HasPrefix(body, "- "),
		})
	}
	return out
}

func parseGolangciShape(src []byte) golangciShape {
	lines := scanLines(src)
	var shape golangciShape
	for i, line := range lines {
		key, value, isPair := cutKey(line.text)
		if !isPair {
			continue
		}
		switch {
		case line.indent == 0 && key == "linters":
			shape.sawLinters = true
		case key == "disable-all" && value == "true":
			shape.defaultOff = true
		case key == "default" && value == "none":
			shape.defaultOff = true
		case key == "enable":
			shape.enabled = append(shape.enabled, listAt(lines, i)...)
		case key == "disable":
			shape.disabled = append(shape.disabled, listAt(lines, i)...)
		case key == "check-blank" && value == "true":
			shape.checkBlankOn = true
		}
	}
	shape.testExclusions = scanTestExclusions(lines)
	return shape
}

// cutKey splits "key: value", rejecting a list item and anything without a
// colon. The value is unquoted where it is a quoted scalar, which is how a
// regexp path is usually written.
func cutKey(text string) (key, value string, ok bool) {
	if after, cut := strings.CutPrefix(text, "- "); cut {
		text = after
	}
	key, value, ok = strings.Cut(text, ":")
	if !ok {
		return "", "", false
	}
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}
	return key, value, true
}

// listAt reads the list a key introduces, in either the block form beneath it or
// the flow form on the same line.
func listAt(lines []cfgLine, at int) []string {
	_, value, _ := cutKey(lines[at].text)
	if strings.HasPrefix(value, "[") {
		return flowList(value)
	}
	var out []string
	for _, line := range lines[at+1:] {
		if line.indent <= lines[at].indent {
			break
		}
		if !line.item {
			continue
		}
		if name := strings.TrimSpace(strings.TrimPrefix(line.text, "- ")); name != "" {
			out = append(out, unquote(name))
		}
	}
	return out
}

func flowList(value string) []string {
	inner := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	var out []string
	for field := range strings.SplitSeq(inner, ",") {
		if name := strings.TrimSpace(field); name != "" {
			out = append(out, unquote(name))
		}
	}
	return out
}

func unquote(s string) string {
	if unquoted, err := strconv.Unquote(s); err == nil {
		return unquoted
	}
	return s
}

// scanTestExclusions finds exclusion rules aimed at test files.
//
// It matches the shape of the list item rather than the path to it, so the v1
// `issues.exclude-rules` and the v2 `linters.exclusions.rules` spellings are
// both covered without the scan having to know which layout it is reading. An
// item that also narrows by `text` or `source` is skipped: it silences some
// findings in test files rather than all of them, and this section reports only
// counts it can stand behind.
func scanTestExclusions(lines []cfgLine) []testExclusion {
	var out []testExclusion
	for i, line := range lines {
		if !line.item {
			continue
		}
		block := itemBlock(lines, i)
		path, narrowed, linters := "", false, []string{}
		hasLinters := false
		for j, inner := range block {
			key, value, ok := cutKey(inner.text)
			if !ok {
				continue
			}
			switch key {
			case "path":
				path = value
			case "text", "source", "path-except":
				narrowed = true
			case "linters":
				hasLinters = true
				linters = listAt(block, j)
			}
		}
		if narrowed || !isTestPath(path) {
			continue
		}
		out = append(out, testExclusion{pattern: path, linters: linters, all: !hasLinters})
	}
	return out
}

// itemBlock returns one list item: its own line plus every line indented under
// it, up to the next item at the same level or any dedent.
func itemBlock(lines []cfgLine, at int) []cfgLine {
	end := at + 1
	for end < len(lines) && lines[end].indent > lines[at].indent {
		end++
	}
	return lines[at:end]
}

// isTestPath recognises the exclusion patterns that name Go test files. Every
// spelling in use is a regexp over the file path containing "_test", so that
// substring is the whole test; anything else is left alone.
func isTestPath(path string) bool {
	return path != "" && strings.Contains(path, "_test")
}

func disabledShadow(cfg golangciShape, strict []string) (Shadow, bool) {
	if !cfg.sawLinters {
		return Shadow{}, false
	}
	var off []string
	for _, linter := range strict {
		switch {
		case slices.Contains(cfg.disabled, linter):
			off = append(off, linter)
		case cfg.defaultOff && !slices.Contains(cfg.enabled, linter):
			off = append(off, linter)
		}
	}
	if len(off) == 0 {
		return Shadow{}, false
	}
	slices.Sort(off)
	detail := "the enable list does not carry them"
	if !cfg.defaultOff {
		detail = "they appear in the disable list"
	}
	return Shadow{
		ID: ShadowLintersOff,
		Mechanism: "the repository's own configuration does not run these linters, " +
			"so nothing local reports what they find",
		Detail:  detail,
		Linters: off,
	}, true
}

func testExclusionShadow(cfg golangciShape, strict []string) (Shadow, bool) {
	silenced := map[string]bool{}
	var patterns []string
	for _, rule := range cfg.testExclusions {
		patterns = append(patterns, rule.pattern)
		for _, linter := range strict {
			if rule.all || slices.Contains(rule.linters, linter) {
				silenced[linter] = true
			}
		}
	}
	if len(silenced) == 0 {
		return Shadow{}, false
	}
	slices.Sort(patterns)
	return Shadow{
		ID: ShadowTestExclusion,
		Mechanism: "an exclusion rule drops these linters inside test files, so a defect " +
			"in the code that decides whether the suite is trustworthy is never reported locally",
		Detail:  "exclusion path " + strings.Join(slices.Compact(patterns), ", "),
		Linters: slices.Sorted(mapKeysOf(silenced)),
	}, true
}

func checkBlankShadow(cfg golangciShape, strict []string) (Shadow, bool) {
	const errcheck = "errcheck"
	if !slices.Contains(strict, errcheck) || cfg.checkBlankOn {
		return Shadow{}, false
	}
	if slices.Contains(cfg.disabled, errcheck) {
		return Shadow{}, false
	}
	if cfg.defaultOff && !slices.Contains(cfg.enabled, errcheck) {
		return Shadow{}, false
	}
	return Shadow{
		ID: ShadowCheckBlank,
		Mechanism: "errcheck runs without check-blank, so writing `_ =` in front of a call " +
			"discards its error legally; the strict pack checks blanks",
		Detail:  "no `check-blank: true` in this configuration, and errcheck defaults it to false",
		Linters: []string{errcheck},
	}, true
}

func mapKeysOf(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
