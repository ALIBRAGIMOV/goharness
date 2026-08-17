package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/cli"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/leakcheck"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/report"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

func invoke(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = cli.Main(t.Context(), args, cli.Streams{Out: &out, Err: &errBuf})
	return code, out.String(), errBuf.String()
}

func TestVersionPrintsEveryPin(t *testing.T) {
	code, out, _ := invoke(t, "version")
	if code != cli.ExitAdmitted {
		t.Fatalf("exit = %d, want %d", code, cli.ExitAdmitted)
	}
	for _, want := range []string{
		cli.Version, policy.UberGuideCommit, report.SchemaID, "2.12.2",
		tool.XVulnVersion(), leakcheck.Version,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("version output is missing %q:\n%s", want, out)
		}
	}
}

func TestExplainCoversEveryRuleFamily(t *testing.T) {
	for _, id := range []string{
		policy.RuleSuppressNolint,
		policy.RuleVet,
		"GCL-errcheck",
		"UBER-ERR-001",
	} {
		t.Run(id, func(t *testing.T) {
			code, out, errOut := invoke(t, "explain", id)
			if code != cli.ExitAdmitted {
				t.Fatalf("exit = %d (%s)", code, errOut)
			}
			rule, ok := policy.Lookup(id)
			if !ok {
				t.Fatalf("%s is not in the registry", id)
			}
			for _, want := range []string{
				rule.ID, rule.Title, string(rule.Classification),
				string(rule.Lifecycle), rule.Enforcement, rule.DocURL, rule.Rationale,
			} {
				if !strings.Contains(out, want) {
					t.Fatalf("explain %s omitted %q:\n%s", id, want, out)
				}
			}
		})
	}
}

func TestExplainLinksLintersToTheGuide(t *testing.T) {
	_, out, _ := invoke(t, "explain", "GCL-errcheck")
	if !strings.Contains(out, "UBER-ERR-001") {
		t.Fatalf("explain GCL-errcheck does not mention the guide rule it enforces:\n%s", out)
	}
}

func TestExplainUnknownRuleIsInconclusive(t *testing.T) {
	code, _, errOut := invoke(t, "explain", "GH-NOPE-999")
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if !strings.Contains(errOut, "unknown rule") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestUnknownCommandIsInconclusive(t *testing.T) {
	code, _, errOut := invoke(t, "fix")
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestBaseFlagIsRejectedOutsideVerify(t *testing.T) {
	for _, mode := range []string{"fast", "audit"} {
		code, _, errOut := invoke(t, mode, "--base", "HEAD~1")
		if code != cli.ExitInconclusive {
			t.Fatalf("%s exit = %d, want %d", mode, code, cli.ExitInconclusive)
		}
		if !strings.Contains(errOut, "--base applies to `verify` only") {
			t.Fatalf("%s stderr = %q", mode, errOut)
		}
	}
}

func TestVerifyOutsideAModuleIsInconclusive(t *testing.T) {
	dir := t.TempDir()
	code, _, errOut := invoke(t, "verify", "--dir", dir)
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if !strings.Contains(errOut, "go.mod") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestDoctorReportsEnvironment(t *testing.T) {
	root, ok := repoRoot()
	if !ok {
		t.Skip("could not locate the goharness module root")
	}
	code, out, errOut := invoke(t, "doctor", "--dir", root)
	if code != cli.ExitAdmitted {
		t.Fatalf("doctor exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, want := range []string{"go toolchain", "git ", "module ", "golangci-lint", "worktrees", policy.UberGuideCommit} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output is missing %q:\n%s", want, out)
		}
	}
}

// TestDoctorReportsAnUntrustedLinterAsAProblem covers the machine where the
// only golangci-lint in reach is not the pinned release. Doctor must call that
// a problem and name the command that fixes it, because a run there cannot
// produce lint evidence at all.
func TestDoctorReportsAnUntrustedLinterAsAProblem(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/doctor\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	script := filepath.Join(t.TempDir(), "old-golangci-lint")
	body := "#!/bin/sh\necho 'golangci-lint has version 1.64.8 built with go1.22.0'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing fake linter: %v", err)
	}
	t.Setenv(toolcache.EnvCacheRoot, t.TempDir())
	t.Setenv(tool.GolangciLintEnvVar, script)

	code, out, _ := invoke(t, "doctor", "--dir", dir)
	if code != cli.ExitInconclusive {
		t.Fatalf("doctor exit = %d, want %d\n%s", code, cli.ExitInconclusive, out)
	}
	if !strings.Contains(out, "[FAIL]") || !strings.Contains(out, tool.GolangciLintPin) {
		t.Fatalf("doctor did not report the untrusted linter:\n%s", out)
	}
	if !strings.Contains(out, "fix: ") {
		t.Fatalf("doctor did not offer a remediation command:\n%s", out)
	}
}

// TestEveryCommandLeavesTheWorktreeUnchanged is the read-only guarantee checked
// at the level a user actually invokes. Verification modes run against a
// throwaway fixture: pointing them at this repository would make the harness
// run its own test suite, which runs the harness again.
func TestEveryCommandLeavesTheWorktreeUnchanged(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	commands := [][]string{
		{"version"},
		{"explain", "GH-SUPPRESS-001"},
		{"doctor", "--dir", dir},
		{"fast", "--dir", dir},
		{"verify", "--dir", dir},
		{"audit", "--dir", dir},
	}
	for _, args := range commands {
		before := porcelain(t, dir)
		invoke(t, args...)
		after := porcelain(t, dir)
		if before != after {
			t.Fatalf("goharness %s changed the worktree:\nbefore:\n%s\nafter:\n%s",
				strings.Join(args, " "), before, after)
		}
	}
}

func TestVerdictsMapOntoExitCodes(t *testing.T) {
	useGolangci(t)
	clean := newFixtureRepo(t)
	if code, out, errOut := invoke(t, "fast", "--dir", clean); code != cli.ExitAdmitted {
		t.Fatalf("clean fixture exit = %d, want %d\n%s%s", code, cli.ExitAdmitted, out, errOut)
	}

	rejected := newFixtureRepo(t)
	writeFile(t, filepath.Join(rejected, "lib", "lib.go"), suppressedSource)
	if code, out, errOut := invoke(t, "fast", "--dir", rejected); code != cli.ExitRejected {
		t.Fatalf("suppressed fixture exit = %d, want %d\n%s%s", code, cli.ExitRejected, out, errOut)
	}
}

func TestJSONOutputIsValidAndSchemaTagged(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, out, errOut := invoke(t, "fast", "--dir", dir, "--json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON (%v)\nstdout:\n%s\nstderr:\n%s", err, out, errOut)
	}
	if doc["schema"] != report.SchemaID {
		t.Fatalf("schema = %v, want %s", doc["schema"], report.SchemaID)
	}
	if doc["verdict"] == nil || doc["versions"] == nil {
		t.Fatalf("report is missing top-level fields: %v", doc)
	}
}

const (
	fixtureSource = `package lib

// Answer returns a constant the fixture test observes.
func Answer() int {
	return 42
}
`

	fixtureTestSource = `package lib

import "testing"

func TestAnswer(t *testing.T) {
	if got := Answer(); got != 42 {
		t.Fatalf("Answer() = %d, want 42", got)
	}
}
`

	suppressedSource = `package lib

// Answer returns a constant the fixture test observes.
func Answer() int {
	//nolint:errcheck
	return 42
}
`
)

// newFixtureRepo builds a committed one-package module in a temporary git
// repository so CLI behaviour can be exercised without touching this checkout.
func newFixtureRepo(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/clifixture\n\ngo 1.26\n")
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), fixtureSource)
	writeFile(t, filepath.Join(dir, "lib", "lib_test.go"), fixtureTestSource)
	git(t, dir, "init", "--initial-branch=main")
	git(t, dir, "config", "user.email", "harness@example.invalid")
	git(t, dir, "config", "user.name", "goharness fixture")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "--no-gpg-sign", "-m", "fixture baseline")
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=goharness fixture",
		"GIT_AUTHOR_EMAIL=harness@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
		"GIT_COMMITTER_NAME=goharness fixture",
		"GIT_COMMITTER_EMAIL=harness@example.invalid",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func useGolangci(t *testing.T) {
	t.Helper()
	root, ok := repoRoot()
	if !ok {
		t.Skip("could not locate the goharness module root")
	}
	path := filepath.Join(root, ".tools", "golangci-lint")
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		t.Skip("pinned golangci-lint not found at .tools/golangci-lint")
	}
	t.Setenv("GOHARNESS_GOLANGCI_LINT", path)
}

func repoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			if _, toolErr := os.Stat(filepath.Join(dir, ".tools")); toolErr == nil {
				return dir, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func porcelain(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "status", "--porcelain", "--untracked-files=all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git status in %s: %v", dir, err)
	}
	return string(out)
}

func TestUnknownCommandSuggestsTheNearestName(t *testing.T) {
	code, _, errOut := invoke(t, "verfiy")
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if !strings.Contains(errOut, "did you mean: verify") {
		t.Fatalf("no suggestion offered:\n%s", errOut)
	}
	if !strings.Contains(errOut, "try: goharness verify") {
		t.Fatalf("the error does not say what to type:\n%s", errOut)
	}
}

func TestUnknownRuleSuggestsTheNearestID(t *testing.T) {
	_, _, errOut := invoke(t, "explain", "GH-SUPRESS-001")
	if !strings.Contains(errOut, "did you mean") {
		t.Fatalf("no rule suggestion offered:\n%s", errOut)
	}
}

func TestNoArgumentsPrintsStructuredHelp(t *testing.T) {
	code, _, errOut := invoke(t)
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{
		"Commands", "Exit codes", "0   ADMITTED", "1   REJECTED",
		"2   INCONCLUSIVE", "130 aborted", "Examples",
		"goharness verify --agent",
	} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("help is missing %q:\n%s", want, errOut)
		}
	}
}

func TestEveryCommandHasHelp(t *testing.T) {
	for _, command := range []string{"verify", "audit", "fast", "deep", "explain", "doctor", "version"} {
		t.Run(command, func(t *testing.T) {
			code, out, _ := invoke(t, command, "-h")
			if code != cli.ExitAdmitted {
				t.Fatalf("exit = %d", code)
			}
			if !strings.Contains(out, "usage: goharness "+command) &&
				!strings.Contains(out, "usage: goharness audit") {
				t.Fatalf("%s -h has no usage line:\n%s", command, out)
			}
		})
	}
}

func TestDeepPrintsADeprecationNote(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, _, errOut := invoke(t, "deep", "--dir", dir)
	if !strings.Contains(errOut, "deprecated") || !strings.Contains(errOut, "goharness audit") {
		t.Fatalf("deep did not announce its deprecation:\n%s", errOut)
	}
}

// TestAgentModeSplitsTheStreams is the agent protocol: stdout is exactly the
// JSON document so it can be piped into a parser, and the human text goes to
// stderr.
func TestAgentModeSplitsTheStreams(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	code, out, errOut := invoke(t, "verify", "--agent", "--dir", dir)
	if code != cli.ExitAdmitted {
		t.Fatalf("exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	var doc struct {
		Schema                  string `json:"schema"`
		Verdict                 string `json:"verdict"`
		SufficientForCompletion bool   `json:"sufficientForCompletion"`
		Claims                  []struct {
			Dimension string `json:"dimension"`
		} `json:"claims"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not exactly one JSON document (%v):\n%s", err, out)
	}
	if doc.Schema != report.SchemaID || doc.Verdict != "ADMITTED" {
		t.Fatalf("document = %+v", doc)
	}
	if !doc.SufficientForCompletion {
		t.Fatal("an ADMITTED verify is not sufficient for completion")
	}
	if len(doc.Claims) == 0 {
		t.Fatal("the agent document carries no claim table")
	}
	if !strings.Contains(errOut, "ADMITTED") {
		t.Fatalf("the human report did not go to stderr:\n%s", errOut)
	}
}

func TestFastJSONIsNeverSufficientForCompletion(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, out, _ := invoke(t, "fast", "--dir", dir, "--json")
	var doc struct {
		AdmissionGate           bool `json:"admissionGate"`
		SufficientForCompletion bool `json:"sufficientForCompletion"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.SufficientForCompletion || doc.AdmissionGate {
		t.Fatalf("fast presented itself as a gate: %+v", doc)
	}
}

func TestAgentJSONIsDeterministicAcrossRuns(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	strip := func(raw string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, raw)
		}
		delete(doc, "timing")
		encoded, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatalf("re-encoding: %v", err)
		}
		return string(encoded)
	}
	_, first, _ := invoke(t, "verify", "--agent", "--dir", dir)
	_, second, _ := invoke(t, "verify", "--agent", "--dir", dir)
	if strip(first) != strip(second) {
		t.Fatalf("two agent runs differ outside the timing block:\n%s\n---\n%s",
			strip(first), strip(second))
	}
}

func TestExplainPlanPrintsObligationsWithoutRunningChecks(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	code, out, errOut := invoke(t, "verify", "--dir", dir, "--explain-plan")
	if code != cli.ExitAdmitted {
		t.Fatalf("exit = %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"obligations", "compile-clean", "claim=correctness", "checks:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan output is missing %q:\n%s", want, out)
		}
	}
}

func TestNoColorEnvironmentDisablesColour(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, out, _ := invoke(t, "fast", "--dir", dir)
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("NO_COLOR was ignored:\n%q", out)
	}
}

func TestQuietReducesOutputToTheVerdict(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, out, _ := invoke(t, "fast", "--dir", dir, "--quiet")
	if lines := strings.Count(strings.TrimSpace(out), "\n"); lines != 0 {
		t.Fatalf("--quiet printed %d extra lines:\n%s", lines, out)
	}
}

func TestVerboseFlagsEmitDiagnosticsOnStderrOnly(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, out, errOut := invoke(t, "fast", "--dir", dir, "-v", "--log-json")
	if strings.Contains(out, "check started") {
		t.Fatalf("diagnostics leaked into stdout:\n%s", out)
	}
	if !strings.Contains(errOut, "check started") {
		t.Fatalf("-v produced no INFO diagnostics on stderr:\n%s", errOut)
	}
	if !strings.Contains(errOut, `"check":`) {
		t.Fatalf("--log-json did not switch the encoder:\n%s", errOut)
	}
}

func TestQuietRunEmitsNoLogsByDefault(t *testing.T) {
	useGolangci(t)
	dir := newFixtureRepo(t)
	_, _, errOut := invoke(t, "fast", "--dir", dir)
	if strings.Contains(errOut, "check started") {
		t.Fatalf("INFO diagnostics appeared without -v:\n%s", errOut)
	}
}

func TestHelpTopicMatchesCommandFlag(t *testing.T) {
	for _, command := range []string{"verify", "audit", "fast", "setup", "tools", "explain", "doctor", "help"} {
		t.Run(command, func(t *testing.T) {
			code, viaTopic, _ := invoke(t, "help", command)
			if code != cli.ExitAdmitted {
				t.Fatalf("help %s exit = %d", command, code)
			}
			if !strings.Contains(viaTopic, "usage: goharness "+command) {
				t.Fatalf("help %s has no usage line:\n%s", command, viaTopic)
			}
			if !strings.Contains(viaTopic, "Examples") {
				t.Fatalf("help %s carries no examples:\n%s", command, viaTopic)
			}
			if command == "tools" {
				return
			}
			_, viaFlag, _ := invoke(t, command, "-h")
			if viaFlag != viaTopic {
				t.Fatalf("help %s and %s -h differ:\n%s\n---\n%s",
					command, command, viaTopic, viaFlag)
			}
		})
	}
}

func TestHelpWithNoTopicPrintsGlobalUsage(t *testing.T) {
	code, out, _ := invoke(t, "help")
	if code != cli.ExitAdmitted {
		t.Fatalf("help exit = %d", code)
	}
	if !strings.Contains(out, "Commands") || !strings.Contains(out, "Exit codes") {
		t.Fatalf("bare help is not the global usage:\n%s", out)
	}
}

func TestHelpUnknownTopicSuggests(t *testing.T) {
	code, _, errOut := invoke(t, "help", "verfiy")
	if code != cli.ExitInconclusive {
		t.Fatalf("exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if !strings.Contains(errOut, "did you mean: verify") {
		t.Fatalf("no suggestion offered:\n%s", errOut)
	}
	if !strings.Contains(errOut, "try: goharness help verify") {
		t.Fatalf("the error does not say what to type:\n%s", errOut)
	}
}

// TestGlobalHelpIsSelfSufficientForAnAgent checks that an agent that has never
// seen goharness can learn the protocol from one screen.
func TestGlobalHelpIsSelfSufficientForAnAgent(t *testing.T) {
	code, stdout, text := invoke(t)
	if code != cli.ExitInconclusive {
		t.Fatalf("bare goharness exit = %d, want %d", code, cli.ExitInconclusive)
	}
	if stdout != "" {
		t.Fatalf("usage went to stdout, where --agent puts the report:\n%s", stdout)
	}
	for _, want := range []string{
		"Agent protocol",
		"goharness verify --agent",
		"goharness.report/v2",
		"sufficientForCompletion",
		"FAIL",
		"INCONCLUSIVE",
		"goharness explain RULE-ID",
		"never sufficient",
		"goharness setup",
		"never installs anything",
		"setup", "tools update", "help",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("global help is missing %q:\n%s", want, text)
		}
	}
	// The budget is one and a half terminal screens rather than one. The block
	// that grew past a screenful is the agent protocol's field map, and an
	// agent that reads it needs no second command to parse the report.
	if lines := strings.Count(text, "\n"); lines > 80 {
		t.Fatalf("global help is %d lines; keep it near a screenful", lines)
	}
}

// jsonKeys marshals a value and returns the field names it actually emits.
func jsonKeys(t *testing.T, value any) map[string]bool {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshalling %T: %v", value, err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decoding %T: %v", value, err)
	}
	keys := make(map[string]bool, len(decoded))
	for key := range decoded {
		keys[key] = true
	}
	return keys
}

// TestAgentProtocolNamesFieldsTheReportHas keeps the help honest about the
// document it tells an agent to parse.
//
// The protocol block is the only instruction some agents will ever read, and a
// field name that drifted from the report sends them looking for a key that is
// not there. This test caught exactly that: the help said
// sufficient_for_completion while the report has emitted sufficientForCompletion
// since the schema was written.
func TestAgentProtocolNamesFieldsTheReportHas(t *testing.T) {
	_, _, help := invoke(t)
	document := jsonKeys(t, report.Build(cli.Version, verify.Result{}))
	claim := jsonKeys(t, admission.QualityClaim{})
	finding := jsonKeys(t, report.Finding{
		Evidence: evidence.Evidence{Fix: &evidence.Remediation{Command: "gofmt -w a.go"}},
	})
	remediation := jsonKeys(t, evidence.Remediation{})
	unproducible := jsonKeys(t, report.Unproducible{Remedy: "run goharness setup"})

	for _, c := range []struct {
		named string
		keys  map[string]bool
		key   string
	}{
		{"sufficientForCompletion", document, "sufficientForCompletion"},
		{"claims[].state", claim, "state"},
		{"claims[].missingEvidence", claim, "missingEvidence"},
		{"unproducible[]", document, "unproducible"},
		{".remedy", unproducible, "remedy"},
		{"evidence[].blocking", finding, "blocking"},
		{"evidence[].fix.command", finding, "fix"},
		{"evidence[].fix.command", remediation, "command"},
		{"failures[]", document, "failures"},
		{".hint", jsonKeys(t, verify.CheckFailure{Hint: "run goharness setup"}), "hint"},
	} {
		if !strings.Contains(help, c.named) {
			t.Errorf("the agent protocol no longer names %s", c.named)
		}
		if !c.keys[c.key] {
			t.Errorf("the help names %s, but no %q field is emitted there", c.named, c.key)
		}
	}
}

// TestDocumentedFlagsAreAccepted feeds every flag a usage line advertises back
// to the command that printed it.
//
// Help that names a flag its own command rejects turns the documentation into
// an error message, which is worse than saying nothing: a reader who trusts it
// loses the run. The commands run against a directory that is not a module, so
// each one stops immediately after parsing.
func TestDocumentedFlagsAreAccepted(t *testing.T) {
	dir := t.TempDir()
	for _, command := range []string{"verify", "audit", "fast", "deep", "doctor"} {
		t.Run(command, func(t *testing.T) {
			_, help, _ := invoke(t, "help", command)
			args := append([]string{command}, documentedFlags(t, help, dir)...)
			_, _, errOut := invoke(t, args...)
			if strings.Contains(errOut, "not defined") {
				t.Fatalf("goharness %s rejects a flag its own help documents:\n%s",
					strings.Join(args, " "), errOut)
			}
		})
	}
}

// documentedFlags reads the flags out of a usage line, with a usable value for
// the ones that take an argument.
func documentedFlags(t *testing.T, help, dir string) []string {
	t.Helper()
	usage, _, _ := strings.Cut(help, "\n\n")
	pattern := regexp.MustCompile(`\[(-{1,2}[a-z|-]+)(?: ([A-Z][A-Z-]*))?\]`)
	var args []string
	for _, match := range pattern.FindAllStringSubmatch(usage, -1) {
		for flag := range strings.SplitSeq(match[1], "|") {
			args = append(args, flag)
			if match[2] != "" {
				args = append(args, flagValue(t, match[2], dir))
			}
		}
	}
	return args
}

// flagValue supplies an argument for one usage placeholder. An unknown
// placeholder fails rather than being skipped: a flag nobody exercises is how
// the drift this test exists to catch gets back in.
func flagValue(t *testing.T, placeholder, dir string) string {
	t.Helper()
	switch placeholder {
	case "DIR":
		return dir
	case "REV":
		return "HEAD"
	case "FILE":
		return filepath.Join(dir, "task.yaml")
	case "D", "DURATION":
		return "1s"
	default:
		t.Fatalf("no test value for the usage placeholder %q", placeholder)
		return ""
	}
}

// TestContractHelpSampleParses keeps the documented file format loadable. An
// agent copies the sample it is shown, and a sample the parser rejects teaches
// a syntax the harness does not accept.
func TestContractHelpSampleParses(t *testing.T) {
	_, help, _ := invoke(t, "help", "contract")
	sample := indentedSample(t, help, "  goal:")
	contract, err := admission.ParseContract([]byte(sample), admission.ContractFromFile)
	if err != nil {
		t.Fatalf("the contract sample in help does not parse: %v\n%s", err, sample)
	}
	if contract.Goal == "" || !contract.HasScope() || len(contract.Budgets) == 0 {
		t.Fatalf("the sample parsed into an empty contract: %+v", contract)
	}
}

// indentedSample lifts the indented block that starts at the first line with
// the given prefix out of a help topic, dedented by two spaces.
func indentedSample(t *testing.T, help, start string) string {
	t.Helper()
	_, rest, found := strings.Cut(help, start)
	if !found {
		t.Fatalf("no sample starting with %q in:\n%s", start, help)
	}
	var lines []string
	for line := range strings.SplitSeq(strings.TrimPrefix(start, "  ")+rest, "\n") {
		if strings.TrimSpace(line) == "" {
			break
		}
		lines = append(lines, strings.TrimPrefix(line, "  "))
	}
	return strings.Join(lines, "\n") + "\n"
}
