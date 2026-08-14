package tool

import (
	"context"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

type stubRunner struct {
	result Result
	err    error
	last   Command
}

func (s *stubRunner) Run(_ context.Context, cmd Command) (Result, error) {
	s.last = cmd
	return s.result, s.err
}

func TestParseGolangciVersion(t *testing.T) {
	cases := map[string]string{
		"golangci-lint has version 2.12.2 built with go1.26.4 from (unknown)": "2.12.2",
		"golangci-lint has version v2.12.2 built with go1.26.4":               "2.12.2",
		"golangci-lint has version 1.64.8":                                    "1.64.8",
		"nothing useful here":                                                 "",
	}
	for in, want := range cases {
		if got := parseGolangciVersion(in); got != want {
			t.Errorf("parseGolangciVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveVersionRejectsNonZeroExit(t *testing.T) {
	runner := &stubRunner{result: Result{ExitCode: 3, Stderr: "boom"}}
	if _, err := (Golangci{Path: "x"}).ResolveVersion(t.Context(), runner); err == nil {
		t.Fatal("a failing --version was accepted")
	}
}

func TestMatchesPin(t *testing.T) {
	if !(Golangci{Version: GolangciLintPin}).MatchesPin() {
		t.Fatal("the pinned version does not match itself")
	}
	if (Golangci{Version: "2.12.1"}).MatchesPin() {
		t.Fatal("a different version matched the pin")
	}
}

func TestRunGolangciTreatsExitOneAsFindings(t *testing.T) {
	runner := &stubRunner{result: Result{
		ExitCode: 1,
		Stdout:   `{"Issues":[{"FromLinter":"errcheck","Text":"boom","Pos":{"Filename":"a.go","Line":3,"Column":4}}]}`,
	}}
	issues, err := RunGolangci(t.Context(), runner, Golangci{Path: "x", Version: GolangciLintPin}, ".", "cfg", []string{"./..."})
	if err != nil {
		t.Fatalf("RunGolangci: %v", err)
	}
	if len(issues) != 1 || issues[0].FromLinter != "errcheck" || issues[0].Pos.Line != 3 {
		t.Fatalf("issues = %+v", issues)
	}
}

func TestRunGolangciTreatsOtherExitCodesAsToolFailures(t *testing.T) {
	runner := &stubRunner{result: Result{ExitCode: 3, Stderr: "internal error"}}
	if _, err := RunGolangci(t.Context(), runner, Golangci{Path: "x"}, ".", "cfg", []string{"./..."}); err == nil {
		t.Fatal("exit code 3 was not reported as a tool failure")
	}
}

func TestParseVetJSON(t *testing.T) {
	stream := `{
  "example.com/x": {
    "printf": [
      {"posn": "/tmp/x/b.go:6:14", "message": "wrong type"}
    ]
  }
}`
	diags, err := parseVetJSON(stream)
	if err != nil {
		t.Fatalf("parseVetJSON: %v", err)
	}
	if len(diags) != 1 {
		t.Fatalf("diags = %+v", diags)
	}
	got := diags[0]
	if got.Package != "example.com/x" || got.Analyzer != "printf" ||
		got.File != "/tmp/x/b.go" || got.Line != 6 || got.Column != 14 {
		t.Fatalf("diagnostic = %+v", got)
	}
}

func TestParseTestJSONKeepsOnlyLeafFailures(t *testing.T) {
	stream := strings.Join([]string{
		`{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:9: got 1 want 2\n"}`,
		`{"Action":"fail","Package":"p","Test":"TestA"}`,
		`{"Action":"fail","Package":"p"}`,
		`{"Action":"fail","Package":"q"}`,
	}, "\n")
	failures, err := parseTestJSON(stream)
	if err != nil {
		t.Fatalf("parseTestJSON: %v", err)
	}
	if len(failures) != 2 {
		t.Fatalf("failures = %+v, want the named failure plus the package with no named failure", failures)
	}
	if failures[0].Test != "TestA" || !strings.Contains(failures[0].Output, "got 1 want 2") {
		t.Fatalf("first failure = %+v", failures[0])
	}
	if failures[1].Package != "q" || failures[1].Test != "" {
		t.Fatalf("second failure = %+v", failures[1])
	}
}

func TestSplitPosition(t *testing.T) {
	file, line, col := splitPosition("/a/b.go:12:34")
	if file != "/a/b.go" || line != 12 || col != 34 {
		t.Fatalf("got %q %d %d", file, line, col)
	}
	if file, line, col := splitPosition("plain.go"); file != "plain.go" || line != 0 || col != 0 {
		t.Fatalf("got %q %d %d", file, line, col)
	}
}

func TestStrictConfigIsIndependentPerCall(t *testing.T) {
	first := StrictConfig()
	if len(first) == 0 {
		t.Fatal("embedded config is empty")
	}
	first[0] = 'X'
	if StrictConfig()[0] == 'X' {
		t.Fatal("StrictConfig handed out a mutable view of the embedded bytes")
	}
}

func TestExecRunnerReportsExitCodeWithoutError(t *testing.T) {
	res, err := ExecRunner{}.Run(t.Context(), Command{Name: "sh", Args: []string{"-c", "echo hi; exit 7"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 7 || strings.TrimSpace(res.Stdout) != "hi" {
		t.Fatalf("result = %+v", res)
	}
}

func TestExecRunnerReportsStartFailureAsError(t *testing.T) {
	if _, err := (ExecRunner{}).Run(t.Context(), Command{Name: "goharness-no-such-binary"}); err == nil {
		t.Fatal("a missing executable was not reported as an error")
	}
}

// TestDiscoveryFallsThroughACorruptCacheEntry documents the chosen behaviour:
// a cached binary whose hash no longer matches its manifest is never executed,
// discovery continues to PATH, and the reason travels with the result so the
// corruption is visible rather than silent. The version pin still applies to
// whatever is found next, so falling through can never trust a wrong binary.
func TestDiscoveryFallsThroughACorruptCacheEntry(t *testing.T) {
	root := t.TempDir()
	t.Setenv(GolangciLintEnvVar, "")
	t.Setenv(toolcache.EnvCacheRoot, root)

	cache := toolcache.OpenAt(root)
	binary := []byte("cached linter")
	blob, err := cache.WriteBlob(binary, 0o700)
	if err != nil {
		t.Fatalf("seeding the blob: %v", err)
	}
	manifest := toolcache.ToolManifest{
		Tool: toolcache.ToolGolangci, Version: GolangciLintPin,
		Platform: toolcache.CurrentPlatform(),
		// A binary hash the payload does not match, as if something rewrote it.
		BinarySHA256: strings.Repeat("0", 64), Blob: blob,
	}
	if err := cache.WriteToolManifest(manifest); err != nil {
		t.Fatalf("seeding the manifest: %v", err)
	}

	discovered, err := DiscoverGolangci(t.TempDir())
	if discovered.Source == "goharness cache" {
		t.Fatal("a corrupt cache entry was selected for execution")
	}
	if err == nil && discovered.Note == "" {
		t.Fatalf("discovery fell through silently: %+v", discovered)
	}
	note := discovered.Note
	if err != nil {
		note = err.Error()
	}
	if !strings.Contains(note, "does not match its manifest checksum") {
		t.Fatalf("the rejection reason is not surfaced: %q", note)
	}
}

func TestDiscoveryPrefersTheVerifiedCacheEntry(t *testing.T) {
	root := t.TempDir()
	t.Setenv(GolangciLintEnvVar, "")
	t.Setenv(toolcache.EnvCacheRoot, root)

	cache := toolcache.OpenAt(root)
	blob, err := cache.WriteBlob([]byte("cached linter"), 0o700)
	if err != nil {
		t.Fatalf("seeding the blob: %v", err)
	}
	if err := cache.WriteToolManifest(toolcache.ToolManifest{
		Tool: toolcache.ToolGolangci, Version: GolangciLintPin,
		Platform: toolcache.CurrentPlatform(), BinarySHA256: blob, Blob: blob,
	}); err != nil {
		t.Fatalf("seeding the manifest: %v", err)
	}
	discovered, err := DiscoverGolangci(t.TempDir())
	if err != nil {
		t.Fatalf("DiscoverGolangci: %v", err)
	}
	if discovered.Source != "goharness cache" {
		t.Fatalf("source = %q, want the cache", discovered.Source)
	}
	if discovered.Note != "" {
		t.Fatalf("a healthy cache entry produced a note: %q", discovered.Note)
	}
}
