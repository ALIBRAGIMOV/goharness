package verify_test

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// corpusEnv gates the only test in this repository that reaches the network.
// It is off by default because a verification run must never depend on one, and
// on demand because a rule's precision is a claim about real code, not about
// fixtures written to make it fire.
const corpusEnv = "GOHARNESS_CORPUS"

// corpusRepo is one published repository pinned to the exact commit the harness
// was calibrated against, so a rule's hit count can be compared across runs.
type corpusRepo struct {
	name   string
	url    string
	commit string
	// modulePrefix is the module's directory below the repository root, empty
	// when they coincide. A very large share of real Go repositories keep their
	// module in a subdirectory, and every defect the 0.6 coordinate work closed
	// was invisible to a corpus that contained none of them.
	modulePrefix string
}

func corpusRepos() []corpusRepo {
	return []corpusRepo{
		{name: "google/uuid", url: "https://github.com/google/uuid", commit: "0f11ee6918f41a04c201eceeadf612a377bc7fbc"},
		{name: "gorilla/mux", url: "https://github.com/gorilla/mux", commit: "b4617d0b9670ad14039b2739167fd35a60f557c5"},
		{name: "sirupsen/logrus", url: "https://github.com/sirupsen/logrus", commit: "d40e25cd45ed9c6b2b66e6b97573a0413e4c23bd"},
		{name: "rs/zerolog", url: "https://github.com/rs/zerolog", commit: "116c8060e034e8d46855354d22db2acbc8df9e1e"},
		{
			name: "open-telemetry/opentelemetry-go-contrib/propagators/b3",
			url:  "https://github.com/open-telemetry/opentelemetry-go-contrib",
			// A repository of many modules, none of them at the root: the layout
			// that made ADMITTED unreachable before the coordinate systems were
			// unified.
			commit:       "89837128476902ae5334ee36aedc2b4684a6b0cb",
			modulePrefix: "propagators/b3",
		},
	}
}

// moduleDir is where the harness is pointed for this repository.
func (r corpusRepo) moduleDir(checkout string) string {
	if r.modulePrefix == "" {
		return checkout
	}
	return filepath.Join(checkout, filepath.FromSlash(r.modulePrefix))
}

// TestCorpus runs the harness against real repositories at pinned revisions and
// reports what every rule fired on.
//
// It exists because "this rule has a low false positive rate" is a claim about
// code nobody here wrote, and the only way to hold it is to look. What the run
// asserts is narrow and absolute: the harness must not fail on real code, and it
// must not touch the tree it was pointed at. The hit table it prints is the
// evidence a rule is ready to move from advisory to required, or that it is not.
func TestCorpus(t *testing.T) {
	if os.Getenv(corpusEnv) == "" {
		t.Skipf("set %s=1 to run the corpus; it clones repositories and downloads modules", corpusEnv)
	}
	useGolangci(t)
	hits := map[string]int{}
	for _, repo := range corpusRepos() {
		t.Run(repo.name, func(t *testing.T) {
			dir := checkoutCorpus(t, repo)
			// Downloading modules is allowed to rewrite go.mod and go.sum, so the
			// read-only comparison starts from the state verification actually
			// begins in, not from a pristine checkout.
			before := corpusPorcelain(t, dir)
			for _, mode := range []verify.Mode{verify.ModeAudit, verify.ModeVerify} {
				runCorpusMode(t, repo, dir, mode, before, hits)
			}
		})
	}
	for _, rule := range slices.Sorted(maps.Keys(hits)) {
		t.Logf("rule %-24s %d hit(s) across the corpus", rule, hits[rule])
	}
}

// runCorpusMode exercises one mode against one repository. Audit is what
// calibrates a rule, because it judges the whole codebase with every risk domain
// active; verify exercises the diff path over the revisions leading to the pin.
func runCorpusMode(
	t *testing.T, repo corpusRepo, dir string, mode verify.Mode, before string, hits map[string]int,
) {
	t.Helper()
	// Dir names the module, which in a multi-module repository is not the
	// checkout root; the porcelain guard still watches the whole checkout,
	// because a run must leave every part of the tree alone.
	options := verify.Options{Mode: mode, Dir: repo.moduleDir(dir)}
	if mode == verify.ModeVerify {
		options.Base = repo.commit + "~5"
	}
	started := time.Now()
	result, err := verify.Run(t.Context(), "corpus", options)
	if err != nil {
		t.Fatalf("the harness failed on %s in %s mode: %v", repo.name, mode, err)
	}
	if after := corpusPorcelain(t, dir); after != before {
		t.Fatalf("%s mode modified %s:\nbefore:\n%s\nafter:\n%s", mode, repo.name, before, after)
	}
	if mode == verify.ModeAudit {
		for _, e := range result.Evidence {
			hits[e.RuleID]++
		}
	}
	t.Logf("%s %s: %s in %s, %d evidence, %d failure(s), %d unproducible",
		repo.name, mode, result.Decision.Verdict, time.Since(started).Round(time.Second),
		len(result.Evidence), len(result.Failures), len(result.Unproducible))
	for _, failure := range result.Failures {
		t.Logf("  check %s failed: %s", failure.CheckID, firstCorpusLine(failure.Reason))
	}
	for _, u := range result.Unproducible {
		t.Logf("  unproducible %s: %s", u.Kind, firstCorpusLine(u.Reason))
	}
	logBlockingEvidence(t, result.Evidence)
}

func logBlockingEvidence(t *testing.T, items []evidence.Evidence) {
	t.Helper()
	for _, e := range items {
		if !verify.Blocking(e) {
			continue
		}
		t.Logf("  blocking %s %s:%d %s", e.RuleID, e.File, e.Line, firstCorpusLine(e.Message))
	}
}

func checkoutCorpus(t *testing.T, repo corpusRepo) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), filepath.Base(repo.url))
	runCorpusCommand(t, "", "git", "clone", "--quiet", repo.url, dir)
	runCorpusCommand(t, dir, "git", "checkout", "--quiet", repo.commit)
	runCorpusCommand(t, repo.moduleDir(dir), "go", "mod", "download", "all")
	return dir
}

func runCorpusCommand(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func corpusPorcelain(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "status", "--porcelain", "--untracked-files=all")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git status in %s: %v\n%s", dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func firstCorpusLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 120 {
		return line[:120]
	}
	return line
}
