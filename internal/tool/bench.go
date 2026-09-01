package tool

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Benchmark sampling is bounded by time rather than by iteration count.
//
// A fixed count cannot serve both ends of the range: two hundred iterations of
// a hundred-nanosecond operation is twenty microseconds of measurement, which
// is noise wearing a number, while two hundred iterations of a one-second
// operation is three minutes. Letting the go command choose the count for a
// short, fixed slice of time gives every benchmark enough repetitions to say
// something and none of them an unbounded bill. Both revisions get the same
// budget, and the comparison reads medians and ranges, not totals.
const (
	BenchTime = "100ms"
	// BenchSamples is how many measurements each side of a comparison gets.
	BenchSamples = 3
)

// BenchSample is one measurement of one benchmark.
type BenchSample struct {
	NsPerOp     float64
	BytesPerOp  float64
	AllocsPerOp float64
}

// BenchResult aggregates the samples of one benchmark.
type BenchResult struct {
	Name    string
	Samples []BenchSample
}

// MedianNs returns the median time per operation.
func (r BenchResult) MedianNs() float64 {
	return median(r.Samples, func(s BenchSample) float64 { return s.NsPerOp })
}

// MedianAllocs returns the median allocation count per operation.
func (r BenchResult) MedianAllocs() float64 {
	return median(r.Samples, func(s BenchSample) float64 { return s.AllocsPerOp })
}

// RangeNs returns the fastest and slowest time samples. Two runs of the same
// code overlap here; code that genuinely got slower does not.
func (r BenchResult) RangeNs() (fastest, slowest float64) {
	if len(r.Samples) == 0 {
		return 0, 0
	}
	fastest, slowest = r.Samples[0].NsPerOp, r.Samples[0].NsPerOp
	for _, s := range r.Samples {
		fastest = min(fastest, s.NsPerOp)
		slowest = max(slowest, s.NsPerOp)
	}
	return fastest, slowest
}

func median(samples []BenchSample, pick func(BenchSample) float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	values := make([]float64, 0, len(samples))
	for _, s := range samples {
		values = append(values, pick(s))
	}
	slices.Sort(values)
	return values[len(values)/2]
}

// BrokenBenchmark is a benchmark the run could not measure because it failed:
// a panic, a fatal error, or a Fatal call inside the benchmark.
type BrokenBenchmark struct {
	Package string
	// Output is the first line of the failure that says what went wrong.
	Output string
}

// BenchRun is one sampling of a package set.
type BenchRun struct {
	Results map[string]BenchResult
	// Broken maps every benchmark that failed to what it said. Each is skipped
	// and the packages are run again without it, so a benchmark that panics
	// costs its own measurement rather than every measurement of its package.
	Broken map[string]BrokenBenchmark
}

// maxBrokenBenchmarks bounds how many failing benchmarks one sampling skips
// past: each is another run of the binaries, and a package set where more of
// them fail is reported as the failure it is.
const maxBrokenBenchmarks = 5

// RunBenchmarks executes every benchmark in the given packages once, except
// the names in skip, and returns the parsed samples keyed by benchmark name.
// Callers take repeated samples by calling again, which is what lets a
// comparison interleave the two sides, and pass the Broken names of earlier
// samples as skip so a failure is paid for once.
func RunBenchmarks(ctx context.Context, runner Runner, dir string, patterns, skip []string) (BenchRun, error) {
	run := BenchRun{Results: map[string]BenchResult{}, Broken: map[string]BrokenBenchmark{}}
	if len(patterns) == 0 {
		return run, nil
	}
	skip = slices.Clone(skip)
	for attempt := 0; ; attempt++ {
		args := []string{
			"test", "-run", "^$", "-bench", ".", "-benchmem",
			"-benchtime", BenchTime, "-count", "1", "-json",
		}
		if len(skip) > 0 {
			args = append(args, "-skip", skipPattern(skip))
		}
		args = append(args, patterns...)

		res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
		if err != nil {
			return BenchRun{}, err
		}
		stream, parseErr := parseBenchmarkStream(res.Stdout)
		if parseErr != nil {
			return BenchRun{}, parseErr
		}
		if res.ExitCode == 0 {
			run.Results = stream.results
			return run, nil
		}
		name, broken, found := stream.failure()
		if !found || attempt == maxBrokenBenchmarks {
			return BenchRun{}, fmt.Errorf("go test -bench exited %d without producing measurements: %s",
				res.ExitCode, strings.TrimSpace(firstLines(stream.text()+res.Stderr, 20)))
		}
		run.Broken[name] = broken
		skip = append(skip, name)
	}
}

// skipPattern builds the -skip expression for whole benchmarks. A failing
// sub-benchmark takes its parent with it, because the parent is what -skip
// addresses and what the next sample must not start.
func skipPattern(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, regexp.QuoteMeta(name))
	}
	return "^(" + strings.Join(quoted, "|") + ")$"
}

// benchStream is what one -json benchmark run said: the measurements, which
// benchmark each package was running last, which ones reported failure, and
// every output line in order for the reader who has to see the rest.
type benchStream struct {
	results map[string]BenchResult
	running map[string]string
	order   []string
	failed  []benchFailure
	output  map[string][]string
	lines   []string
}

type benchFailure struct {
	name, pkg string
}

func parseBenchmarkStream(stdout string) (*benchStream, error) {
	dec := jsontext.NewDecoder(strings.NewReader(stdout))
	stream := &benchStream{
		results: map[string]BenchResult{}, running: map[string]string{}, output: map[string][]string{},
	}
	for {
		var ev testEvent
		if err := json.UnmarshalDecode(dec, &ev); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decoding benchmark output: %w", err)
		}
		switch ev.Action {
		case "run":
			stream.running[ev.Package] = ev.Test
			stream.order = append(stream.order, ev.Package)
		case "fail":
			if ev.Test != "" {
				stream.failed = append(stream.failed, benchFailure{name: ev.Test, pkg: ev.Package})
			}
		case "output":
			stream.lines = append(stream.lines, strings.TrimRight(ev.Output, "\n"))
			if ev.Test != "" {
				key := ev.Package + " " + ev.Test
				stream.output[key] = append(stream.output[key], ev.Output)
			}
			name, sample, ok := parseBenchmarkLine(ev.Output)
			if !ok {
				continue
			}
			result := stream.results[name]
			result.Name = name
			result.Samples = append(result.Samples, sample)
			stream.results[name] = result
		}
	}
	return stream, nil
}

// failure names the benchmark that brought the run down: the first one the
// stream reported as failed, else the one that was running when the process
// died, which is what a panic leaves behind. The name is the top-level
// benchmark, since that is the unit -skip addresses.
func (s *benchStream) failure() (string, BrokenBenchmark, bool) {
	var name, pkg string
	switch {
	case len(s.failed) > 0:
		name, pkg = s.failed[0].name, s.failed[0].pkg
	case len(s.order) > 0:
		pkg = s.order[len(s.order)-1]
		name = s.running[pkg]
	}
	if name == "" {
		return "", BrokenBenchmark{}, false
	}
	line := "no output captured"
	for _, out := range s.output[pkg+" "+name] {
		trimmed := strings.TrimSpace(out)
		if trimmed == "" || strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "---") || trimmed == name {
			continue
		}
		line = trimmed
		break
	}
	top, _, _ := strings.Cut(name, "/")
	return top, BrokenBenchmark{Package: pkg, Output: line}, true
}

// text returns the run's output as the reader would have seen it without
// -json, which is the only form an error message should quote.
func (s *benchStream) text() string {
	return strings.Join(s.lines, "\n")
}

// parseBenchmarkLine reads one "BenchmarkX-8  200  1234 ns/op  56 B/op  7
// allocs/op" line. Lines that are not measurements are skipped.
func parseBenchmarkLine(line string) (name string, sample BenchSample, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasPrefix(fields[0], "Benchmark") {
		return "", BenchSample{}, false
	}
	name = fields[0]
	if base, procs, ok := strings.CutLast(name, "-"); ok && base != "" {
		if _, err := strconv.Atoi(procs); err == nil {
			name = base
		}
	}
	measured := false
	for i := 1; i+1 < len(fields); i++ {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			continue
		}
		switch fields[i+1] {
		case "ns/op":
			sample.NsPerOp = value
			measured = true
		case "B/op":
			sample.BytesPerOp = value
		case "allocs/op":
			sample.AllocsPerOp = value
		}
	}
	return name, sample, measured
}

// OverlayPath writes a go build overlay mapping original file paths to
// replacement files, and returns the overlay's path.
func OverlayPath(dir string, replacements map[string]string) (string, error) {
	document := struct {
		Replace map[string]string `json:"Replace"`
	}{Replace: replacements}
	encoded, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return "", fmt.Errorf("encoding build overlay: %w", err)
	}
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return "", fmt.Errorf("writing build overlay: %w", err)
	}
	return path, nil
}

// OverlayOutcome is what one overlaid test run established.
type OverlayOutcome int

const (
	// OverlayPassed means every package built and no test failed.
	OverlayPassed OverlayOutcome = iota
	// OverlayFailed means a test in a package that built failed.
	OverlayFailed
	// OverlayNotBuilt means a package did not compile, so none of its tests
	// ran. go test exits 1 here exactly as it does for a failing test, and only
	// the event stream tells the two apart; read as a kill, a compiler error
	// once discharged the test-effectiveness claim for a whole change.
	OverlayNotBuilt
)

// RunTestsWithOverlay runs the test binary for the given packages against an
// overlay, so a mutated source file is compiled without the worktree ever being
// modified.
//
// Vet is off here for a reason beyond speed: a mutated expression can trip a vet
// analyzer, and a non-zero exit from vet would be read as a test noticing the
// mutant when no test ran at all.
func RunTestsWithOverlay(ctx context.Context, runner Runner, dir, overlay string, patterns []string) (OverlayOutcome, error) {
	args := []string{"test", "-count=1", "-vet=off", "-json", "-overlay", overlay}
	args = append(args, patterns...)
	res, runErr := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if runErr != nil {
		return OverlayPassed, runErr
	}
	outcome, err := overlayOutcome(res.Stdout)
	if err != nil {
		return OverlayPassed, fmt.Errorf("%w (go test exit %d, stderr: %s)",
			err, res.ExitCode, strings.TrimSpace(firstLines(res.Stderr, 10)))
	}
	if res.ExitCode != 0 && outcome == OverlayPassed {
		return OverlayPassed, fmt.Errorf("go test exited %d without a failing test or a failed build: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr+res.Stdout, 20)))
	}
	return outcome, nil
}

// overlayOutcome reads the event stream for the two facts a mutant run needs:
// whether a test failed in a package that built, and whether any package
// failed to build. A failure in a built package wins, because a test that
// noticed the mutant is the evidence the run was after, whatever happened to
// packages further away that never compiled against it.
func overlayOutcome(stdout string) (OverlayOutcome, error) {
	dec := jsontext.NewDecoder(strings.NewReader(stdout))
	outcome := OverlayPassed
	for {
		var ev testEvent
		if err := json.UnmarshalDecode(dec, &ev); err != nil {
			if errors.Is(err, io.EOF) {
				return outcome, nil
			}
			return OverlayPassed, fmt.Errorf("decoding go test JSON: %w", err)
		}
		switch {
		case ev.Action == "build-fail":
			if outcome == OverlayPassed {
				outcome = OverlayNotBuilt
			}
		case ev.Action == "fail" && ev.FailedBuild != "":
			// The package-level echo of a build-fail event, already counted.
		case ev.Action == "fail":
			outcome = OverlayFailed
		}
	}
}

// MergeBenchResults appends one run's samples onto the results collected so far.
func MergeBenchResults(into, from map[string]BenchResult) {
	for name, result := range from {
		existing := into[name]
		existing.Name = name
		existing.Samples = append(existing.Samples, result.Samples...)
		into[name] = existing
	}
}

// BenchmarkNames returns the benchmark names common to two runs, sorted.
func BenchmarkNames(base, head map[string]BenchResult) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(head)) {
		if _, ok := base[name]; ok {
			out = append(out, name)
		}
	}
	return out
}
