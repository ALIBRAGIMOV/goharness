package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
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

// RunBenchmarks executes every benchmark in the given packages once and returns
// the parsed samples keyed by benchmark name. Callers take repeated samples by
// calling again, which is what lets a comparison interleave the two sides.
func RunBenchmarks(ctx context.Context, runner Runner, dir string, patterns []string) (map[string]BenchResult, error) {
	if len(patterns) == 0 {
		return map[string]BenchResult{}, nil
	}
	args := []string{
		"test", "-run", "^$", "-bench", ".", "-benchmem",
		"-benchtime", BenchTime, "-count", "1", "-json",
	}
	args = append(args, patterns...)

	res, err := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if err != nil {
		return nil, err
	}
	results, parseErr := parseBenchmarkStream(res.Stdout)
	if parseErr != nil {
		return nil, parseErr
	}
	if len(results) == 0 && res.ExitCode != 0 {
		return nil, fmt.Errorf("go test -bench exited %d without producing measurements: %s",
			res.ExitCode, strings.TrimSpace(firstLines(res.Stderr+res.Stdout, 20)))
	}
	return results, nil
}

func parseBenchmarkStream(stdout string) (map[string]BenchResult, error) {
	dec := json.NewDecoder(strings.NewReader(stdout))
	out := map[string]BenchResult{}
	for {
		var ev testEvent
		if err := dec.Decode(&ev); err != nil {
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			return nil, fmt.Errorf("decoding benchmark output: %w", err)
		}
		if ev.Action != "output" {
			continue
		}
		name, sample, ok := parseBenchmarkLine(ev.Output)
		if !ok {
			continue
		}
		result := out[name]
		result.Name = name
		result.Samples = append(result.Samples, sample)
		out[name] = result
	}
	return out, nil
}

// parseBenchmarkLine reads one "BenchmarkX-8  200  1234 ns/op  56 B/op  7
// allocs/op" line. Lines that are not measurements are skipped.
func parseBenchmarkLine(line string) (name string, sample BenchSample, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasPrefix(fields[0], "Benchmark") {
		return "", BenchSample{}, false
	}
	name = fields[0]
	if i := strings.LastIndex(name, "-"); i > 0 {
		if _, err := strconv.Atoi(name[i+1:]); err == nil {
			name = name[:i]
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
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("encoding build overlay: %w", err)
	}
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return "", fmt.Errorf("writing build overlay: %w", err)
	}
	return path, nil
}

// RunTestsWithOverlay runs the test binary for the given packages against an
// overlay, so a mutated source file is compiled without the worktree ever being
// modified.
//
// Vet is off here for a reason beyond speed: a mutated expression can trip a vet
// analyzer, and a non-zero exit from vet would be read as a test noticing the
// mutant when no test ran at all.
func RunTestsWithOverlay(ctx context.Context, runner Runner, dir, overlay string, patterns []string) (failed bool, err error) {
	args := []string{"test", "-count=1", "-vet=off", "-overlay", overlay}
	args = append(args, patterns...)
	res, runErr := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if runErr != nil {
		return false, runErr
	}
	return res.ExitCode != 0, nil
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
