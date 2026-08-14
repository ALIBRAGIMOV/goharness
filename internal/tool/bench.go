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

// Benchmark sampling is fixed rather than time-based so that base and head do
// the same amount of work and the comparison measures the code, not the clock.
const (
	BenchIterations = "200x"
	BenchSamples    = "3"
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

// SpreadNs returns the relative spread of the time samples, which bounds how
// much of an observed change can be attributed to noise.
func (r BenchResult) SpreadNs() float64 {
	if len(r.Samples) < 2 {
		return 0
	}
	lowest, highest := r.Samples[0].NsPerOp, r.Samples[0].NsPerOp
	for _, s := range r.Samples {
		lowest = min(lowest, s.NsPerOp)
		highest = max(highest, s.NsPerOp)
	}
	mid := r.MedianNs()
	if mid == 0 {
		return 0
	}
	return (highest - lowest) / mid * 100
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

// RunBenchmarks executes every benchmark in the given packages and returns the
// parsed samples keyed by benchmark name.
func RunBenchmarks(ctx context.Context, runner Runner, dir string, patterns []string) (map[string]BenchResult, error) {
	if len(patterns) == 0 {
		return map[string]BenchResult{}, nil
	}
	args := []string{
		"test", "-run", "^$", "-bench", ".", "-benchmem",
		"-benchtime", BenchIterations, "-count", BenchSamples, "-json",
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
func RunTestsWithOverlay(ctx context.Context, runner Runner, dir, overlay string, patterns []string) (failed bool, err error) {
	args := []string{"test", "-count=1", "-overlay", overlay}
	args = append(args, patterns...)
	res, runErr := runner.Run(ctx, Command{Dir: dir, Name: "go", Args: args})
	if runErr != nil {
		return false, runErr
	}
	return res.ExitCode != 0, nil
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
