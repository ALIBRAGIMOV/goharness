package tool

import (
	"context"
	"strings"
	"testing"
)

// sequenceRunner answers one scripted result per call, in order, and keeps
// every command it was given.
type sequenceRunner struct {
	results []Result
	calls   []Command
}

func (s *sequenceRunner) Run(_ context.Context, cmd Command) (Result, error) {
	s.calls = append(s.calls, cmd)
	res := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return res, nil
}

const panickingBenchStream = `{"Action":"start","Package":"example.com/lib"}
{"Action":"output","Package":"example.com/lib","Output":"goos: darwin\n"}
{"Action":"run","Package":"example.com/lib","Test":"BenchmarkFine"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkFine","Output":"BenchmarkFine-8   \t 1000000\t      1024 ns/op\t     256 B/op\t       4 allocs/op\n"}
{"Action":"run","Package":"example.com/lib","Test":"BenchmarkBroken"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkBroken","Output":"=== RUN   BenchmarkBroken\n"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkBroken","Output":"BenchmarkBroken\n"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkBroken","Output":"panic: cannot create context from nil parent\n"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkBroken","Output":"\n"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkBroken","Output":"goroutine 23 [running]:\n"}
{"Action":"output","Package":"example.com/lib","Output":"FAIL\texample.com/lib\t0.792s\n"}
{"Action":"fail","Package":"example.com/lib"}
`

const measuredBenchStream = `{"Action":"start","Package":"example.com/lib"}
{"Action":"run","Package":"example.com/lib","Test":"BenchmarkFine"}
{"Action":"output","Package":"example.com/lib","Test":"BenchmarkFine","Output":"BenchmarkFine-8   \t 1000000\t      1024 ns/op\t     256 B/op\t       4 allocs/op\n"}
{"Action":"output","Package":"example.com/lib","Output":"PASS\n"}
{"Action":"pass","Package":"example.com/lib"}
`

// TestRunBenchmarksSkipsTheBenchmarkThatPanickedAndMeasuresTheRest pins the
// recovery: the benchmark that was running when the process died is named,
// skipped on the next run, and the rest of the package is measured.
func TestRunBenchmarksSkipsTheBenchmarkThatPanickedAndMeasuresTheRest(t *testing.T) {
	t.Parallel()
	runner := &sequenceRunner{results: []Result{
		{ExitCode: 2, Stdout: panickingBenchStream},
		{ExitCode: 0, Stdout: measuredBenchStream},
	}}
	run, err := RunBenchmarks(t.Context(), runner, ".", []string{"./lib"}, nil)
	if err != nil {
		t.Fatalf("RunBenchmarks: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("go test ran %d time(s), want 2: once to fail, once without the broken benchmark", len(runner.calls))
	}
	second := strings.Join(runner.calls[1].Args, " ")
	if !strings.Contains(second, "-skip ^(BenchmarkBroken)$") {
		t.Fatalf("the second run does not skip the broken benchmark: %s", second)
	}
	broken, ok := run.Broken["BenchmarkBroken"]
	if !ok || broken.Package != "example.com/lib" || broken.Output != "panic: cannot create context from nil parent" {
		t.Fatalf("broken = %+v, want BenchmarkBroken with its panic line", run.Broken)
	}
	if got := run.Results["BenchmarkFine"]; len(got.Samples) != 1 || got.Samples[0].NsPerOp != 1024 {
		t.Fatalf("BenchmarkFine was not measured on the second run: %+v", run.Results)
	}
}

// TestRunBenchmarksPaysForAKnownFailureOnce is the interleaving contract: a
// caller that passes the broken names back as skip gets one run, not two.
func TestRunBenchmarksPaysForAKnownFailureOnce(t *testing.T) {
	t.Parallel()
	runner := &sequenceRunner{results: []Result{{ExitCode: 0, Stdout: measuredBenchStream}}}
	if _, err := RunBenchmarks(t.Context(), runner, ".", []string{"./lib"}, []string{"BenchmarkBroken"}); err != nil {
		t.Fatalf("RunBenchmarks: %v", err)
	}
	if len(runner.calls) != 1 || !strings.Contains(strings.Join(runner.calls[0].Args, " "), "-skip ^(BenchmarkBroken)$") {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

// TestRunBenchmarksQuotesTheOutputNotTheEventStream keeps a failure that
// names no benchmark readable: the error carries what go test printed, never
// the JSON envelope it was printed in.
func TestRunBenchmarksQuotesTheOutputNotTheEventStream(t *testing.T) {
	t.Parallel()
	stream := `{"Action":"start","Package":"example.com/lib"}
{"Action":"output","Package":"example.com/lib","Output":"# example.com/lib [example.com/lib.test]\n"}
{"Action":"output","Package":"example.com/lib","Output":"./lib_test.go:9:2: undefined: Missing\n"}
{"Action":"output","Package":"example.com/lib","Output":"FAIL\texample.com/lib [build failed]\n"}
{"Action":"fail","Package":"example.com/lib"}
`
	runner := &sequenceRunner{results: []Result{{ExitCode: 1, Stdout: stream}}}
	_, err := RunBenchmarks(t.Context(), runner, ".", []string{"./lib"}, nil)
	if err == nil {
		t.Fatal("a run that measured nothing and named no benchmark was accepted")
	}
	if !strings.Contains(err.Error(), "undefined: Missing") || strings.Contains(err.Error(), `"Action"`) {
		t.Fatalf("the error does not quote the output as printed: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("go test ran %d time(s); nothing to skip, so once", len(runner.calls))
	}
}
