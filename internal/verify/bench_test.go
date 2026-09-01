package verify

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// BenchmarkSchedule measures the scheduler's own overhead with trivial checks,
// so a regression in wave computation or aggregation is visible separately from
// the cost of the tools it runs.
func BenchmarkSchedule(b *testing.B) {
	engine := &Engine{Logger: slog.New(slog.DiscardHandler), Concurrency: 4}
	checks := make([]Check, 0, 24)
	checks = append(checks, Check{
		ID:       admission.ProducerCompile,
		Produces: []admission.EvidenceKind{admission.KindCompileClean},
		run:      func(context.Context) (checkResult, error) { return checkResult{}, nil },
	})
	for i := range 23 {
		checks = append(checks, Check{
			ID:        fmt.Sprintf("check-%02d", i),
			DependsOn: []string{admission.ProducerCompile},
			Produces:  []admission.EvidenceKind{admission.EvidenceKind(fmt.Sprintf("kind-%02d", i))},
			run: func(context.Context) (checkResult, error) {
				return checkResult{evidence: []evidence.Evidence{{RuleID: "GH-X", File: "a.go"}}}, nil
			},
		})
	}
	sortChecks(checks)

	ctx := b.Context()
	b.ResetTimer()
	for b.Loop() {
		if _, err := engine.schedule(ctx, checks); err != nil {
			b.Fatal(err)
		}
	}
}

// TestTimeRegressionNeedsEvidenceBeyondTheMeasurementSpread is the
// false-positive guard, and this harness needed it twice.
//
// Comparing medians turned a machine's drift into a regression report for every
// benchmark at once, and interleaving fixed that. Separated sample ranges became
// the evidence, and then this harness rejected its own change on two benchmarks
// measuring under one percent apart on an idle machine: head's samples had been
// stretched by the base tree's suite running beside them, which separates two
// ranges describing identical code.
//
// So the budget is applied to the most conservative pairing the samples permit,
// head's fastest against base's slowest. A real regression of about the size of
// the budget goes unreported when the samples are spread, which is the right way
// round: a gate that cries wolf is switched off.
func TestTimeRegressionNeedsEvidenceBeyondTheMeasurementSpread(t *testing.T) {
	t.Parallel()
	noisy := func(values ...float64) tool.BenchResult {
		samples := make([]tool.BenchSample, 0, len(values))
		for _, v := range values {
			samples = append(samples, tool.BenchSample{NsPerOp: v})
		}
		return tool.BenchResult{Samples: samples}
	}
	cases := []struct {
		name       string
		base, head tool.BenchResult
		regressed  bool
	}{
		{"overlapping ranges are noise", noisy(70, 72, 90), noisy(80, 85, 88), false},
		{"unambiguously slower", noisy(70, 72, 74), noisy(100, 102, 104), true},
		{"inside the budget", noisy(100, 100, 100), noisy(105, 105, 105), false},
		// The case this harness rejected itself on: the medians are 45% apart and
		// the ranges do not overlap, but head's own samples span three quarters of
		// their own value, which is a machine under load rather than a measurement.
		{"a stretched head sample is not a measurement",
			noisy(414665, 420000, 424766), noisy(437071, 600000, 761580), false},
		// And the near miss the conservative pairing accepts: separated ranges
		// whose worst-case reading is still inside the budget.
		{"separated but inside the budget once spread is counted",
			noisy(70, 72, 74), noisy(85, 88, 90), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, got := timeRegression(c.base, c.head, 15); got != c.regressed {
				t.Fatalf("timeRegression = %t, want %t", got, c.regressed)
			}
		})
	}
}
