package verify

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/tool"
)

// BenchmarkSchedule measures the scheduler's own overhead with trivial checks,
// so a regression in wave computation or aggregation is visible separately from
// the cost of the tools it runs.
func BenchmarkSchedule(b *testing.B) {
	engine := &Engine{Logger: zap.NewNop(), Concurrency: 4}
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

// TestTimeRegressionIgnoresOverlappingSamples is the false-positive guard the
// corpus asked for: a nanosecond-scale benchmark measured on a busy machine
// swings by tens of percent, and a change is only slower when every sample says
// so.
func TestTimeRegressionIgnoresOverlappingSamples(t *testing.T) {
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
		{"separated ranges are a regression", noisy(70, 72, 74), noisy(85, 88, 90), true},
		{"inside the budget", noisy(100, 100, 100), noisy(105, 105, 105), false},
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
