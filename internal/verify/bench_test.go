package verify

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
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
