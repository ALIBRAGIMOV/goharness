package evidence_test

import (
	"fmt"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

func BenchmarkFingerprint(b *testing.B) {
	for b.Loop() {
		_ = evidence.Fingerprint("GCL-errcheck", "internal/verify/engine.go",
			"github.com/ALIBRAGIMOV/goharness/internal/verify",
			"Error return value of `os.Open` is not checked", 0)
	}
}

func BenchmarkFinalize(b *testing.B) {
	const size = 500
	items := make([]evidence.Evidence, 0, size)
	for i := range size {
		items = append(items, evidence.Evidence{
			RuleID:  fmt.Sprintf("GCL-linter%02d", i%20),
			File:    fmt.Sprintf("internal/pkg%02d/file.go", i%13),
			Line:    i,
			Message: fmt.Sprintf("finding number %d that needs normalising", i%7),
		})
	}
	b.ResetTimer()
	for b.Loop() {
		_ = evidence.Finalize(items)
	}
}
