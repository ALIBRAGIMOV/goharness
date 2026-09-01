package tool

import (
	"strings"
	"testing"
)

// The streams the harness reads come from Go programs whose encoders never
// emit a duplicate name, so one that does is not a stream to guess about: it
// is refused, and the check fails loudly instead of taking the last value.
func TestDuplicateNamesInAToolStreamAreRefused(t *testing.T) {
	t.Parallel()
	const stream = `{"Action":"fail","Package":"p","Package":"q","Test":"TestX"}` + "\n"
	if _, err := parseTestJSON(stream); err == nil {
		t.Fatal("a stream with a duplicate object member was accepted")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	if _, err := overlayOutcome(stream); err == nil {
		t.Fatal("an overlay stream with a duplicate object member was accepted")
	}
}
