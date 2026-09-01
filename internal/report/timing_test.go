package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ALIBRAGIMOV/goharness/internal/report"
)

// A run past a minute says where the time went, so nobody digs
// timing.checksMs out of the JSON to learn that one check was most of it.
func TestTextReportNamesTheSlowestChecksOfALongRun(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.Duration = 6 * time.Minute
	result.CheckTimings = map[string]time.Duration{
		"benchmark": 250 * time.Second,
		"race-test": 70 * time.Second,
		"gofmt":     900 * time.Millisecond,
		"lint":      12 * time.Second,
		"compile":   3 * time.Second,
	}
	var buf bytes.Buffer
	if err := report.WriteTextWithOptions(&buf, "test", result, report.TextOptions{}); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	text := buf.String()
	want := "slowest checks: benchmark 4m10s, race-test 1m10s, lint 12s"
	if !strings.Contains(text, want) {
		t.Fatalf("the report does not name the three slowest checks in order:\nwant %q\n%s", want, text)
	}
	if strings.Contains(text, "compile 3s") {
		t.Fatalf("the report lists more than the three slowest checks:\n%s", text)
	}
}

func TestTextReportStaysQuietAboutTimingsOnAShortRun(t *testing.T) {
	t.Parallel()
	result := sampleResult()
	result.Duration = 40 * time.Second
	result.CheckTimings = map[string]time.Duration{"race-test": 35 * time.Second}
	var buf bytes.Buffer
	if err := report.WriteTextWithOptions(&buf, "test", result, report.TextOptions{}); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if strings.Contains(buf.String(), "slowest checks") {
		t.Fatalf("a short run reports its slowest checks:\n%s", buf.String())
	}
}
