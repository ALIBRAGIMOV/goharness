package change

import "testing"

// TestHunkHeadersThatWriteNothingAreNotSpans covers the shapes a diff produces
// that added no line: a pure deletion, and a file the head tree does not have.
func TestHunkHeadersThatWriteNothingAreNotSpans(t *testing.T) {
	t.Parallel()
	diff := "diff --git a/lib/gone.go b/lib/gone.go\n" +
		"--- a/lib/gone.go\n+++ /dev/null\n@@ -1,4 +0,0 @@\n" +
		"diff --git a/lib/lib.go b/lib/lib.go\n" +
		"--- a/lib/lib.go\n+++ b/lib/lib.go\n@@ -8,2 +7,0 @@\n@@ -20,0 +19,3 @@\n"
	spans := parseUnifiedHunks(diff, "")
	if _, ok := spans["lib/gone.go"]; ok {
		t.Fatalf("a deleted file carries spans: %v", spans)
	}
	if got := spans["lib/lib.go"]; len(got) != 1 || got[0] != (LineRange{Start: 19, End: 21}) {
		t.Fatalf("spans for the edited file = %v, want one span 19-21", got)
	}
}
