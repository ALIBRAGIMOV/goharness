package verify_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

const outsideLibrary = `package lib

// Extra is code that lives outside the repository.
func Extra() int {
	return 1
}
`

// TestSymlinkOutOfTheTreeIsNotRead holds the boundary every read of repository
// content now goes through. A symlink inside the tree that points outside it
// used to be read and judged as this repository's code, which is one way to
// have the gate certify a file it was never asked about. The run refuses the
// path by name and never reaches a verdict on it.
func TestSymlinkOutOfTheTreeIsNotRead(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.anchor()
	outside := filepath.Join(t.TempDir(), "extra.go")
	if err := os.WriteFile(outside, []byte(outsideLibrary), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.moduleDir, "lib", "escape.go")); err != nil {
		t.Fatal(err)
	}

	result, err := verify.Run(t.Context(), "test", verify.Options{Mode: verify.ModeVerify, Dir: f.verifyDir()})
	if err == nil {
		t.Fatalf("a file outside the repository was read and judged: verdict %s", result.Decision.Verdict)
	}
	if !strings.Contains(err.Error(), "escape.go") {
		t.Fatalf("the refusal does not name the path: %v", err)
	}
	if result.Decision.Verdict == admission.VerdictAdmitted {
		t.Fatal("a run that could not read its own input was admitted")
	}
}

// TestSymlinkInsideTheTreeIsRead is the guard: a link whose target is inside
// the repository is ordinary repository content and is read like any file.
func TestSymlinkInsideTheTreeIsRead(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("lib/lib.go", cleanLibrary)
	f.write("lib/lib_test.go", cleanLibraryTest)
	f.commit("clean baseline")
	f.anchor()
	f.write("assets/extra.go.src", outsideLibrary)
	if err := os.Symlink(filepath.Join("..", "assets", "extra.go.src"), filepath.Join(f.moduleDir, "lib", "extra.go")); err != nil {
		t.Fatal(err)
	}

	result, err := verify.Run(t.Context(), "test", verify.Options{Mode: verify.ModeVerify, Dir: f.verifyDir()})
	if err != nil {
		t.Fatalf("a link inside the tree was refused: %v", err)
	}
	for _, failure := range result.Failures {
		if strings.Contains(failure.Reason, "escape") {
			t.Fatalf("a link inside the tree was reported as escaping it: %+v", failure)
		}
	}
	if result.Decision.Verdict == "" {
		t.Fatal("the run reached no verdict")
	}
}
