package verify_test

import (
	"strings"
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

// The cases here are the module states a repository actually shows up in.
// None of them is exotic, and each one used to be unexercised: a vendored tree,
// and a requirement the machine cannot resolve.

const vendoredDependency = `package dep

// Value is what the fixture's library returns.
func Value() int {
	return 7
}
`

const vendorConsumer = `package lib

import "example.com/dep"

// Answer returns the dependency's value.
func Answer() int {
	return dep.Value()
}
`

const vendorConsumerTest = `package lib

import "testing"

func TestAnswer(t *testing.T) {
	if got := Answer(); got != 7 {
		t.Fatalf("Answer() = %d, want 7", got)
	}
}
`

// TestVendoredModuleIsVerifiable covers the repository that ships its
// dependencies in tree. The go command switches to -mod=vendor on its own, so
// the harness has to leave vendored code out of scope while still judging the
// module's own packages.
func TestVendoredModuleIsVerifiable(t *testing.T) {
	useGolangci(t)
	f := newFixture(t)
	f.write("go.mod", "module example.com/fixture\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./deps/dep\n")
	f.write("deps/dep/go.mod", "module example.com/dep\n\ngo 1.26\n")
	f.write("deps/dep/dep.go", vendoredDependency)
	f.write("lib/lib.go", vendorConsumer)
	f.write("lib/lib_test.go", vendorConsumerTest)
	f.mustGo("mod", "tidy")
	f.mustGo("mod", "vendor")
	f.commit("vendored baseline")
	f.write("lib/lib.go", strings.Replace(vendorConsumer, "dep.Value()", "dep.Value() + 0", 1))
	f.commit("touch the consumer")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictAdmitted)
	for _, e := range result.Evidence {
		if strings.HasPrefix(e.File, "vendor/") {
			t.Fatalf("vendored code was judged as the module's own: %+v", e)
		}
	}
}

// TestUnresolvableRequirementIsInconclusive pins what happens when the machine
// cannot obtain a module the change depends on. Nothing about the code has been
// established, so the run must say so rather than call the change broken, and it
// must never call it admissible.
func TestUnresolvableRequirementIsInconclusive(t *testing.T) {
	f := newFixture(t)
	f.write("lib/lib.go", "package lib\n\nimport \"example.com/absent/pkg\"\n\n// Answer returns the absent module's answer.\nfunc Answer() int {\n\treturn pkg.Answer()\n}\n")
	f.write("go.mod", "module example.com/fixture\n\ngo 1.26\n\nrequire example.com/absent v1.0.0\n")
	f.commit("a requirement nothing can resolve")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "")

	result := run(t, f, verify.ModeVerify)
	requireVerdict(t, result, admission.VerdictInconclusive)
	if !strings.Contains(allFailureText(result), "example.com/absent") {
		t.Fatalf("nothing named the unresolvable module: %+v", result.Failures)
	}
	for _, e := range result.Evidence {
		if e.RuleID == "GH-BUILD-001" {
			t.Fatalf("an unobtainable module was reported as a compile defect: %+v", e)
		}
	}
}

func allFailureText(result verify.Result) string {
	var b strings.Builder
	for _, f := range result.Failures {
		b.WriteString(f.Reason)
	}
	for _, u := range result.Unproducible {
		b.WriteString(u.Reason)
	}
	return b.String()
}
