package verify_test

import (
	"testing"

	"github.com/ALIBRAGIMOV/goharness/internal/admission"
	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
	"github.com/ALIBRAGIMOV/goharness/internal/verify"
)

func TestExitCodes(t *testing.T) {
	t.Parallel()
	cases := map[admission.Verdict]int{
		admission.VerdictAdmitted:     0,
		admission.VerdictRejected:     1,
		admission.VerdictInconclusive: 2,
	}
	for verdict, want := range cases {
		if got := verdict.ExitCode(); got != want {
			t.Errorf("%s exit code = %d, want %d", verdict, got, want)
		}
	}
}

func TestBlockingRespectsBaseComparison(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		item evidence.Evidence
		want bool
	}{
		{
			name: "new required finding blocks",
			item: evidence.Evidence{RuleID: "GCL-errcheck", Classification: evidence.ClassificationRequired, State: evidence.StateNew},
			want: true,
		},
		{
			name: "pre-existing required finding is debt",
			item: evidence.Evidence{RuleID: "GCL-errcheck", Classification: evidence.ClassificationRequired, State: evidence.StatePreexisting},
			want: false,
		},
		{
			name: "pre-existing suppression still blocks",
			item: evidence.Evidence{RuleID: policy.RuleSuppressNolint, Classification: evidence.ClassificationRequired, State: evidence.StatePreexisting},
			want: true,
		},
		{
			name: "pre-existing em dash still blocks",
			item: evidence.Evidence{RuleID: policy.RuleCommentEmDash, Classification: evidence.ClassificationRequired, State: evidence.StatePreexisting},
			want: true,
		},
		{
			name: "fixed finding never blocks",
			item: evidence.Evidence{RuleID: policy.RuleSuppressNolint, Classification: evidence.ClassificationRequired, State: evidence.StateFixed},
			want: false,
		},
		{
			name: "advisory never blocks",
			item: evidence.Evidence{RuleID: "GCL-modernize", Classification: evidence.ClassificationAdvisory, State: evidence.StateNew},
			want: false,
		},
		{
			name: "required finding without base comparison blocks",
			item: evidence.Evidence{RuleID: "GCL-errcheck", Classification: evidence.ClassificationRequired},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := verify.Blocking(tc.item); got != tc.want {
				t.Fatalf("Blocking = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"fast", "verify", "audit"} {
		if mode, ok := verify.ParseMode(name); !ok || string(mode) != name {
			t.Fatalf("ParseMode(%q) = %q, %v", name, mode, ok)
		}
	}
	if mode, ok := verify.ParseMode("deep"); !ok || mode != verify.ModeAudit {
		t.Fatalf("ParseMode(\"deep\") = %q, %v; want the audit alias", mode, ok)
	}
	if _, ok := verify.ParseMode("fix"); ok {
		t.Fatal("ParseMode accepted an unknown mode")
	}
}

func TestOnlyGatesCanCompleteATask(t *testing.T) {
	t.Parallel()
	if verify.ModeFast.IsAdmissionGate() {
		t.Fatal("fast presented itself as an admission gate")
	}
	for _, mode := range []verify.Mode{verify.ModeVerify, verify.ModeAudit} {
		if !mode.IsAdmissionGate() {
			t.Fatalf("%s is not an admission gate", mode)
		}
	}
}
