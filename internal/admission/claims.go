package admission

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
)

// Unproducible records an obligation that could not be discharged, with the
// reason a human can act on.
type Unproducible struct {
	Kind   EvidenceKind
	Reason string
	Remedy string
}

// ClaimInput is everything the claim evaluator reads. It is a value: evaluation
// is a pure function of the plan, the evidence, and what the run managed to
// produce.
type ClaimInput struct {
	Plan         VerificationPlan
	Evidence     []evidence.Evidence
	Produced     []EvidenceKind
	Unproducible []Unproducible
	Blocking     Blocking
}

// EvaluateClaims turns produced evidence and discharged obligations into one
// claim per dimension. It never invents a PASS: a dimension whose obligations
// were not all discharged is INCONCLUSIVE.
func EvaluateClaims(in ClaimInput) []QualityClaim {
	produced := make(map[EvidenceKind]bool, len(in.Produced))
	for _, kind := range in.Produced {
		produced[kind] = true
	}
	unproducible := make(map[EvidenceKind]Unproducible, len(in.Unproducible))
	for _, u := range in.Unproducible {
		unproducible[u.Kind] = u
	}
	byDimension := groupEvidence(in.Evidence)

	claims := make([]QualityClaim, 0, len(Dimensions()))
	for _, dim := range Dimensions() {
		claims = append(claims, evaluateOne(in, dim, produced, unproducible, byDimension[dim]))
	}
	return claims
}

func groupEvidence(items []evidence.Evidence) map[Dimension][]evidence.Evidence {
	out := map[Dimension][]evidence.Evidence{}
	for _, e := range items {
		dim, ok := DimensionOf(e.RuleID)
		if !ok {
			// An unmapped rule is a policy gap, not a licence to ignore the
			// finding: policy integrity owns anything the model cannot place.
			dim = DimPolicyIntegrity
		}
		out[dim] = append(out[dim], e)
	}
	return out
}

func evaluateOne(
	in ClaimInput,
	dim Dimension,
	produced map[EvidenceKind]bool,
	unproducible map[EvidenceKind]Unproducible,
	found []evidence.Evidence,
) QualityClaim {
	claim := QualityClaim{Dimension: dim}
	obligations := in.Plan.ObligationsFor(dim)

	var violations, supporting []evidence.Evidence
	for _, e := range found {
		if in.Blocking != nil && in.Blocking(e) {
			violations = append(violations, e)
			continue
		}
		supporting = append(supporting, e)
	}
	claim.EvidenceRefs = fingerprints(found)

	for _, o := range obligations {
		if !produced[o.Kind] {
			claim.MissingEvidence = append(claim.MissingEvidence, o.Kind)
		}
	}
	slices.Sort(claim.MissingEvidence)

	switch {
	case len(violations) > 0:
		claim.State = ClaimFail
		claim.Reason = failReason(violations)
	case len(obligations) == 0:
		claim.State = ClaimNotApplicable
		claim.Reason = "this change activates no obligation for this dimension"
	case len(claim.MissingEvidence) > 0:
		claim.State = ClaimInconclusive
		claim.Reason = inconclusiveReason(claim.MissingEvidence, unproducible)
	default:
		claim.State = ClaimPass
		claim.Reason = passReason(obligations, supporting)
	}
	return claim
}

func fingerprints(items []evidence.Evidence) []string {
	out := make([]string, 0, len(items))
	for _, e := range items {
		out = append(out, e.Fingerprint)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func failReason(violations []evidence.Evidence) string {
	rules := make([]string, 0, len(violations))
	for _, v := range violations {
		if !slices.Contains(rules, v.RuleID) {
			rules = append(rules, v.RuleID)
		}
	}
	slices.Sort(rules)
	return fmt.Sprintf("%d required violation(s): %s", len(violations), strings.Join(rules, ", "))
}

func inconclusiveReason(missing []EvidenceKind, unproducible map[EvidenceKind]Unproducible) string {
	parts := make([]string, 0, len(missing))
	for _, kind := range missing {
		if u, ok := unproducible[kind]; ok && u.Reason != "" {
			parts = append(parts, string(kind)+" ("+u.Reason+")")
			continue
		}
		parts = append(parts, string(kind))
	}
	return "required evidence was not produced: " + strings.Join(parts, ", ")
}

func passReason(obligations []RequiredEvidence, supporting []evidence.Evidence) string {
	reason := fmt.Sprintf("%d obligation(s) discharged with no required violation", len(obligations))
	if len(supporting) > 0 {
		reason += fmt.Sprintf("; %d advisory finding(s) recorded", len(supporting))
	}
	return reason
}

// UnmetObligations returns the obligations whose claims came out INCONCLUSIVE,
// so a report can name exactly what could not be produced.
func UnmetObligations(plan VerificationPlan, claims []QualityClaim) []RequiredEvidence {
	missing := map[EvidenceKind]bool{}
	for _, c := range claims {
		for _, kind := range c.MissingEvidence {
			missing[kind] = true
		}
	}
	var out []RequiredEvidence
	for _, o := range plan.Obligations {
		if missing[o.Kind] {
			out = append(out, o)
		}
	}
	return out
}

// Remedies returns the human remedy for each unproducible obligation, in a
// stable order, for the INCONCLUSIVE section of a report.
func Remedies(unproducible []Unproducible) []string {
	sorted := slices.Clone(unproducible)
	slices.SortFunc(sorted, func(a, b Unproducible) int {
		return strings.Compare(string(a.Kind), string(b.Kind))
	})
	out := make([]string, 0, len(sorted))
	for _, u := range sorted {
		line := string(u.Kind) + ": " + u.Reason
		if u.Remedy != "" {
			line += "\n      to produce it: " + u.Remedy
		}
		out = append(out, line)
	}
	return out
}
