package admission

import (
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// DimensionOf maps a rule ID onto the quality dimension whose claim the rule's
// evidence belongs to. The mapping lives here rather than in the policy
// registry so that policy stays a leaf package with no knowledge of the
// admission model.
//
// An unmapped rule reports false; callers must treat that as a policy gap
// rather than guessing a dimension, and a registry test keeps the map total.
func DimensionOf(ruleID string) (Dimension, bool) {
	if dim, ok := nativeDimensions()[ruleID]; ok {
		return dim, true
	}
	if analyzer, ok := strings.CutPrefix(ruleID, policy.GoFixRulePrefix); ok {
		dim, found := gofixDimensions()[analyzer]
		return dim, found
	}
	if linter, ok := strings.CutPrefix(ruleID, "GCL-"); ok {
		dim, found := linterDimensions()[linter]
		return dim, found
	}
	if strings.HasPrefix(ruleID, "UBER-") {
		return uberDimension(ruleID)
	}
	return "", false
}

func nativeDimensions() map[string]Dimension {
	return map[string]Dimension{
		policy.RuleFormatGofmt:         DimMaintainability,
		policy.RuleFormatGoimports:     DimMaintainability,
		policy.RuleCompile:             DimCorrectness,
		policy.RuleModTidy:             DimArchitecture,
		policy.RuleTestFailure:         DimCorrectness,
		policy.RuleVet:                 DimCorrectness,
		policy.RuleGovulncheck:         DimSecurity,
		policy.RuleSuppressNolint:      DimPolicyIntegrity,
		policy.RuleSuppressStaticcheck: DimPolicyIntegrity,
		policy.RuleSuppressNosec:       DimPolicyIntegrity,
		policy.RuleSuppressRevive:      DimPolicyIntegrity,
		policy.RulePolicyEdit:          DimPolicyIntegrity,
		policy.RulePolicyGrant:         DimPolicyIntegrity,
		policy.RuleGeneratedEdit:       DimPolicyIntegrity,
		policy.RuleGoroutineLeak:       DimConcurrencySafety,
		policy.RuleCommentEmDash:       DimPolicyIntegrity,
		policy.RuleCommentSize:         DimMaintainability,
		policy.RuleCommentRestates:     DimMaintainability,
		policy.RuleTestNoAssertion:     DimTestEffectiveness,
		policy.RuleTestSkipped:         DimTestEffectiveness,
		policy.RuleTestEmpty:           DimTestEffectiveness,
		policy.RuleTestTautology:       DimTestEffectiveness,
		policy.RuleTestIgnoredError:    DimTestEffectiveness,
		policy.RuleGoroutineLifetime:   DimConcurrencySafety,
		policy.RuleGoroutineInLoop:     DimBoundedResources,
		policy.RuleTimerInLoop:         DimBoundedResources,
		policy.RuleVariableChanBuf:     DimBoundedResources,
		policy.RuleClientTimeout:       DimReliability,
		policy.RuleRequestContext:      DimReliability,
		policy.RuleUnboundedRetry:      DimReliability,
		policy.RuleTxNotResolved:       DimOperability,
		policy.RuleMigrationRewrite:    DimOperability,
		policy.RuleBannedPackageName:   DimArchitecture,
		policy.RuleForbiddenImport:     DimArchitecture,
		policy.RuleAPIBreak:            DimArchitecture,
		policy.RuleNewDependency:       DimArchitecture,
		policy.RuleComplexity:          DimSimplicity,
		policy.RuleForwardingLayer:     DimSimplicity,
		policy.RuleSoleImplementation:  DimSimplicity,
		policy.RuleDeprecatedNoInline:  DimMaintainability,
		policy.RuleNesting:             DimSimplicity,
		policy.RuleFunctionLength:      DimSimplicity,
		policy.RuleComplexityDelta:     DimMaintainability,
		policy.RuleDocCoverageDelta:    DimMaintainability,
		policy.RuleFanOutDelta:         DimMaintainability,
		policy.RuleClone:               DimReuse,
		policy.RuleAssertionRemoved:    DimTestEffectiveness,
		policy.RuleSkipAdded:           DimTestEffectiveness,
		policy.RuleTestDeleted:         DimTestEffectiveness,
		policy.RuleToleranceWidened:    DimTestEffectiveness,
		policy.RuleMutantsSurvived:     DimTestEffectiveness,
		policy.RuleBenchTimeDelta:      DimPerformance,
		policy.RuleBenchAllocDelta:     DimPerformance,
		policy.RuleScopeViolation:      DimRequirements,
	}
}

// gofixDimensions places each go fix analyzer on the dimension its findings
// speak to. The three groups match the three obligations the fix check
// discharges, so a check that fails leaves every dimension it could have
// spoken to INCONCLUSIVE rather than one of them silently passing.
func gofixDimensions() map[string]Dimension {
	dims := map[string]Dimension{
		"inline":    DimMaintainability,
		"plusbuild": DimMaintainability,
		"hostport":  DimReliability,
	}
	for _, analyzer := range policy.GoFixAnalyzers() {
		if _, placed := dims[analyzer]; !placed {
			dims[analyzer] = DimSimplicity
		}
	}
	return dims
}

func linterDimensions() map[string]Dimension {
	return map[string]Dimension{
		"bodyclose":        DimOperability,
		"dupl":             DimReuse,
		"errcheck":         DimReliability,
		"errname":          DimMaintainability,
		"errorlint":        DimReliability,
		"fatcontext":       DimReliability,
		"forcetypeassert":  DimReliability,
		"gochecknoglobals": DimArchitecture,
		"gochecknoinits":   DimArchitecture,
		"gosec":            DimSecurity,
		"revive":           DimCorrectness,
		"ineffassign":      DimCorrectness,
		"makezero":         DimCorrectness,
		"modernize":        DimSimplicity,
		"musttag":          DimReliability,
		"nilerr":           DimReliability,
		"nilnesserr":       DimReliability,
		"nilnil":           DimReliability,
		"noctx":            DimOperability,
		"predeclared":      DimMaintainability,
		"rowserrcheck":     DimOperability,
		"sqlclosecheck":    DimOperability,
		"staticcheck":      DimCorrectness,
		"testifylint":      DimTestEffectiveness,
		"typecheck":        DimCorrectness,
		"unused":           DimSimplicity,
		"usestdlibvars":    DimSimplicity,
	}
}

// uberDimension derives a guide rule's dimension from the harness rule that
// enforces it, so the two can never disagree.
func uberDimension(ruleID string) (Dimension, bool) {
	rule, ok := policy.Lookup(ruleID)
	if !ok {
		return "", false
	}
	if dim, found := DimensionOf(rule.Enforcement); found {
		return dim, true
	}
	return uberManualDimensions()[ruleID], true
}

func uberManualDimensions() map[string]Dimension {
	return map[string]Dimension{
		"UBER-ERR-004": DimReliability,
		"UBER-PAN-001": DimReliability,
		"UBER-EXI-001": DimOperability,
		"UBER-STY-002": DimConcurrencySafety,
		"UBER-LOO-001": DimConcurrencySafety,
		"UBER-GOR-001": DimConcurrencySafety,
		"UBER-CPY-001": DimReliability,
		"UBER-EMB-001": DimArchitecture,
		"UBER-CHN-001": DimBoundedResources,
		"UBER-IFC-001": DimMaintainability,
		"UBER-ENU-001": DimReliability,
		"UBER-TIM-001": DimReliability,
		"UBER-STY-001": DimMaintainability,
		"UBER-TST-001": DimTestEffectiveness,
		"UBER-DEF-001": DimOperability,
	}
}
