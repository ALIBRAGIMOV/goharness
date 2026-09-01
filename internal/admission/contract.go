package admission

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

// ContractFileName is the conventional location of a task contract.
const ContractFileName = "goharness.task.yaml"

// ContractSource records where a contract came from, for the report.
type ContractSource string

// Contract sources, in the priority order they are tried.
const (
	ContractFromFlag    ContractSource = "--contract flag"
	ContractFromFile    ContractSource = ContractSource(ContractFileName)
	ContractFromBase    ContractSource = "base revision"
	ContractFromDefault ContractSource = "implicit default"
)

// Grant names the permissive contract fields. They are the only fields that can
// make the gate weaker, which is why they are honoured from an authenticated
// contract alone.
const (
	GrantAPIBreak   = "allowApiBreak"
	GrantPolicyEdit = "allowPolicyEdit"
	GrantBudgets    = "budgets"
)

// Budget bounds an acceptable performance regression for one benchmark.
type Budget struct {
	MaxTimeIncreasePercent  float64
	MaxAllocIncreasePercent float64
}

// DefaultBudget is applied to any benchmark the contract does not name.
func DefaultBudget() Budget {
	return Budget{MaxTimeIncreasePercent: 15, MaxAllocIncreasePercent: 10}
}

// TaskContract is what the change claims to accomplish. The zero value is the
// implicit default contract: no declared scope, no declared risks, no API
// breaks allowed.
type TaskContract struct {
	Source          ContractSource
	Goal            string
	DeclaredScope   []string
	DeclaredRisks   []RiskDomain
	Budgets         map[string]Budget
	AllowAPIBreak   bool
	AllowPolicyEdit bool
	// Authenticated records that the grants in force were read from the base
	// revision, where the change under verification could not have written them.
	Authenticated bool
	// IgnoredGrants names the grants the working-tree contract asked for and did
	// not get, so the report can say why a permission had no effect.
	IgnoredGrants []string
}

// HasScope reports whether the contract constrains where the change may land.
func (c TaskContract) HasScope() bool {
	return len(c.DeclaredScope) > 0
}

// BudgetFor returns the regression budget for one benchmark.
func (c TaskContract) BudgetFor(benchmark string) Budget {
	if b, ok := c.Budgets[benchmark]; ok {
		return b
	}
	return DefaultBudget()
}

// InScope reports whether a module-relative path is inside the declared scope.
// Without a declared scope every path is in scope.
func (c TaskContract) InScope(file string) bool {
	if !c.HasScope() {
		return true
	}
	return slices.ContainsFunc(c.DeclaredScope, func(pattern string) bool {
		return scopeMatch(pattern, file)
	})
}

func scopeMatch(pattern, file string) bool {
	pattern = strings.TrimSuffix(strings.TrimSuffix(pattern, "..."), "**")
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(file, pattern)
	}
	if pattern == file {
		return true
	}
	if ok, err := path.Match(pattern, file); err == nil && ok {
		return true
	}
	return strings.HasPrefix(file, pattern+"/")
}

// LoadContract resolves the contract in priority order: the explicit flag, the
// conventional file at the repository root, then the implicit default.
func LoadContract(explicitPath string, tree fs.FS) (TaskContract, error) {
	if explicitPath != "" {
		data, err := os.ReadFile(explicitPath)
		if err != nil {
			return TaskContract{}, fmt.Errorf("reading contract %s: %w", explicitPath, err)
		}
		return ParseContract(data, ContractFromFlag)
	}
	data, err := fs.ReadFile(tree, ContractFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return TaskContract{
				Source: ContractFromDefault,
				Goal:   "this change must be admissible under the strict policy",
			}, nil
		}
		return TaskContract{}, fmt.Errorf("reading %s: %w", ContractFileName, err)
	}
	return ParseContract(data, ContractFromFile)
}

// Merge combines the contract committed at the base revision with the one the
// working tree carries.
//
// Grants come from the base alone. A change cannot widen the permissions it is
// judged under, because the base revision predates it; a working-tree contract
// that asks for a grant it was not given records the refusal in IgnoredGrants
// instead of taking effect. Declarations that can only make the gate stricter
// (the goal, a scope where the base declares none, additional risk domains) are
// taken from either side, because granting them costs nothing.
func Merge(base, head TaskContract) TaskContract {
	out := head
	if head.Source == ContractFromDefault {
		out = base
	}
	out.Authenticated = base.Source == ContractFromBase
	out.AllowAPIBreak = base.AllowAPIBreak
	out.AllowPolicyEdit = base.AllowPolicyEdit
	out.Budgets = base.Budgets
	if base.HasScope() {
		out.DeclaredScope = base.DeclaredScope
	}
	out.DeclaredRisks = mergedRisks(base, head)
	out.IgnoredGrants = ignoredGrants(base, head)
	return out
}

func mergedRisks(base, head TaskContract) []RiskDomain {
	out := slices.Clone(base.DeclaredRisks)
	for _, domain := range head.DeclaredRisks {
		if !slices.Contains(out, domain) {
			out = append(out, domain)
		}
	}
	slices.Sort(out)
	return out
}

// ignoredGrants lists the grants the working-tree contract asks for beyond the
// ones the base revision already carries. Budgets count as one grant however
// many benchmarks differ: the report names the field, not every entry.
func ignoredGrants(base, head TaskContract) []string {
	var out []string
	if head.AllowAPIBreak && !base.AllowAPIBreak {
		out = append(out, GrantAPIBreak)
	}
	if head.AllowPolicyEdit && !base.AllowPolicyEdit {
		out = append(out, GrantPolicyEdit)
	}
	if budgetsDiffer(base.Budgets, head.Budgets) {
		out = append(out, GrantBudgets)
	}
	return out
}

func budgetsDiffer(base, head map[string]Budget) bool {
	for name, budget := range head {
		if existing, ok := base[name]; !ok || existing != budget {
			return true
		}
	}
	return false
}

// ParseContract decodes the restricted contract subset: scalar keys, string
// lists, and a nested budgets mapping. Anything outside that shape is an error
// rather than a silently ignored key, because a misread contract would relax
// the gate without saying so.
func ParseContract(src []byte, source ContractSource) (TaskContract, error) {
	c := TaskContract{Source: source, Budgets: map[string]Budget{}}
	section := ""
	benchmark := ""

	for lineNo, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 {
			key, value, err := splitKeyValue(trimmed, lineNo+1)
			if err != nil {
				return TaskContract{}, err
			}
			section, benchmark = key, ""
			if value == "" {
				if !isContractSection(key) {
					return TaskContract{}, fmt.Errorf("%s line %d: unknown key %q", ContractFileName, lineNo+1, key)
				}
				continue
			}
			if err := c.setScalar(key, value, lineNo+1); err != nil {
				return TaskContract{}, err
			}
			section = ""
			continue
		}

		if item, ok := strings.CutPrefix(trimmed, "- "); ok {
			if err := c.appendItem(section, strings.TrimSpace(item), lineNo+1); err != nil {
				return TaskContract{}, err
			}
			continue
		}
		key, value, err := splitKeyValue(trimmed, lineNo+1)
		if err != nil {
			return TaskContract{}, err
		}
		if section != "budgets" {
			return TaskContract{}, fmt.Errorf("%s line %d: unexpected mapping under %q", ContractFileName, lineNo+1, section)
		}
		if value == "" {
			benchmark = key
			c.Budgets[benchmark] = DefaultBudget()
			continue
		}
		if err := c.setBudgetField(benchmark, key, value, lineNo+1); err != nil {
			return TaskContract{}, err
		}
	}
	return c, nil
}

func isContractSection(key string) bool {
	switch key {
	case "scope", "risks", "budgets":
		return true
	}
	return false
}

func splitKeyValue(body string, lineNo int) (key, value string, err error) {
	key, value, ok := strings.Cut(body, ":")
	if !ok {
		return "", "", fmt.Errorf("%s line %d: expected key: value, got %q", ContractFileName, lineNo, body)
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if unquoted, unquoteErr := strconv.Unquote(value); unquoteErr == nil {
		value = unquoted
	}
	return key, value, nil
}

func (c *TaskContract) setScalar(key, value string, lineNo int) error {
	switch key {
	case "goal":
		c.Goal = value
	case "allowApiBreak":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s line %d: allowApiBreak must be true or false: %w", ContractFileName, lineNo, err)
		}
		c.AllowAPIBreak = parsed
	case "allowPolicyEdit":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s line %d: allowPolicyEdit must be true or false: %w", ContractFileName, lineNo, err)
		}
		c.AllowPolicyEdit = parsed
	default:
		return fmt.Errorf("%s line %d: unknown key %q", ContractFileName, lineNo, key)
	}
	return nil
}

func (c *TaskContract) appendItem(section, item string, lineNo int) error {
	if unquoted, err := strconv.Unquote(item); err == nil {
		item = unquoted
	}
	switch section {
	case "scope":
		c.DeclaredScope = append(c.DeclaredScope, item)
	case "risks":
		domain := RiskDomain(item)
		if !slices.Contains(RiskDomains(), domain) {
			return fmt.Errorf("%s line %d: unknown risk domain %q", ContractFileName, lineNo, item)
		}
		c.DeclaredRisks = append(c.DeclaredRisks, domain)
	default:
		return fmt.Errorf("%s line %d: list item outside a list-valued key", ContractFileName, lineNo)
	}
	return nil
}

func (c *TaskContract) setBudgetField(benchmark, key, value string, lineNo int) error {
	if benchmark == "" {
		return fmt.Errorf("%s line %d: budget field %q has no benchmark", ContractFileName, lineNo, key)
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fmt.Errorf("%s line %d: %s must be a number: %w", ContractFileName, lineNo, key, err)
	}
	budget := c.Budgets[benchmark]
	switch key {
	case "maxTimeIncreasePercent":
		budget.MaxTimeIncreasePercent = parsed
	case "maxAllocIncreasePercent":
		budget.MaxAllocIncreasePercent = parsed
	default:
		return fmt.Errorf("%s line %d: unknown budget field %q", ContractFileName, lineNo, key)
	}
	c.Budgets[benchmark] = budget
	return nil
}
