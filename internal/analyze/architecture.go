package analyze

import (
	"slices"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/evidence"
	"github.com/ALIBRAGIMOV/goharness/internal/policy"
)

// BannedPackageNames are names that describe no domain. A package named for
// what it is not becomes an import magnet: unrelated code accumulates there
// because nothing about the name excludes anything.
func BannedPackageNames() []string {
	return []string{
		"base", "common", "core", "helper", "helpers", "misc", "shared",
		"util", "utils", "manager", "service", "handler", "handlers",
	}
}

func (s *scanner) scanArchitecture() {
	s.checkPackageName()
	s.checkForbiddenImports()
}

func (s *scanner) checkPackageName() {
	name := s.file.Name.Name
	if !slices.Contains(BannedPackageNames(), strings.ToLower(name)) {
		return
	}
	// One finding per package, not per file: the name is a property of the
	// directory, and repeating it per file would inflate the evidence set.
	if s.rel != s.firstFileOfPackage {
		return
	}
	s.add(s.file.Name.Pos(), policy.RuleBannedPackageName,
		"package name "+name+" names no domain, so unrelated code accumulates here and every layer ends up importing it",
		evidence.SeverityError, false)
}

func (s *scanner) checkForbiddenImports() {
	rules := s.opts.Architecture.ForbiddenImports
	if len(rules) == 0 {
		return
	}
	dir := packageDirOf(s.rel)
	for _, spec := range s.file.Imports {
		importPath := strings.Trim(spec.Path.Value, `"`)
		local := strings.TrimPrefix(importPath, s.opts.Architecture.ModulePath+"/")
		for _, rule := range rules {
			if !strings.HasPrefix(dir, rule.From) || !strings.HasPrefix(local, rule.Deny) {
				continue
			}
			message := dir + " must not import " + local
			if rule.Reason != "" {
				message += ": " + rule.Reason
			}
			s.add(spec.Pos(), policy.RuleForbiddenImport, message, evidence.SeverityError, false)
		}
	}
}

func packageDirOf(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return "."
}
