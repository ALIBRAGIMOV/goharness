package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Exception is a centrally recorded, expiring waiver for one rule in one scope.
// Every field is mandatory: an exception without an owner or an expiry is
// indistinguishable from disabling the rule.
type Exception struct {
	RuleID  string
	Scope   string
	Reason  string
	Owner   string
	Expires time.Time
}

// RuleOverride raises the classification of an optional rule. Configuration can
// only make policy stricter.
type RuleOverride struct {
	RuleID         string
	Classification Classification
}

// ArchitectureRule forbids one package prefix from importing another. The
// harness never invents a layering; every rule here is declared by the project.
type ArchitectureRule struct {
	From   string
	Deny   string
	Reason string
}

// Config is the parsed contents of goharness.yaml.
type Config struct {
	Exceptions   []Exception
	Overrides    []RuleOverride
	Architecture []ArchitectureRule
}

// ExpiresLayout is the date format accepted for exception expiry.
const ExpiresLayout = "2006-01-02"

// ConfigFileName is the project policy file, at the module root.
const ConfigFileName = "goharness.yaml"

// ParseConfig decodes the restricted goharness.yaml subset: two optional
// top-level keys, each a list of flat string mappings. Anything outside that
// shape is an error rather than a silently ignored key.
func ParseConfig(src []byte) (Config, error) {
	var cfg Config
	section := ""
	var current map[string]string
	flush := func() error {
		if current == nil {
			return nil
		}
		defer func() { current = nil }()
		switch section {
		case "exceptions":
			exc, err := exceptionFromMap(current)
			if err != nil {
				return err
			}
			cfg.Exceptions = append(cfg.Exceptions, exc)
		case "rules":
			ovr, err := overrideFromMap(current)
			if err != nil {
				return err
			}
			cfg.Overrides = append(cfg.Overrides, ovr)
		case "architecture":
			rule, err := architectureFromMap(current)
			if err != nil {
				return err
			}
			cfg.Architecture = append(cfg.Architecture, rule)
		}
		return nil
	}

	for lineNo, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimRight(raw, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := strings.TrimSpace(line)

		switch {
		case indent == 0 && strings.HasSuffix(body, ":"):
			if err := flush(); err != nil {
				return Config{}, err
			}
			section = strings.TrimSuffix(body, ":")
			if section != "exceptions" && section != "rules" && section != "architecture" {
				return Config{}, fmt.Errorf("%s line %d: unknown top-level key %q", ConfigFileName, lineNo+1, section)
			}
		case strings.HasPrefix(body, "- "):
			if err := flush(); err != nil {
				return Config{}, err
			}
			current = map[string]string{}
			if err := putField(ConfigFileName, current, strings.TrimPrefix(body, "- "), lineNo+1); err != nil {
				return Config{}, err
			}
		case current != nil:
			if err := putField(ConfigFileName, current, body, lineNo+1); err != nil {
				return Config{}, err
			}
		default:
			return Config{}, fmt.Errorf("%s line %d: unexpected content %q", ConfigFileName, lineNo+1, body)
		}
	}
	if err := flush(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// putField records one "key: value" line of a restricted document. The file
// name is a parameter because two files share this shape and an error that
// names the wrong one sends the reader to the wrong document.
func putField(file string, dst map[string]string, body string, lineNo int) error {
	key, value, ok := strings.Cut(body, ":")
	if !ok {
		return fmt.Errorf("%s line %d: expected key: value, got %q", file, lineNo, body)
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}
	if _, exists := dst[key]; exists {
		return fmt.Errorf("%s line %d: duplicate key %q", file, lineNo, key)
	}
	dst[key] = value
	return nil
}

func exceptionFromMap(fields map[string]string) (Exception, error) {
	for _, key := range []string{"rule", "scope", "reason", "owner", "expires"} {
		if strings.TrimSpace(fields[key]) == "" {
			return Exception{}, fmt.Errorf("exception is missing required field %q", key)
		}
	}
	expires, err := time.Parse(ExpiresLayout, fields["expires"])
	if err != nil {
		return Exception{}, fmt.Errorf("exception %q: expires must be YYYY-MM-DD: %w", fields["rule"], err)
	}
	for _, id := range MandatoryRuleIDs() {
		if id == fields["rule"] {
			return Exception{}, fmt.Errorf("rule %s is mandatory and cannot be excepted", id)
		}
	}
	return Exception{
		RuleID:  fields["rule"],
		Scope:   fields["scope"],
		Reason:  fields["reason"],
		Owner:   fields["owner"],
		Expires: expires,
	}, nil
}

func architectureFromMap(fields map[string]string) (ArchitectureRule, error) {
	for _, key := range []string{"from", "deny"} {
		if strings.TrimSpace(fields[key]) == "" {
			return ArchitectureRule{}, fmt.Errorf("architecture rule is missing required field %q", key)
		}
	}
	return ArchitectureRule{
		From: fields["from"], Deny: fields["deny"], Reason: fields["reason"],
	}, nil
}

func overrideFromMap(fields map[string]string) (RuleOverride, error) {
	id := strings.TrimSpace(fields["id"])
	if id == "" {
		return RuleOverride{}, fmt.Errorf("rule override is missing required field %q", "id")
	}
	class := Classification(strings.TrimSpace(fields["classification"]))
	if class != ClassRequired && class != ClassAdvisory {
		return RuleOverride{}, fmt.Errorf("rule override %q: classification must be required or advisory", id)
	}
	return RuleOverride{RuleID: id, Classification: class}, nil
}
