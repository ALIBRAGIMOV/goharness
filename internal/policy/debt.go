package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// DebtFileName is the acknowledged-debt ledger, at the module root beside the
// policy file.
const DebtFileName = "goharness.debt.yaml"

// DebtSchema is the only ledger schema this binary reads. A ledger declaring
// another version is refused rather than read on a guess: it names findings by
// fingerprint, and reading it wrongly would silence the wrong ones.
const DebtSchema = 1

// DebtRecordedUncommitted is the revision a ledger records when the repository
// had no commit to name.
const DebtRecordedUncommitted = "uncommitted"

// DebtEntry is one acknowledged finding.
//
// The fingerprint is the whole identity; rule and file are carried so the file
// can be reviewed by a human, which is the only reason it is a checked-in
// document rather than a cache entry.
type DebtEntry struct {
	Fingerprint string
	RuleID      string
	File        string
}

// DebtLedger is the parsed contents of goharness.debt.yaml: the findings a
// repository has acknowledged as existing debt.
//
// It is a ratchet, never a discount. A finding it names stops blocking only
// through the same pre-existing-debt path that base comparison already uses, so
// the ungrandfatherable core is unaffected by any ledger, and the bar for
// anything the ledger does not name does not move by a hair.
type DebtLedger struct {
	Schema     int
	RecordedAt string
	Entries    []DebtEntry
}

// Fingerprints returns the acknowledged identities as a set, so a caller pays
// for the index once rather than scanning the ledger per finding.
func (l DebtLedger) Fingerprints() map[string]bool {
	out := make(map[string]bool, len(l.Entries))
	for _, e := range l.Entries {
		out[e.Fingerprint] = true
	}
	return out
}

// ParseDebtLedger decodes the restricted ledger shape: two scalar top-level
// keys and one list of flat mappings. Anything outside that shape is an error
// rather than a silently ignored key, for the same reason the policy file is
// read that way: a mistyped key in a file that decides what stops blocking must
// never read as an empty one.
func ParseDebtLedger(src []byte) (DebtLedger, error) {
	var l DebtLedger
	var current map[string]string
	inEntries, sawSchema := false, false

	flush := func() error {
		if current == nil {
			return nil
		}
		defer func() { current = nil }()
		entry, err := debtEntryFromMap(current)
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, entry)
		return nil
	}

	for lineNo, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimRight(raw, "\r")
		body := strings.TrimSpace(line)
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			if err := flush(); err != nil {
				return DebtLedger{}, err
			}
			inEntries = false
			key, value, err := debtTopLevel(body, lineNo+1)
			if err != nil {
				return DebtLedger{}, err
			}
			switch key {
			case "entries":
				inEntries = true
			case "schema":
				n, convErr := strconv.Atoi(value)
				if convErr != nil {
					return DebtLedger{}, fmt.Errorf(
						"%s line %d: schema must be an integer, got %q", DebtFileName, lineNo+1, value)
				}
				l.Schema, sawSchema = n, true
			case "recordedAt":
				l.RecordedAt = value
			}
		case inEntries && strings.HasPrefix(body, "- "):
			if err := flush(); err != nil {
				return DebtLedger{}, err
			}
			current = map[string]string{}
			if err := putField(DebtFileName, current, strings.TrimPrefix(body, "- "), lineNo+1); err != nil {
				return DebtLedger{}, err
			}
		case inEntries && current != nil:
			if err := putField(DebtFileName, current, body, lineNo+1); err != nil {
				return DebtLedger{}, err
			}
		default:
			return DebtLedger{}, fmt.Errorf("%s line %d: unexpected content %q", DebtFileName, lineNo+1, body)
		}
	}
	if err := flush(); err != nil {
		return DebtLedger{}, err
	}
	if !sawSchema {
		return DebtLedger{}, fmt.Errorf("%s: no schema declared; this binary reads schema %d",
			DebtFileName, DebtSchema)
	}
	if l.Schema != DebtSchema {
		return DebtLedger{}, fmt.Errorf("%s declares schema %d, and this binary reads schema %d",
			DebtFileName, l.Schema, DebtSchema)
	}
	return l, duplicateFingerprints(l.Entries)
}

func debtTopLevel(body string, lineNo int) (key, value string, err error) {
	key, value, ok := strings.Cut(body, ":")
	if !ok {
		return "", "", fmt.Errorf("%s line %d: expected key: value, got %q", DebtFileName, lineNo, body)
	}
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if unquoted, unquoteErr := strconv.Unquote(value); unquoteErr == nil {
		value = unquoted
	}
	switch key {
	case "schema", "recordedAt", "entries":
		return key, value, nil
	default:
		return "", "", fmt.Errorf("%s line %d: unknown top-level key %q", DebtFileName, lineNo, key)
	}
}

func debtEntryFromMap(fields map[string]string) (DebtEntry, error) {
	for key := range fields {
		switch key {
		case "fingerprint", "rule", "file":
		default:
			return DebtEntry{}, fmt.Errorf("%s: unknown entry field %q", DebtFileName, key)
		}
	}
	for _, key := range []string{"fingerprint", "rule"} {
		if strings.TrimSpace(fields[key]) == "" {
			return DebtEntry{}, fmt.Errorf("%s: entry is missing required field %q", DebtFileName, key)
		}
	}
	return DebtEntry{
		Fingerprint: fields["fingerprint"], RuleID: fields["rule"], File: fields["file"],
	}, nil
}

// duplicateFingerprints refuses a ledger that names one finding twice. The
// second entry could only ever have come from a hand edit, and a document whose
// entry count disagrees with the number of findings it acknowledges would
// report a burn-down that never reaches zero.
func duplicateFingerprints(entries []DebtEntry) error {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.Fingerprint] {
			return fmt.Errorf("%s: fingerprint %s is recorded twice", DebtFileName, e.Fingerprint)
		}
		seen[e.Fingerprint] = true
	}
	return nil
}

// SortDebtEntries orders a ledger for writing: by rule, then file, then
// fingerprint, so re-recording an unchanged finding set produces identical
// bytes and a review diff shows only what actually moved.
func SortDebtEntries(entries []DebtEntry) {
	slices.SortFunc(entries, func(a, b DebtEntry) int {
		if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
			return c
		}
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
}

// RenderDebtLedger renders a ledger to its canonical bytes, sorted and with the
// header that says what the file is for. File paths are quoted because a path is
// the one field whose contents this format does not otherwise constrain.
func RenderDebtLedger(l DebtLedger) []byte {
	entries := slices.Clone(l.Entries)
	SortDebtEntries(entries)

	var b strings.Builder
	b.WriteString("# goharness acknowledged debt ledger.\n")
	b.WriteString("# Commit and review this file: only the copy at HEAD has any effect, and an\n")
	b.WriteString("# entry here stops a finding from blocking `goharness audit` and nothing else.\n")
	b.WriteString("# Rules in the ungrandfatherable core are never recorded and never silenced.\n")
	fmt.Fprintf(&b, "schema: %d\n", DebtSchema)
	fmt.Fprintf(&b, "recordedAt: %s\n", l.RecordedAt)
	b.WriteString("entries:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  - fingerprint: %s\n", e.Fingerprint)
		fmt.Fprintf(&b, "    rule: %s\n", e.RuleID)
		if e.File != "" {
			fmt.Fprintf(&b, "    file: %s\n", strconv.Quote(e.File))
		}
	}
	return []byte(b.String())
}
