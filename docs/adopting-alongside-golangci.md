# Adopting goharness alongside an existing golangci-lint configuration

This page is for a repository that already runs golangci-lint in CI and now
wants goharness's fixed external bar as well. It is written from one real
adoption: a 111k-line Go backend whose local gate ran "enable all, disable
questionable" plus `go test -race` and govulncheck, was green, and produced 1623
blocking findings on first contact with `goharness audit`.

The friction is not that the two tools disagree about Go. It is that they are
two gates over one tree, and satisfying one can break the other. Every coupling
below cost that adoption real time.

## The shape of the problem

goharness runs its own pinned golangci-lint (2.12.2 exactly) with its own
embedded strict configuration. It never reads your `.golangci.yml` and never
writes it. Your configuration keeps deciding what your CI gate reports; the
strict pack decides what goharness reports. Where the two differ, the difference
is the accumulated distance between "our standard" and "the standard", and that
difference is what `goharness audit` measures.

Run `goharness audit` once before changing anything. In audit mode the report
carries a `policyShadow` section built from your own configuration: which
linters the strict pack requires and yours does not run, which exclusion rules
drop linters inside `_test.go`, and whether `errcheck` runs with `check-blank`.
It states the mechanism and, where the count can be exact, how many of this
run's findings live behind it. It never changes the verdict.

## The four couplings that bite

### 1. Deleting an inline suppression breaks your gate first

`GH-SUPPRESS-003` fires on an inline `#nosec`; the same rules cover `//nolint`,
`//lint:ignore` and `//revive:disable`. They are mandatory and can never be
excepted or baselined, because a suppression is precisely what an outer gate
exists to see.

The trap: that `#nosec` is what keeps *your* gosec green. Delete it to satisfy
goharness and your own CI turns red on the next push.

Order that avoids a red intermediate state:

1. Teach your configuration the equivalent scoped exclusion first, and commit
   that alone. In v2 that is an entry under `linters.exclusions.rules` naming
   the path, the linter and, ideally, the `text` of the finding.
2. Then delete the inline comment. Your gate stays green across both commits and
   goharness stops reporting the suppression.
3. Then decide whether the exclusion is still wanted at all. A scoped exclusion
   in a reviewed configuration file is a central, greppable decision. An inline
   comment is not; that asymmetry is the whole rule.

goharness has no opinion about step 3, and it does not read the exclusion you
added. It only ever objected to the comment.

### 2. `check-blank` and the local blank-discard idiom

The strict pack runs `errcheck` with `check-blank: true`. Most configurations
leave it at its default, which is false, so `_ = f.Close()` and
`rows, _ := db.Query(...)` are legal locally and reported by goharness. This was
461 findings on the adoption above, of which roughly 40 were silent data loss in
a compliance-bearing flow and the rest were the community's close/rollback
idiom.

Do not start by turning `check-blank: true` on locally. That reproduces the
whole cliff inside your own gate on the same afternoon. Instead:

1. Read the findings by `remedyClass`, which goharness derives from the callee:
   `domain-write` and anything unrecognised come first (a lost write nothing
   observes), then `resource-close`, `cleanup`, `encode`, `diagnostic`.
   `summary.byRemedyClass` in the JSON report gives the counts in one place.
2. Fix the `domain-write` bucket by hand. It is small and it is the reason to
   adopt the tool.
3. Record the rest in the debt ledger (below), which keeps the bar fixed for
   anything new without asking you to rewrite a thousand idiomatic lines.
4. Turn `check-blank: true` on locally once the ledger stops growing. From then
   on both gates agree and new code cannot add to the pile.

A note on `errchkjson`: if you run it with `check-error-free-encoding`, it
proves certain `json.Marshal` calls cannot fail and then objects to checking
their error, which contradicts errcheck. goharness deliberately does not add
errchkjson to the pack; the canonical escape is a small typed helper that owns
the check once. `goharness explain GCL-errcheck` prints the shape.

### 3. Convention-based exclusions, such as `// Const.` globals

Configurations often grant `gochecknoglobals` an exclusion by comment
convention, so a global marked `// Const.` is accepted. goharness reads no such
convention: `GCL-gochecknoglobals` is required and fires on the declaration.

There is no configuration answer on the goharness side, and there should not be
one: a comment that grants an exemption is a suppression wearing different
words. The two real answers are to make the value actually immutable (a
function returning a fresh copy, or a typed constant set), or to record the
handful of remaining sites in the ledger and stop adding to them. Either way,
change nothing in your own configuration; the convention keeps working locally.

### 4. Wholesale `_test.go` exclusions

Excluding a dozen linters from test files is a very common local choice, and it
is where the adoption above had 259 unreported errcheck findings: setup failures
in tests that pass silently. goharness lints test files like any other code, so
these arrive all at once.

The strict pack itself excludes exactly two linters from `_test.go`
(`gochecknoglobals`, `gosec`), and that difference is deliberate: those two
report noise about test code, and the rest report defects in the code that
decides whether your suite can be trusted. Duplication in test files is exempt
too, but the exemption lives in the native clone scanner rather than in this
configuration, because `dupl` no longer runs at all.

Sequence:

1. Leave your exclusion in place. Fixing test-file findings does not require
   touching it, and narrowing it early doubles the work in flight.
2. Work the findings goharness reports, worst consequence first.
3. Narrow the exclusion list in your own configuration afterwards, one linter at
   a time, each time the corresponding goharness findings reach zero. Every step
   is green in both gates.

## The general ordering

The pattern behind all four is the same, and it is the only ordering that never
leaves a commit that fails a gate:

1. **Adjust the local configuration so the intended end state is already
   permitted.** Add the scoped exclusion, or nothing at all where none is
   needed. Commit alone.
2. **Fix the findings.** Commit in whatever slices review can absorb.
3. **Tighten the local configuration back**, removing the exclusion you added in
   step 1 or the one that hid the class you just fixed. Commit alone.

Reversing steps 1 and 2 is what produces the red intermediate state. Skipping
step 3 is what leaves the shadow in place for the next class of finding to
accumulate in.

## The two on-ramps

**`goharness fix --rule GH-COMMENT-001`** applies the mechanical remediation for
the rules whose fix the harness can state exactly. It rewrites comments only,
through the same parser-based walk the scanner uses, so string literals are
untouched by construction; `--dry-run` prints a diff and writes nothing. It is a
write command, so no verification command can reach it, and admission
re-verifies afterwards. Where a finding carries `fix.command` in the report,
that command closes it.

**The debt ledger** turns first contact from a cliff into a slope.
`goharness audit --baseline` records the run's blocking findings by fingerprint
in `goharness.debt.yaml` at the module root. Subsequent audits treat those
findings as pre-existing debt and enforce that nothing new joins them, and the
report's `baseline` block shows the burn-down. Four properties make it a ratchet
rather than a discount:

- only the copy committed at HEAD counts, so a change can never baseline itself;
- editing the file is an edit to the gate and is reported as `GH-POLICY-001`,
  which is ungrandfatherable, so the recording commit is visible to review;
- the mandatory core (inline suppressions, the policy guards, em dashes in
  generated prose) is never recorded and is never silenced by any ledger;
- the bar for everything the ledger does not name does not move at all.

`goharness verify`, the admission gate for a change, ignores the ledger
entirely. It has a real base revision to compare against, and pre-existing debt
is already what a base comparison means.

## What the end state looks like

- Your `.golangci.yml` has converged toward the strict pack: the same linters
  enabled, `check-blank` on, `_test.go` excluded for at most the three linters
  the strict pack excludes there.
- The exceptions that remain live in `goharness.yaml`, each with a rule, a
  narrow scope, a written reason, an owner and an expiry date. The mandatory
  core cannot appear there and the parser refuses anything less than all five
  fields.
- No inline suppression comments anywhere.
- `goharness.debt.yaml` is shrinking, and `baseline.new` is zero on every audit.
- `policyShadow` reports nothing, or reports only differences you have decided
  to keep and can name.

## Reference

- `goharness explain <RULE-ID>` for any rule, including its compliant pattern
  where one exists.
- `goharness explain <FINGERPRINT> --report report.json` for one row of a
  report, including rows a truncated document omitted.
- `docs/admission-model.md` for the normative claims model, the ledger and the
  policy-shadow section.
- `docs/toolchain.md` for how the pinned golangci-lint is provisioned and
  verified.
