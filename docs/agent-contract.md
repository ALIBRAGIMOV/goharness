# The agent contract snippet

goharness is designed as the completion protocol for coding agents. The whole
integration is one section in the instruction file your harness already reads:
`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or whatever your tool calls it. There
is no server to run and no protocol to speak: the CLI has documented exit codes
and one versioned JSON document, and that is the interface.

Copy the fragment below into that file, adjusting nothing but the paths. It
states the completion protocol, how to read the report, the two things an agent
must never do, and where the on-ramps are for a repository that does not pass
yet.

---

```markdown
## Completion protocol

Every task ends the same way:

    go build ./... && goharness verify --agent

The task is complete only when the verdict is ADMITTED. Resolve every FAIL and
every INCONCLUSIVE claim in the JSON document. `goharness fast` is a loop aid
during the work; it is never sufficient to finish, and always reports
`sufficientForCompletion: false`.

## Reading the report

In `--agent` mode stdout is exactly one `goharness.report/v2` document and the
human report goes to stderr. If the run could not start, stdout is empty and the
exit code is 2, so check the exit code before parsing. Work the document in this
order:

1. `sufficientForCompletion` - the task may be called done only when it is true.
2. `claims[].state` - FAIL: fix it. INCONCLUSIVE: produce the evidence named in
   `claims[].missingEvidence`, which is a different job.
3. `unproducible[]` - why an obligation could not be discharged, each with the
   `.remedy` that would produce it.
4. `evidence[]` - already in consequence order: silent-loss, unsafe-behavior,
   structural, hygiene. Work it in that order, never by count. `blocking: false`
   is advisory or pre-existing debt and does not have to be fixed.
5. `evidence[].state` and `evidence[].origin` - two different questions. `state`
   is whether the base revision already had the finding; `origin` is whether it
   sits in a file this change wrote. `new` plus `untouched` is a package the
   change broke without editing, and it blocks like anything else that is new.
6. `evidence[].fix.command` - the exact command that closes that finding.
7. `failures[]` - a tool that could not run; never a statement about the code.

`verify` renders the diff view by default: everything blocking, everything new or
fixed, and debt in the files the change touched. `evidenceScope` names the view
and `evidenceOmitted` counts the rows it withheld, so a short list is never
mistaken for a clean run. No view ever withholds a finding whose `blocking` is
true, so this changes how much there is to read and never what has to be fixed;
`--evidence full` prints everything.

`goharness explain RULE-ID` explains any rule. `goharness explain FINGERPRINT
--report r.json` explains one finding, including rows a narrowed report omitted.

## Two things never to do

- **Never write an inline suppression** (`//nolint`, `//lint:ignore`, `#nosec`,
  `//revive:disable`). They are mandatory findings that no configuration, no
  exception and no baseline can silence. Fix the code instead.
- **Never soften the gate to make a change pass.** Editing `goharness.yaml` or
  `goharness.debt.yaml` is reported as GH-POLICY-001, and a permission a change
  grants itself in the working tree is ignored and reported as GH-POLICY-003.
  If a rule is genuinely wrong, say so and stop; do not route around it.
```

---

## Context for whoever adopts this

**On-ramps, for a repository that does not pass yet.** Three, in the order they
usually matter:

- `goharness fix --rule <ID>` applies the mechanical remediation for the rules
  whose fix a tool can state exactly. Rewrites work on parsed syntax, so a
  string literal that contains the same text as a comment is untouched by
  construction. `--dry-run` prints a diff.
- `goharness audit --baseline` records today's blocking findings as
  acknowledged debt in `goharness.debt.yaml`. It is a ratchet, not a discount:
  only the committed copy counts, the ungrandfatherable core is never in it,
  and the report carries the burn-down. `goharness help audit` has the details.
- [docs/adopting-alongside-golangci.md](adopting-alongside-golangci.md) is the
  guide for a repository that already runs its own golangci-lint configuration,
  including the couplings that break the incumbent gate if the two are adopted
  in the wrong order.

**Progress accounting.** `goharness diff before.json after.json` compares two
reports by fingerprint and states what was fixed, introduced and remains. It
exits 1 when blocking evidence was introduced and 2 when a report could not be
read, which are not the verification exit codes. A supervisor that wants to
verify an agent's account of its own progress runs that rather than reading the
account.

**Why the snippet says "never route around it".** The threat model of this gate
is the operator: an agent optimising "pass with minimum effort" reaches for the
gate before it reaches for the code, and every mechanism that stops it is
documented in [docs/threat-model.md](threat-model.md). The instruction is in the
fragment because stating it up front is cheaper for everyone than having the
gate refuse the attempt afterwards.
