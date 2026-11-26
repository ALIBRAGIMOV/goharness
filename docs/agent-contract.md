# The agent contract

goharness is the completion protocol for coding agents. The interface is the
CLI: documented exit codes and one versioned JSON document. There is no
server to run and no protocol to speak. What an agent has to know, the
completion protocol, the Go engineering standard the gate enforces, the order
to read the report in, what each INCONCLUSIVE remedy means, and the routes it
must never take, ships with the binary as an agent skill.

## The skill

`goharness setup` installs the skill for the current user, where Claude
Code and Codex read skills from:

```
~/.claude/skills/goharness/SKILL.md     Claude Code
~/.agents/skills/goharness/SKILL.md     Codex
```

`goharness skill install --project` writes the same two files under the
repository root, into `.claude/skills/` and `.agents/skills/`, so that a
commit carries the protocol to every checkout and to cloud sessions that
never see a developer's home directory. This repository commits its own
copies, and a test keeps them byte-identical to the text the binary ships.

`goharness skill print` writes the skill to stdout for any other agent
harness. A copy goharness wrote is replaced by every newer release; a file
goharness did not write is left alone and named, and `--force` replaces it.
`goharness doctor` reports the state of both copies.

The skill is in the Agent Skills format: a `SKILL.md` with `name` and
`description` in its frontmatter and nothing tool-specific, so the same file
serves both agents. Its `description` is what makes an agent load it when a
task in a Go module is being finished, a report is being read, or a rule ID
comes up.

## The instruction-file fragment

For an agent that reads none of those locations, one section in the
instruction file it does read (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`) is
enough. Copy it as it is.

---

```markdown
## Completion protocol

Every task ends the same way:

    go build ./... && goharness verify --agent

Run it once, after the last edit; it already contains gofmt, vet, go fix,
tidy, golangci-lint, the tests under the race detector, benchmarks and
mutation. If the bridge you run commands through times out before a large
repository finishes, add `--report report.json` and run it detached.

The task is complete only when the verdict is ADMITTED and
`sufficientForCompletion` is true. Resolve every FAIL and every INCONCLUSIVE
claim in the JSON document. `goharness fast` is a loop aid; it is never
sufficient to finish.

## Write to the standard

Write Go to the standard the gate enforces: Effective Go, Go Code Review
Comments, Go Test Comments, Go Doc Comments, the Google Go Style Guide, and
the Uber Go Style Guide at the commit goharness pins. `goharness skill print` prints the full standard,
each line tied to the rule that checks it; `goharness explain RULE-ID` prints
what one rule defends and the compliant pattern where one exists.

## Reading the report

In `--agent` mode stdout is exactly one `goharness.report/v2` document and the
human report goes to stderr. If the run could not start, stdout is empty and
the exit code is 2, so check the exit code before parsing. Work the document
in this order:

1. `sufficientForCompletion` - the task may be called done only when it is
   true.
2. `claims[].state` - FAIL: fix it. INCONCLUSIVE: produce the evidence named
   in `claims[].missingEvidence`, which is a different job.
3. `unproducible[]` - why an obligation could not be discharged, each with the
   `remedy` that would produce it.
4. `failures[]` - a tool that could not run, with a `hint`; never a statement
   about the code.
5. `evidence[]` - already in consequence order: silent-loss, unsafe-behavior,
   structural, hygiene. Work it in that order. `blocking: false` is advisory
   or pre-existing debt and does not have to be fixed. `state` says whether
   the base revision already had the finding; `origin` says how close it sits
   to what you wrote (`added-line`, `changed-file`, `changed-package`,
   `untouched`). `new` plus `untouched` is a package the change broke without
   editing, and it blocks.
6. `evidence[].fix.command` - the exact command that closes that finding.
7. `summary.debtInChangedFiles` - pre-existing findings in files you edited,
   on lines you did not write; the repository's debt, not this change's.

`verify` renders the diff view by default: every blocking row, every new or
fixed row, every row on a line you wrote. `evidenceOmitted` counts what it
withheld, and no view withholds a blocking row. `goharness explain RULE-ID`
explains any rule; `goharness explain FINGERPRINT --report r.json` explains
one finding.

## The base revision

The change is the diff from the base revision to the working tree: the
merge-base with the default branch; HEAD when you are on the default branch
with uncommitted work; the parent commit once everything is committed. Work
on a branch or pass `--base REV` naming the commit your work started from,
and never choose a base that shrinks the change. An empty diff is
INCONCLUSIVE, not admitted.

## Never do these

- **Never write an inline suppression** (`//nolint`, `//lint:ignore`,
  `#nosec`, `//revive:disable`). They are mandatory findings that no
  configuration, exception or baseline can silence. One you add, rewrite or
  move rejects the change. Fix the code instead.
- **Never soften the gate to make a change pass.** Editing `goharness.yaml` or
  `goharness.debt.yaml` is reported as GH-POLICY-001, and a permission a
  change grants itself in the working tree is ignored and reported as
  GH-POLICY-003. If a rule is genuinely wrong, say so and stop; the exception
  is a person's commit, never yours.
- **Never weaken a test to pass it**, and never exclude a test file with a
  build constraint: the deletion is reported.
```

---

## Context for whoever adopts this

**On-ramps, for a repository that does not pass yet.** Three, in the order
they usually matter:

- `goharness fix --rule ID` applies the mechanical remediation for the rules
  whose fix a tool can state exactly. Rewrites work on parsed syntax, so a
  string literal containing the same text as a comment is untouched by
  construction. `--dry-run` prints a diff.
- `goharness audit --baseline` records today's blocking findings as
  acknowledged debt in `goharness.debt.yaml`. It is a ratchet, not a
  discount: only the committed copy counts, the ungrandfatherable core is
  never in it, and the report carries the burn-down.
- [docs/adopting-alongside-golangci.md](adopting-alongside-golangci.md) is
  the guide for a repository that already runs its own golangci-lint
  configuration.

**Progress accounting.** `goharness diff before.json after.json` compares two
reports by fingerprint and states what was fixed, introduced and remains. It
exits 1 when blocking evidence was introduced and 2 when a report could not
be read. A supervisor that wants to verify an agent's account of its own
progress runs that rather than reading the account.

**Why the fragment says "never".** The threat model of this gate is the
operator: an agent optimising "pass with minimum effort" reaches for the gate
before it reaches for the code, and every mechanism that stops it is in
[docs/threat-model.md](threat-model.md). Stating the rules up front is
cheaper for everyone than having the gate refuse the attempt afterwards.
