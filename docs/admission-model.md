# Admission model

This document is the normative description of what goharness decides and
how: the claims model, the obligations and their producers, the risk
domains, the comparison against the base revision, the report, the debt
ledger, the policy shadow, and the command surface. `docs/architecture.md`
holds the mechanism; where the two conflict, this document wins.

## The requirement

goharness exists for trustworthy admission of production-grade Go changes,
written by people or by coding agents. A change may be ADMITTED only when
every applicable quality claim has sufficient evidence. If any required
evidence cannot be produced, the result is INCONCLUSIVE; the harness never
declares a change safe by default.

There is no aggregate score. A critical failure cannot be compensated by
excellence elsewhere. The decision is a conjunction over claims, never a
weighted sum.

## Domain concepts

All live in `internal/admission` except where noted.

### TaskContract

What the change claims to accomplish. Sources, in priority order: the
`--contract FILE` flag; `goharness.task.yaml` at the repository root; the
implicit default, "this change must be admissible under the strict policy",
with no declared scope or risks.

The contract has two kinds of field. Declarations can only make the gate
stricter: a goal, a scope where the base declares none, additional risk
domains. Grants make it weaker: `allowApiBreak`, `allowPolicyEdit`, and
benchmark budgets. A change cannot widen the permissions it is judged under,
so the effective contract takes its grants from the copy committed at the
base revision, where the change could not have written them, and its
declarations from either side.

A working-tree contract asking for a grant the base does not give it gets
nothing, and the refusal is reported: the fields are listed under
`contract.ignoredGrants`, and `GH-POLICY-003` fails policy integrity so the
attempt is visible rather than silently inert. The route to a grant is the
one a person takes anyway: commit the contract in a revision that precedes
the change it authorises.

With a declared scope, files changed outside it fail the
requirements-compliance claim (`GH-SCOPE-001`). Without a contract that
claim is NOT_APPLICABLE.

### QualityClaim

One claim per applicable dimension per run: the dimension, a state (PASS,
FAIL, INCONCLUSIVE, NOT_APPLICABLE), the fingerprints of the evidence that
supports or violates it, the obligations that could not be produced, and one
sentence of reason.

- PASS: every obligation for the claim was produced and shows no
  required-severity violation.
- FAIL: at least one required-severity violation exists.
- INCONCLUSIVE: an obligation could not be produced.
- NOT_APPLICABLE: the risk profile does not activate the dimension.

### RequiredEvidence

A named obligation: a stable kind (`race-clean`, `mutation-signal`,
`bench-delta`, `api-compat`, `change-visible`, and so on), the producer that
discharges it, and the claim it supports. The plan is the closed set of
obligations; an obligation with no produced result forces INCONCLUSIVE on
its claim, never PASS.

### RiskProfile

The risk domains a change touches, derived from the change set plus the
contract's declared risks. Any hit activates the domain:

| Domain | Detection |
|---|---|
| concurrency | the diff adds or edits `go` statements, channel operations, `sync` or `sync/atomic` usage, mutex or wait-group fields |
| network | changed code uses `net`, `net/http`, `net/rpc` or gRPC import paths |
| persistence | changed code uses `database/sql` or known driver and ORM import paths; a file under a `migrations` directory changed |
| public-api | exported declarations added, removed or re-signed in a non-internal, non-main package |
| tests | any `_test.go` changed |
| hot-path | benchmarks exist in the changed packages, or the contract declares hot-path |
| dependency | `go.mod`, `go.sum`, `go.work`, `go.work.sum` or `vendor/modules.txt` changed |

Detection is AST-based on head for Go files and path-based for everything
else; every changed file reaches detection. False activation costs extra
checks; false non-activation costs trust, so detection errs toward
activation.

### VerificationPlan

Built by the risk-aware planner: start from the obligations that apply to
every change, add each active domain's obligations, map every obligation to
a check, and emit the deterministic DAG. Base checks mirror head checks with
one narrowing: the base runs a test package only where head's own run of it
produced a test failure or a leak, because those are the only rows a base
result can reclassify, and it runs them the way head did, leak detector
included. `--explain-plan` prints the plan; the report embeds it.

### AdmissionDecision

The verdict, every claim with its state and reason, the evidence set, the
unmet obligations, and `sufficientForCompletion`, which is true only for an
admission gate (`verify`, `audit`) whose verdict is ADMITTED and always
false for `fast`. The decision rule, exactly:

1. any applicable claim FAIL: REJECTED, exit 1;
2. else any applicable claim INCONCLUSIVE: INCONCLUSIVE, exit 2;
3. else ADMITTED, exit 0.

Advisory findings never change the verdict; they are reported inside the
claims that own them.

## Quality dimensions and their evidence

| Dimension | Applicability | Evidence producers |
|---|---|---|
| requirements-compliance | contract present, else N/A | scope conformance against the declared scope |
| correctness | always | compile, `go vet`, `go test`, correctness-class linters, change visibility |
| simplicity | always | native complexity, nesting and length metrics on changed functions; forwarding-layer and sole-implementation scans (advisory); `go fix` modernizers (advisory) |
| maintainability | always | maintainability deltas base/head; `go fix` migration analyzers; deprecations without a `//go:fix inline` directive (advisory) |
| architecture | always | layout policy: banned package names, internal boundaries, the project's dependency-direction rules |
| appropriate-reuse | always | native clone detection over changed code, advisory first |
| concurrency-safety | concurrency risk | `go test -race` on affected packages; the goroutine-lifecycle scan; the runtime goroutine-leak profile read by an injected `TestMain` |
| bounded-resources | concurrency or network risk | goroutine spawn in an unbounded loop, `time.After` in a loop, variable-sized buffered channels, `http.Client` without a timeout |
| reliability | always; stricter under network risk | errcheck and errorlint class, panic-in-library scan, the `go fix` address-format analyzer; network risk adds timeout, cancellation and bounded-retry scans |
| test-effectiveness | always; stricter under tests risk | `GH-TEST-*` natives; tests risk adds the anti-weakening comparison and mutation evidence |
| performance | hot-path risk | base/head benchmark comparison with `-benchmem` |
| security | always; scan under dependency risk and in audit | gosec-class linters; the embedded vulnerability scanner |
| operability | network or persistence risk | context propagation, shutdown and cleanup heuristics, resource closing |
| policy-integrity | always | the suppression scanner in every dialect, exception validity, the policy guards, generated-file edits (advisory), the worktree guard |

## Obligations by domain

- concurrency changes require race evidence, goroutine-lifecycle evidence and
  leak evidence;
- hot-path changes require base/head benchmark and allocation evidence;
- network changes require timeout, cancellation and bounded-retry checks;
- persistence changes require transaction pairing and migration evidence;
- test changes require anti-weakening and mutation evidence;
- public-API changes require compatibility evidence: an export-surface diff
  through `go/types` between base and head, where a removal or an
  incompatible signature fails unless the base contract grants
  `allowApiBreak`;
- dependency changes require vulnerability-scan evidence in `verify` as well
  as in `audit`, at base and at head, and produce `GH-DEP-001`, advisory, for
  every direct requirement head's `go.mod` carries that base's did not.

If a producer cannot run or cannot find a measurable subject, the owning
claim is INCONCLUSIVE. Missing evidence is never downgraded to PASS.

## An empty change is no change

A diff that holds nothing, in this module or outside it, produces the
`change-visible` obligation as unproducible with the reason that nothing
differs between the base revision and the working tree. The verdict is
INCONCLUSIVE and `sufficientForCompletion` is false. A document that called
an empty diff admitted would certify work the gate never saw, which is what
an agent verifying against the commit it just made, or against a tree it
never edited, would present as completion. A change that touches no Go file
is still a change: it is judged and admitted like any other. `audit` judges
the repository and is not subject to this rule.

## Mutation evidence

Scope: the functions the diff changed, located by mapping head hunks to
their enclosing declarations. The worktree is never written; mutants are
temporary files applied with `go test -overlay`.

Mutants are generated deterministically, ordered by file and offset: flipped
relational operators, negated conditions, swapped boolean literals, `return
err` replaced with `return nil`. The budget is at most sixteen mutants per
run, spread across the changed files one at a time so that a nineteen-file
change is sampled as a change rather than as its alphabetically first file,
sixty seconds per mutant and five minutes in total, with tests run only in
the mutated package and its direct importers.

Mutants go to the tests nearest them first. One kill answers the obligation,
so the near pass stops at the first kill, and the wider search over
importers runs only when nothing near any mutant noticed it. A mutant whose
wider search runs out of time is dropped rather than reported as a survivor.

Outcomes: a killed mutant is the signal that tests observe the change;
mutants surviving both passes fail test-effectiveness (`GH-MUT-001`); a
budget exhausted before any mutant ran, no tests covering the mutated
packages, or every survivor unconfirmed is INCONCLUSIVE with the reason
naming which. A mutant that did not build is neither a kill nor a survivor,
and a change where no mutant compiled is INCONCLUSIVE.

A change that edits no function body, or whose functions offer the operators
nothing to damage, has nothing a test could fail to notice: the obligation is
discharged and `coverage.mutation` records zero targets or zero mutants, so a
reader sees the shape of what was discharged. Reporting it unproducible made
a test-only change and a one-line accessor into changes nobody could finish.

## Test failures: pre-existing and flaky

A test failing at both base and head is pre-existing debt by the ordinary
comparison, identified by its package and top-level test name rather than by
its output, and does not block a change that did not cause it.

A test failing at head is re-run once, alone, before it becomes evidence. A
test that fails twice is a defect. A test that passes on the second run has
established nothing either way: it produces no evidence, the obligations
that run was carrying go unproducible with the test named, and the verdict
is INCONCLUSIVE rather than a rejection of an innocent change. Output
carrying a race detector report is exempt: a race seen once is a race.

## Goroutine-leak evidence

Where the change touches concurrency, every affected test package that does
not declare a `TestMain` receives one through a build overlay. It runs the
package's tests and, when they pass, looks up the Go runtime's
`goroutineleak` profile: a goroutine blocked on a channel, lock or select
that nothing reachable can ever wake. A non-empty profile fails the package,
and the finding (`GH-LEAK-001`) is identified by the site that started the
goroutine and carries the functions it is parked in. One site is one finding
however many packages reached it.

A package with its own `TestMain` cannot be injected. When the change
touched it, the leak obligation is INCONCLUSIVE with the remedy spelled out;
elsewhere in the closure it is a coverage gap named in
`coverage.leakInjectionBlocked`, because telling the author of a change to
edit three packages they never opened is an instruction nobody follows. A
toolchain without the profile makes the obligation unproducible with the
version named.

## Generated code

A generated file the change leaves alone is exempt from every scanner. A
generated file the change rewrote is judged in full, because the marker is a
claim its author controls; the edit itself is reported as `GH-POLICY-002`,
advisory, worded as what was observed and no more.

No delta is computed across generated code. A function there is identified
by a name the generator chose, and regeneration renumbers names, so a
maintainability delta between two functions that are not the same function
is not a measurement. Maintainability deltas and duplication pass over files
carrying the header.

## Anti-weakening evidence

The comparison over changed test files measures the shape of every test at
both revisions: how many times it can fail, whether it skips, and the
numeric bounds it asserts. Assertions removed (`GH-WEAK-001`), a skip added
(`GH-WEAK-002`), a test deleted (`GH-WEAK-003`) and a tolerance widened
(`GH-WEAK-004`) are required violations; a renamed or rewritten test that
moves its assertions rather than removing them is not.

A test file is measured as the build the gate runs sees it. One a build
constraint excludes, by a `//go:build` line or by a platform suffix in its
name, runs no tests, so its functions are not shapes of the suite whatever
the file says; a constraint typed above a failing test is the test's
deletion, and is reported as one.

## Benchmark evidence

Benchmarks run in the packages the change edited, not across the closure,
at base and head, with `-benchmem`, a fixed `-benchtime` of 100ms and three
samples each, interleaved between the two revisions so that the machine's
load cannot masquerade as a regression.

Time is a regression only when the medians differ by more than the budget
(default 15%) and the budget is still exceeded under the most conservative
pairing the samples permit, head's fastest against base's slowest. Allocation
counts are deterministic, so the budget alone decides there (default 10%).

A benchmark that panics or fails is named from the event stream, skipped,
and its package run again, so one broken benchmark costs its own measurement
rather than every measurement of its package. One that fails at both
revisions is reported as `GH-PERF-003`, advisory, and the benchmarks that run
judge the change; one that ran at base and fails at head is the change's
doing, and the claim is INCONCLUSIVE naming it.

## Scopes and commands

- `goharness verify`: change admission. The diff plus its reverse-dependency
  closure, base/head comparison, the full claims model. The command an agent
  finishes with.
- `goharness audit`: repository audit. The whole codebase at head, every risk
  domain active, the vulnerability scan and repository-wide race detection,
  no base comparison. `--baseline` records the run's blocking findings as
  acknowledged debt after the run completes.
- `goharness fast`: a developer-loop aid over changed packages and their
  direct dependents. It never produces an admission decision; its JSON
  carries `sufficientForCompletion: false`.

### The base revision

The base is an explicit `--base`; else the merge-base with the default
branch; else, when HEAD is on the default branch and the working tree
carries uncommitted work, HEAD itself; else the parent commit. On a shared
clone the commit before HEAD is somebody else's work, and judging it as part
of the working tree blamed a change for debt it never wrote. The report
records which rule applied under `change.baseOrigin`.

### Narrowing the directory-local checks

A package directory whose judged files are byte-identical at base and head
produces identical findings from any check that reads only that directory,
and identical findings pair in the comparison. In `verify`, and only where a
comparison will happen, such a check examines only the directories the
change touched, on both sides. Two conditions bound this: the check must
read one directory and nothing else, and none of its rules may be
ungrandfatherable. Which leaves the metrics scan, `gofmt` and `goimports`;
`goimports` narrows only when `go.mod` and `go.sum` are untouched. The base
side is handed the head run's answer, and a moved file is two directories.

### Renames

The change set keeps the source path git reports for a rename, and the base
evidence set is realigned into head's coordinates before the two are
compared. A move whose source lies outside the module is an addition. The
base test scope follows renames too.

## The agent completion protocol

An agent must never finish after only `fast`. Completion requires:

    goharness verify --agent

`--agent` emits the decision as one `goharness.report/v2` JSON document on
stdout, moves the human report to stderr, sets `sufficientForCompletion`
true only for an ADMITTED admission gate, and includes the full claim table.
Exit codes are unchanged. The protocol ships as an agent skill (see
`docs/agent-contract.md`), installed by `goharness setup` for the current
user and by `goharness skill install --project` for a repository.

The document carries what a repair loop needs without a second command:
`blocking` on every finding; every undischarged obligation under
`unproducible` with its reason and remedy; `contract.authenticated` and
`ignoredGrants`; `fix.command` where a tool can state the fix, for the
mechanical rules and every `GO-FIX-*` finding; `coverage.mutation`; and
`summary.debtInChangedFiles`.

## Report-to-report comparison

`goharness diff OLD.json NEW.json` compares two reports on fingerprint
identity and emits the `goharness.diff/v1` document. It reads no repository,
no git history, no cache and no network. It reports what was fixed,
introduced and remaining, blocking split from advisory, grouped by
consequence class and rule, with the verdict transition and every claim that
moved. Its exit codes are its own: 0 when nothing blocking was introduced, 1
when it was, 2 when a report could not be read. Reports of different
modules or modes are compared with `subjectMismatch: true`; reports of
different evidence scopes are refused unless `--allow-scope-mismatch`,
because that comparison is arithmetic rather than a burn-down.

## The shape of the document

**Consequence classes.** Every rule carries one of `silent-loss`,
`unsafe-behavior`, `structural`, `hygiene`, and every finding carries its
rule's class. `evidence[]` is sorted by class before rule, file, line and
fingerprint, so position is triage order. The class is triage data and
never verdict data.

**Remedy classes.** Where one rule covers several remedies, the finding
carries `remedyClass`; `GCL-errcheck` is the standing case, where the callee
names the remedy and anything unrecognised is `domain-write`, a lost write
nothing observes.

**`summary`.** Counts over the whole final evidence set: `total`,
`blocking`, `advisory`, `new`, `preexisting`, `fixed`, the maps
`byConsequence`, `byRule`, `byDimension`, `byRemedyClass`, `byFile`, and
`debtInChangedFiles`, the pre-existing advisory findings per edited file on
lines the change did not write.

**`coverage`.** What the verdict rests on: the packages and files judged,
the generated files exempted, the test packages, `leakInjectionBlocked`,
`localScanNarrowed` with the directories examined, `baseTestPackages`, and
`mutation` with the targets, mutants, runs, kills, survivors, unbuilt and
timed-out counts. A verdict whose scope is invisible is not auditable.

**Two axes on every finding.** `state` says whether the base revision
already carried it: `new`, `preexisting`, `fixed`, or empty where no
comparison happened. `origin` says how close it sits to the code the change
wrote:

| origin | meaning |
|---|---|
| `added-line` | the line falls inside a `+` hunk of the diff |
| `changed-file` | the file is in the diff, the line predates the change |
| `changed-package` | the package holds a changed file, this file is not one |
| `untouched` | anywhere else in the reverse-dependency closure |
| empty | there was no diff to attribute against |

The axes are orthogonal. `new` plus `untouched` is a package the change
broke without editing, and it blocks. `preexisting` plus `changed-file` is
debt in a file the author is in, counted and not shown. A finding with no
file is placed by its package's directory. A finding the run cannot place
stays unattributed, and everything downstream treats unattributed as the
change's. `origin` never enters a fingerprint. A repository-wide run places
nothing: an audit answers for the repository, and its origins are empty.

**Rendered views.** `--evidence` selects the rows `evidence[]` carries and
`evidenceScope` records the answer:

| mode | carries |
|---|---|
| `full` | every finding the run produced |
| `diff` | everything blocking, everything `new` or `fixed`, everything on an added line, and anything unattributed |
| `new` | everything blocking, plus `new` and `fixed` |
| `top` | `full`, cut to `--evidence-limit` (default 100) in consequence order |

`verify` defaults to `diff`; `audit` and `fast` default to `full`.
`evidenceTruncated` and `evidenceOmitted` are always present. No view ever
drops a row whose `blocking` is true, so a view changes how much a reader
reads and never what they have to fix, and every omitted row stays
addressable through `goharness explain FINGERPRINT --report FILE`.

## What blocks

    blocking = required && (state == new
                            || state == uncompared
                            || (state == preexisting
                                && ungrandfatherable
                                && origin is added-line or unattributed))

A required finding blocks unless the base revision already carried it. The
ungrandfatherable core, the four suppression rules, the two policy guards
and `GH-COMMENT-001`, blocks on a pre-existing finding too, but only on a
line the change wrote. A suppression the change adds is new and blocks
wherever it is; one it rewrites or moves sits on an added line and blocks;
one it leaves as it found it is the repository's debt, reported beside the
change, counted per file, and rejected by an audit, where no ledger may
acknowledge it. Enforcing the core across every file a change opened made a
legacy repository unable to admit anything: the author of a change could
neither fix a directive they did not write nor except it, because the
exception is a policy edit no change may grant itself.

## Identity a producer states

A finding is named by its message reduced to the part that says which
finding it is. That is right for a scanner whose message is the finding and
wrong for a producer whose message carries a timestamp, a goroutine dump or
a generated key. `evidence[].identity` is what such a producer states, and
the fingerprint uses it in place of the message: a test failure is its
package and top-level test, a leak is its site, an API break is its symbol,
a broken benchmark is its package and name. The volatile text stays in
`message`.

## Mechanical fixes

Where the harness can perform a rule's remediation itself, the finding
carries `fix.command` naming `goharness fix --rule ID`, beside the `gofmt`,
`goimports`, `go mod tidy` and `GO-FIX-*` commands that already appear
there. `goharness fix` is a write command: no verification command can
reach it, its rewrites work on parsed syntax so string literals are
untouched by construction, `--dry-run` prints a diff, and admission
re-verifies afterwards. A fix is a convenience, never evidence.

## The acknowledged-debt ledger

`goharness.debt.yaml` at the module root, in a restricted shape with its own
parser: `schema: 1`, `recordedAt: <revision>`, then `entries:` of
`fingerprint` with `rule` and an optional `file`. Unknown keys are an error.

`goharness audit --baseline` runs the audit and then writes the file, in the
command layer, after the run has returned; the exit code is the audit's own.
An INCONCLUSIVE run records nothing, because its finding set is not a
complete enumeration. Only the copy committed at HEAD has any effect; the
working-tree copy is read by nothing, and the file is a policy file for
`GH-POLICY-001`, so the commit that records it is visible to review. A
finding the committed ledger names is marked `preexisting` and nothing else
changes, which is why an entry for an ungrandfatherable rule has no effect
whatever it says. `verify` ignores the ledger: it has a real base revision.
An audit that read a ledger carries a `baseline` block with `recordedAt`,
`entries`, `stillPresent`, `fixedSince`, `new` and `unbaselineable`, and the
text report prints the burn-down on one line.

## The policy shadow

An audit of a repository that carries its own `.golangci.yml` or
`.golangci.yaml` emits an additive `policyShadow` block: what that
configuration hides from itself, measured against the strict pack, with
counts attributed from the run's own evidence. It is a report section and
never a claim: the same tree with and without a configuration reaches the
same verdict. Only positively recognised shapes are reported (linters the
strict pack requires that the configuration disables, exclusion rules aimed
at test files, `errcheck` without `check-blank`); silence means "not
detected", never "not present". `docs/adopting-alongside-golangci.md` is the
operator-facing companion.

## Coordinates and invocation invariance

Every path leaving `internal/change` is module-relative, in slash form. Git
is asked for repository-relative paths and the module prefix is stripped
once, at ingestion; the prefix comes from `git rev-parse --show-prefix`. A
changed file the repository contains and the module does not is reported
under `change.outsideModule`.

Evidence is a function of (repository, revision, policy, database). No
check reads process-global state. The toolchain that judges the standard
library is resolved once through the runner, in the module, under the
sanitised environment, recorded as `versions.goStdlib` and keyed into the
base-evidence cache. Below the module's declared toolchain floor the
vulnerability obligation goes unproducible naming both versions.

## A tool fault is never a code fact

A deliberate toolchain exclusion and an unresolvable path leave a check
through different channels. The first is a coverage gap reported against the
repository. The second ends the check as a failure attributed to goharness,
and the obligation it leaves says so and points at `failures[]`. A check the
run's own deadline cut short is attributed to goharness, names the check,
and says what to raise.

## Pack coherence: proven-error-free encodes

The strict pack enables `errcheck` with `check-blank`, so a discarded
`_ = json.Marshal(v)` is a required finding. goharness does not enable
`errchkjson` and will not special-case it: suppressing one linter on the
strength of another's proof is reasoning the configuration cannot express.
The compliant shape is a helper that owns the check once; a repository that
prefers the discards records a scoped, expiring exception for
`GCL-errcheck`. What it must not do is add an inline suppression.

## Diagnostics

Diagnostic logging uses `log/slog`. The logger is constructed once in
`internal/cli` and injected explicitly; no package-level logger. Stdout is
reserved for reports; every log line goes to stderr. The default level is
WARN; `-v` enables INFO (per-check start and finish with durations), `-vv`
DEBUG (commands, scope sizes); `--log-json` switches the handler from text
to JSON. Attributes are structured (`slog.String("check", ...)`), never
formatted into the message, and the scheduler logs through `LogAttrs` so a
disabled level costs no allocation. Logging is diagnostics only: nothing
decision-relevant exists solely in a log.

## Process lifecycle

- The root context comes from `signal.NotifyContext` on SIGINT and SIGTERM;
  every check, runner and external process hangs off it, and the reason an
  interrupted run reports names the signal.
- External commands use `exec.CommandContext` with `Cmd.Cancel` sending
  SIGINT first, `Cmd.WaitDelay` escalating to SIGKILL, and their own process
  group, so linter workers and test children die with the parent.
- On the first signal: cancel, drain in-flight checks, run the cleanup
  stack, then report INCONCLUSIVE and exit 2. A second signal aborts
  immediately with exit 130; `doctor` reports a worktree that abort left
  behind and offers the removal command.
- `--timeout` (default 20m for `verify`, unlimited for `audit`) maps
  `context.DeadlineExceeded` to INCONCLUSIVE for the owning claim, never to
  REJECTED; the worktree guard runs on its own short deadline afterwards so
  a timed-out run still states the true worktree state.
- `--jobs N` bounds how many checks run at once.

## CLI

- `goharness` with no arguments prints structured help: purpose, command
  table, flags, the exit-code table, the agent protocol, two examples.
- Every command supports `-h` with a usage line, flag documentation and
  examples; `goharness help contract` documents the task contract.
- Unknown commands and rule IDs suggest the nearest valid name.
- Colour on a TTY only; `NO_COLOR` and `--no-color` disable it. Progress on a
  TTY for long phases, erased before the final report; `--quiet` reduces
  output to the verdict line.
- The human report leads with the verdict, the claim table, the evidence
  counts, the slowest checks past a minute, the mutation line, the scope
  note and the debt line, then findings grouped by claim, then the smallest
  set of actions that would flip each failing claim.
- `doctor` prints a check table with an exact remediation per failure, and
  exits 2 when it found one.
- `--json` is available on every verifying command and is schema-stable;
  timing lives in a dedicated block excluded from determinism comparisons.
