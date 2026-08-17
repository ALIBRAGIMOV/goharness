# goharness Admission Model (v0.5)

Status: accepted. Extends `docs/architecture.md`. Where the two conflict,
this document wins.

## Core product requirement

The goal of goharness is not lint orchestration or isolated anti-pattern
detection. The goal is trustworthy admission of production-grade Go changes
created by humans or coding agents.

A change may be ADMITTED only when every applicable quality claim has
sufficient evidence. If any required evidence cannot be produced, the result
is INCONCLUSIVE; goharness never declares a change safe by default.

There is no aggregate quality score. A critical failure cannot be
compensated by high scores in other dimensions. The decision is a pure
conjunction over claims, never a weighted sum.

## Domain concepts

All live in `internal/admission` (new package) except where noted.

### TaskContract

What the change claims to accomplish. Sources, in priority order:

1. `--contract <file>` flag;
2. `goharness.task.yaml` at the repo root;
3. the implicit default contract: "this change must be admissible under the
   strict policy" with no declared scope or risks.

Grants are read from the base revision alone (normative). The contract has two
kinds of field. Declarations can only make the gate stricter: a goal, a scope
where the base declares none, additional risk domains. Grants make it weaker:
`allowApiBreak`, `allowPolicyEdit`, and benchmark budgets. A change cannot widen
the permissions it is judged under, so the effective contract takes its grants
from the copy committed at the base revision (`git show <base>:...`), where the
change under verification could not have written them, and its declarations from
either side.

A working-tree contract asking for a grant the base does not give it gets
nothing, and the refusal is reported: the fields are listed in the contract block
of the report as `ignoredGrants`, and `GH-POLICY-003` fails policy integrity so
the attempt is visible rather than silently inert. The route to a grant is
therefore the one a human takes anyway: commit the contract in a revision that
precedes the change it authorises.

Fields: `Goal` (free text, recorded in the report), `DeclaredScope`
(path/package globs the change is allowed to touch), `DeclaredRisks`
(explicit risk domains, merged into the detected RiskProfile),
`PerformanceBudget` (optional per-benchmark time/alloc regression limits),
`AllowAPIBreak` (bool, default false).

With a declared scope, files changed outside it fail the
requirements-compliance claim. With no contract, requirements compliance is
NOT_APPLICABLE except for scope sanity that always applies (the diff must
not touch goharness policy files while claiming otherwise; see policy
integrity).

### QualityClaim

One claim per applicable quality dimension per admission run:

- `Dimension` (one of the fourteen below);
- `State`: PASS, FAIL, INCONCLUSIVE, or NOT_APPLICABLE;
- `EvidenceRefs`: fingerprints of supporting or violating Evidence;
- `MissingEvidence`: the RequiredEvidence kinds that could not be produced;
- `Reason`: one human sentence explaining the state.

State semantics:

- PASS: every RequiredEvidence kind for this claim was produced and shows
  no required-severity violation;
- FAIL: at least one required-severity violation exists;
- INCONCLUSIVE: a RequiredEvidence kind could not be produced (tool crash,
  missing benchmark coverage, mutation budget exhausted before signal);
- NOT_APPLICABLE: the RiskProfile does not activate this dimension for this
  change.

### RequiredEvidence

A named evidence obligation: `Kind` (stable identifier, e.g.
`race-clean`, `mutation-signal`, `bench-delta`, `api-compat`), `Producer`
(which check produces it), `Claim` (dimension it supports). The
VerificationPlan is the closed set of obligations; an obligation with no
produced result forces INCONCLUSIVE on its claim, never PASS.

### RiskProfile

The set of risk domains a change touches, derived mechanically from the
ChangeSet plus DeclaredRisks. Detection rules (any hit activates the
domain):

| Domain | Detection |
|---|---|
| concurrency | diff adds or edits `go` statements, channel operations, `sync`/`sync/atomic` usage, mutex/waitgroup fields |
| network | changed code uses `net`, `net/http`, `net/rpc`, grpc import paths |
| persistence | changed code uses `database/sql` or known driver/ORM import paths; files under a `migrations` directory changed |
| public-api | exported declarations added, removed, or signature-changed in non-internal, non-main packages |
| tests | any `_test.go` changed |
| hot-path | benchmarks exist in affected packages, or the contract declares hot-path |

Detection is AST-based on head, restricted to changed files and their
enclosing declarations. False activation costs extra checks; false
non-activation costs trust, so detection errs toward activation.

### MaintainabilityDelta

Base/head comparison of mechanical maintainability metrics over changed
functions and packages: cyclomatic complexity, function length, nesting
depth, exported-symbol doc coverage, package fan-in/fan-out. Computed
natively (AST) at both snapshots. Degradation beyond hard thresholds
(complexity +10 or absolute > 25 on a changed function; nesting > 5) is a
required violation; smaller degradation is advisory evidence. Improvement
is recorded as supporting evidence.

### VerificationPlan

Supersedes ExecutionPlan as the top-level plan type (ExecutionPlan remains
the runnable DAG inside it). Built by the risk-aware planner:

1. start from the base obligations that apply to every change;
2. for each active risk domain, add its RequiredEvidence obligations;
3. map every obligation to a Check;
4. emit the deterministic DAG (compile precedes everything that needs a
   built package; base snapshot checks mirror head checks).

The plan is printed with `--explain-plan` and embedded in the JSON report
so a reviewer can see why each check ran.

### AdmissionDecision

Replaces the bare verdict. Contains the final verdict, every QualityClaim
with its state and reasons, the evidence set (new/preexisting/fixed), the
unmet obligations, and `sufficientForCompletion` (true only for
`verify`/`audit`, always false for `fast`).

Decision rule, exactly:

1. any applicable claim FAIL => REJECTED (exit 1);
2. else any applicable claim INCONCLUSIVE => INCONCLUSIVE (exit 2);
3. else (all applicable claims PASS) => ADMITTED (exit 0).

Advisory findings never change the verdict; they are reported inside the
claims that own them.

## Quality dimensions and their evidence

| Dimension | Applicability | Evidence producers |
|---|---|---|
| requirements-compliance | contract present (else N/A) | scope conformance scan against DeclaredScope |
| correctness | always | compile, go vet, go test, correctness-class linters, change-visibility scan |
| simplicity | always | native complexity/nesting/length metrics on changed functions, forwarding-layer and sole-implementation scans (advisory), `go fix` modernizers (`fix-scan`, advisory) |
| maintainability | always | MaintainabilityDelta base/head, `go fix` migration analyzers (`inline-migration`: calls of APIs marked `//go:fix inline`, obsolete `+build` lines), deprecated declarations left without a `//go:fix inline` directive (advisory) |
| architecture | always | layout policy (banned package names, internal boundary violations, dependency direction rules from config) |
| appropriate-reuse | always | duplication detection on changed code (dupl-class linter plus native diff-local clone scan), advisory-first |
| concurrency-safety | concurrency risk | `go test -race` on affected packages (required evidence), goroutine lifecycle scan (goroutine launched without ctx/done/WaitGroup path), and runtime goroutine-leak evidence: an embedded pinned goleak is injected into every affected test package through a build overlay, with zero user setup. A package that already declares TestMain cannot be injected; its leak obligation is INCONCLUSIVE with the remedy spelled out, never a silent pass |
| bounded-resources | concurrency or network risk | native scans: goroutine spawn in unbounded loop, `time.After` in loop, unbounded buffered channels from variable sizes, missing `http.Client` timeout |
| reliability | always; stricter under network risk | errcheck/errorlint class, panic-in-library scan, `go fix` address-format analyzer (`dial-address`); network risk adds timeout, cancellation (noctx-class), and bounded-retry scans |
| test-effectiveness | always; stricter under tests risk | GH-TEST-* natives; tests risk adds anti-weakening diff and mutation evidence |
| performance | hot-path risk | base/head benchmark comparison with -benchmem |
| security | always | gosec-class linters; audit scope adds govulncheck |
| operability | network or persistence risk | context propagation, shutdown/cleanup heuristics, resource closing (bodyclose/sqlclosecheck class) |
| policy-integrity | always | suppression scanner (every dialect: `//nolint`, `//lint:ignore`, `//lint:file-ignore`, `#nosec`, `//revive:disable*`), exception validity (owner, unexpired), config-tamper check (mandatory rules not disabled), policy-guard (a diff touching `goharness.yaml` or the task contract fails unless the contract itself records `allowPolicyEdit: true`; hand-edited generated files are flagged advisory), worktree read-only guard |

## Risk-aware planner obligations (normative)

- concurrency changes require race evidence and goroutine lifecycle
  evidence;
- hot-path changes require base/head benchmark and allocation evidence;
- network changes require timeout, cancellation and bounded-retry checks;
- persistence changes require transaction-handling and migration evidence
  (v0.2 mechanical form: sql.Tx begin/commit-or-rollback pairing scan;
  changed migration files must be additive and ordered);
- test changes require anti-weakening and mutation evidence;
- public API changes require compatibility evidence (native export-surface
  diff via go/types between base and head; removals or incompatible
  signature changes fail unless the contract sets AllowAPIBreak).

If an obligation's producer cannot run or cannot find a measurable subject
(no benchmark covers a declared hot path, no test exercises a mutated
package), the owning claim is INCONCLUSIVE. Missing evidence is never
downgraded to PASS.

## Mutation evidence (bounded, overlay-based)

Scope: functions changed by the diff, located by mapping head diff hunks to
enclosing FuncDecls. The engine never rewrites the worktree; mutants are
materialized as temp files applied with `go test -overlay`.

Deterministic mutant generation, ordered by (file, offset): flip relational
operators, negate branch conditions, swap boolean literals, replace
`return err` with `return nil` in error-returning paths. Budget: at most 16
mutants per run, 60s per mutant, 5 minute total; tests run only in the
mutated package and its direct importers, `-count=1`.

Mutants are offered to the tests nearest them first: the mutated package's own
suite, or its importers when the package has no tests of its own. One kill
answers the obligation, so the wider search over the importing packages runs
only when nothing near the mutant noticed it. The order matters more than it
looks: on a repository whose integration tests take minutes, searching wide per
mutant spends the whole budget on compilation and reports INCONCLUSIVE for a
suite that was in fact watching. A mutant whose wider search runs out of time is
dropped rather than reported as a survivor, because accusing a suite of weakness
on the strength of a search that did not finish is an accusation the run cannot
support.

Outcomes: any mutant killed by a test is signal that tests observe the change;
mutants surviving both passes fail test-effectiveness (weak-test evidence);
budget exhausted before any mutant ran, no tests covering the mutated package,
or every survivor left unconfirmed, is INCONCLUSIVE for test-effectiveness with
the reason naming which of those it was.

## Test failures: pre-existing and flaky (normative)

Two failures that are not the change's fault must not be reported as if they
were, or the gate loses the authority it needs.

A test failing at both base and head is pre-existing debt by the ordinary
fingerprint comparison, and does not block a change that did not cause it.

A test failing at head is re-run once, alone, before it becomes evidence. A test
that fails twice is a defect. A test that passes on the second run has
established nothing either way: it produces no evidence, and the obligations
that run was carrying (`tests-pass`, and `race-clean` when the run was a race
run) go unproducible with the test named, so the verdict is INCONCLUSIVE rather
than a rejection of an innocent change. Output carrying a race detector report is
exempt from this: a race seen once is a race whether or not the second run
happens to schedule it the same way.

## Anti-weakening evidence

Base/head diff over changed test files: assertions or error checks removed
without the exercised production code being removed; `t.Skip` added;
numeric tolerances widened; test functions deleted while their subject
survives. Hard signals are required violations; soft signals are advisory.

A deleted test is reported only where its package came out of the change able to
fail fewer times than it went in. Renaming or rewriting a test moves its
assertions rather than removing them, and a gate that called that weakening
would make every honest test refactor a rejection.

## Benchmark evidence

Benchmarks in affected packages run at base and head with `-benchmem` and a
fixed `-benchtime` of 100ms, three samples each. The budget is time rather than
an iteration count: a fixed count starves a nanosecond-scale benchmark of the
repetitions it needs to mean anything, and hands a second-scale one a bill of
minutes.

Sampling alternates between the two revisions rather than measuring one and then
the other. A machine's load drifts over the minutes a comparison takes, and
measuring the sides in sequence turns that drift into a regression report for
every benchmark at once, which is exactly what the corpus run produced before
this was fixed.

Time is only a regression when the medians differ by more than the contract
budget (default 15%) *and* the two sample ranges do not overlap: the fastest run
at head must still be slower than the slowest run at base. Timing a
nanosecond-scale benchmark on a machine doing anything else swings by tens of
percent, and a gate that rejected a change over one of those would teach its
users to ignore it. Allocation counts are deterministic, so the budget alone
decides there (default 10%). Inside noise is PASS with the delta recorded;
unmeasurable is INCONCLUSIVE.

## Scopes and commands

Two verification scopes:

- change admission (`goharness verify`): diff plus affected reverse
  dependency graph, base/head evidence comparison, full claims model;
- repository audit (`goharness audit`): the complete codebase at head, all
  always-on dimensions plus every risk domain treated as active, adds
  govulncheck and -race repo-wide. `deep` becomes an alias for `audit` and
  prints a deprecation note.

`fast` remains a developer/editor loop aid. It never produces an
AdmissionDecision: its report and exit text state explicitly that it is not
an admission gate, and its JSON carries `sufficientForCompletion: false`.

## Agent completion protocol

An agent must never finish a task after only `fast`. Successful completion
requires:

    goharness verify --agent

`--agent` emits the AdmissionDecision JSON on stdout (human text moves to
stderr), sets `sufficientForCompletion: true` only when the verdict is
ADMITTED, and always includes the full claim table so the agent can act on
FAIL and INCONCLUSIVE claims individually. Exit codes are unchanged
(0/1/2). Documentation and `fast` output both direct agents to this
command.

The document carries what a repair loop needs without a second command:

- every finding says whether it blocks (`blocking`), so a consumer never has to
  re-derive the grandfathering rules to know what to fix first;
- every obligation the run could not discharge appears under `unproducible`
  with its reason and the action that would produce it, which is what makes an
  INCONCLUSIVE verdict actionable rather than merely honest;
- the contract block reports `authenticated` and `ignoredGrants`, so an agent
  can see that a permission it asked for did not apply and why;
- a finding whose fix a tool can state rather than guess carries `fix`, an
  object with the exact `command` that closes it and a one-line `summary`. It
  is present for the mechanical rules (`gofmt`, `goimports`, `go mod tidy`) and
  for every `GO-FIX-*` finding, where the toolchain computed the replacement
  before reporting it. An agent runs that command instead of inventing an edit;
  the field carries no positions or patch text, so it cannot make two runs of an
  unchanged tree differ, and it is not part of the fingerprint.

### Machine-applicable evidence (`GO-FIX-*`)

`go fix` (Go 1.26 and later) is a suite of analyzers that prove a finding by
producing the edit that closes it. The harness runs it with `-json`, which
reports the diagnostics and their edits without touching the tree, and takes
only the diagnostics that carry an edit: what makes the suite precise enough to
report is the replacement it offers, and a diagnostic without one is the
analyzer saying it cannot help here.

One analyzer of the suite is not a modernizer. `inline` acts on `//go:fix
inline` directives, which an author puts on a deprecated function or constant
to declare that call sites can migrate mechanically. That turns a deprecation
from a notice every caller reads into a migration every caller can perform with
one command, in this module and in every consumer of it. The harness reports
both sides of that mechanism: `GO-FIX-inline` for a call that has not migrated,
and `GH-DEPRECATE-001` for a deprecation whose replacement is a single call or
value but which carries no directive.

All `GO-FIX-*` rules and `GH-DEPRECATE-001` enter advisory and experimental.
They become required on corpus evidence, never on a fixture written to make
them fire.

## Structured logging (zap)

Diagnostic logging uses `go.uber.org/zap`. Rules:

- the logger is constructed once in `internal/cli` and injected explicitly
  through constructors; no package-level logger, no `zap.L()`, no
  `zap.ReplaceGlobals`;
- stdout is reserved for reports; every log line goes to stderr;
- default level is WARN; `-v` enables INFO (per-check start/finish with
  durations), `-vv` enables DEBUG (commands executed, argv, scope sizes);
  `--log-json` switches the encoder from console to JSON;
- in `--agent` mode the console encoder is disabled and the level defaults
  to WARN so stdout stays machine-parseable and stderr stays quiet;
- log fields are structured (`zap.String("check", ...)`,
  `zap.Duration("elapsed", ...)`), never formatted into the message;
- logging is diagnostics only: no verdict, evidence, or claim data may exist
  solely in logs; everything decision-relevant lives in the report.

## Process lifecycle and graceful shutdown

The harness runs external processes and materializes temp state; it must be
interrupt-safe and leak-free:

- the root context comes from `signal.NotifyContext` on SIGINT and SIGTERM;
  every check, runner, and external process hangs off it;
- external commands use `exec.CommandContext` with `Cmd.Cancel` sending
  SIGINT first, `Cmd.WaitDelay` (5s) escalating to SIGKILL, and
  `SysProcAttr{Setpgid: true}` so process groups (golangci-lint workers,
  go test children) die with the parent;
- on the first signal: cancel, drain in-flight checks, run the cleanup
  stack (temp dirs, `git worktree remove --force`), then report
  INCONCLUSIVE with reason "interrupted" and exit 2 - an interrupted
  verification never claims safety;
- a second signal aborts immediately with exit 130; cleanup for that case
  is a best-effort deferred pass plus stale-worktree detection on the next
  run (`goharness doctor` reports and offers the removal command);
- a global `--timeout` flag (default 10m for verify, unlimited for audit)
  and per-check deadlines map `context.DeadlineExceeded` to INCONCLUSIVE
  for the owning claim, never to REJECTED;
- every check goroutine runs under a recover guard: a panicking check is
  converted to a CheckFailure (INCONCLUSIVE), never a harness crash.

## CLI user experience (normative)

The CLI is a product surface, not a script wrapper:

- `goharness` with no arguments prints structured help: one-line purpose,
  command table, common flags, exit-code table (0 ADMITTED, 1 REJECTED,
  2 INCONCLUSIVE, 130 aborted), two realistic examples, and the agent rule
  ("agents: finish only after goharness verify --agent");
- every command supports `-h` with a usage line, flag docs, and examples;
- unknown commands and rule IDs suggest the nearest valid name
  (edit-distance); misuse errors say what to type, not just what failed;
- color on TTY only: verdicts (green/red/yellow), rule IDs dimmed, file
  positions underlined; `NO_COLOR` env and `--no-color` disable; output to
  a pipe is always plain;
- progress on TTY for long phases: transient per-check status lines
  (`[4/11] golangci-lint … 3.8s`) that are erased before the final report;
  never emitted when stdout is not a TTY; `--quiet` reduces output to the
  verdict line;
- the human report leads with the verdict, claim summary (per-dimension
  states), evidence counts (new / preexisting / fixed), and total duration;
  findings are grouped by claim, each rendered as
  `RULE-ID file:line message` with a closing hint
  `run: goharness explain RULE-ID`;
- REJECTED reports end with a "next steps" section: the smallest set of
  actions that would flip each failing claim; INCONCLUSIVE reports state
  exactly which evidence was unproducible and how to make it producible;
- `doctor` prints a check table with pass/fail marks and an exact
  remediation command per failure (including the pinned install command for
  golangci-lint v2.12.2), plus stale-worktree and PATH diagnostics;
- `--json` is available on every verifying command and is schema-stable;
  timing fields live in a dedicated block excluded from determinism
  comparisons.

## Go craft requirements

Use the language fully; every construct below is expected where it applies:

- context as the first parameter of every function that blocks, runs a
  subprocess, or can be cancelled; no context stored in structs;
- `errors.Is`/`errors.As` at every failure branch that discriminates;
  sentinel errors exported only where a consumer must branch on them;
  every wrap adds context (`fmt.Errorf("loading package graph: %w", err)`);
- structured concurrency only: errgroup + weighted semaphore, results
  returned by value to the coordinator, no goroutine outlives its caller's
  context, and every goroutine's termination path is visible at the launch
  site (the harness must satisfy its own goroutine-lifecycle rule);
- `sync.OnceValue`/`OnceValues` for lazy singletons (tool discovery, module
  info) instead of mutex-guarded init flags;
- generics for the typed set/diff operations in evidence comparison and for
  the claim-state algebra; no `interface{}` in exported signatures;
- `slices` and `maps` stdlib packages for sorting and set work; iterators
  (range-over-func) where they make evidence streaming clearer, not as
  decoration;
- functional options only for the two genuinely variadic constructors
  (scheduler, report renderer); plain structs elsewhere; useful zero
  values throughout;
- `t.Parallel()` in unit tests where isolation allows; race detector clean;
  benchmarks for fingerprinting and the scheduler hot path;
- no `init()` functions, no package-level mutable state, no `panic` outside
  `main`'s last-resort handler; assertions with comma-ok everywhere a type
  assertion can fail.
