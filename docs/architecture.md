# Architecture

This document records the pinned versions and the architecture decisions the
code holds to. Where it and the code disagree, one of them is wrong and
either is a defect. `docs/admission-model.md` holds the claims model and the
report; `docs/toolchain.md` holds provisioning; `docs/philosophy.md` holds
the reasons.

## Pinned versions

| Component | Pin | Rationale |
|---|---|---|
| Go toolchain | `go 1.27` in `go.mod`, `toolchain go1.27.0` | The harness needs `encoding/json/v2`, `os.Root`, `go/version`, the `goroutineleak` runtime profile, and the `go fix` analyzer suite. The repository under test may declare any Go version; the host must run the harness's. |
| golangci-lint | `2.13.2`, exact, never `latest` | Run as an external executable only; its GPL-licensed internals are never imported or linked. Every candidate binary is verified against a pinned per-platform sha256. |
| `golang.org/x/vuln` | `v1.7.0`, exact, in `go.mod` | The vulnerability scanner, in-process, against a local database snapshot. No govulncheck binary, no PATH probe. |
| Goroutine-leak evidence | the Go runtime's `goroutineleak` profile, from the toolchain above | Read by a `TestMain` the harness injects into race runs through a build overlay. Nothing is vendored for it and nothing is installed. |
| Uber Go Style Guide | commit `1d60a91aa5e87d443002e23c21903c49489dbde5` of `github.com/uber-go/guide` | Versioned policy source. Never fetched at runtime; a checked-in registry references this commit. |
| JSON report schema | `goharness.report/v2` | Versioned so consumers can detect breaking changes. Fields are added, never renamed or removed, within a schema version. |

Every pin is a constant in the code, embedded in every JSON report, and
enforced at runtime: a linter that does not match is refused, and the
obligations it owned go INCONCLUSIVE with `goharness setup` as the remedy.
Changing a pin changes this document in the same commit.

## Module and dependencies

- Module path: `github.com/ALIBRAGIMOV/goharness`.
- CLI: standard library `flag` with hand-rolled subcommand dispatch. The
  surface is small and stays that way.
- Third-party dependencies, all three of them:
  - `golang.org/x/tools`: `go/packages` for the package graph, `imports` for
    the goimports check in-process;
  - `golang.org/x/sync`: `errgroup` and `semaphore` for bounded concurrency;
  - `golang.org/x/vuln`: the vulnerability scanner.
- Everything else is the standard library. Diagnostics use `log/slog`; JSON
  is read and written through `encoding/json/v2`, which rejects duplicate
  names and invalid UTF-8 on the way in and writes deterministic, unescaped
  documents on the way out; every read inside a tree goes through an
  `os.Root` opened at the module.

Adding a dependency is an architecture decision, recorded here, never a
convenience.

## Package layout

```
cmd/goharness        main: signal handling and exit codes only
internal/cli         subcommand dispatch, flags, help, colours, progress
internal/admission   TaskContract, QualityClaim, RiskProfile, VerificationPlan, Decide
internal/repo        repository discovery, git, worktree snapshots
internal/change      base resolution, ChangeSet, hunks, package graph, affected scope
internal/policy      rule registry (GH-*, GCL-*, UBER-*, GO-*), packs, exceptions, ledger
internal/verify      pipeline engine, check scheduling, base/head orchestration
internal/tool        external process runners: go, golangci-lint, the scanner
internal/toolcache   content-addressed cache, checksummed downloads, vuln DB snapshots
internal/leakcheck   the injected TestMain and the overlay that carries it
internal/analyze     native AST checks: suppressions, comments, tests, concurrency, metrics, mutants
internal/evidence    the Evidence model, stable fingerprints, base/head comparison
internal/report      text and JSON (goharness.report/v2) renderers, report diff
internal/skill       the agent skill the binary ships and installs
```

No `util`, `common`, `manager` or `service` packages. Interfaces exist only
at the two test seams, process execution (`tool.Runner`) and git
(`repo.Git`), and nowhere else.

## Verdict and exit codes

- ADMITTED = 0: every applicable claim has sufficient evidence.
- REJECTED = 1: at least one required rule failed on evidence.
- INCONCLUSIVE = 2: evidence was missing, a tool could not be trusted, or
  the run saw no change. A tool crash is never a code finding: runner errors
  flow through a distinct `CheckFailure` channel, not through evidence.
- 130: a second interrupt stopped the run.

## Change model and scope

- Base resolution order: an explicit `--base`; else the merge-base with the
  default branch; else, when HEAD is on the default branch and the working
  tree carries uncommitted work, HEAD itself; else the parent commit. A
  repository with no commits degrades to full scope over tracked files. The
  report records which applied.
- ChangeSet = the committed diff from base to HEAD plus staged, unstaged and
  untracked files. A diff that holds nothing, in this module or outside it,
  is an empty change, and an empty change is INCONCLUSIVE: there is nothing
  to admit, and a document that said otherwise would certify work the gate
  never saw.
- Affected packages: changed files map to packages through `go/packages`;
  `fast` extends to direct reverse dependents; `verify` uses the full
  reverse-dependency closure. Changed-line filtering alone is rejected:
  scoping is package-aware and dependency-aware, because a change in one
  package can break another it never opened.
- A rename keeps its source path. A file's path is part of a finding's
  identity, and discarding the source made a change that moved a file
  introduce every finding the file already carried.
- What is judged and what is reported are separate decisions. Scope decides
  what the run looks at; `origin` records how close each finding sits to
  the code the change wrote; `--evidence` selects which rows the report
  carries. No selection drops a row that blocks.
- Line attribution comes from one `git diff -U0` against the base with no
  second revision, so the line numbers are the verified tree's.

## The read boundary

Every file a scanner judges is opened through an `os.Root` at the module
root, at head and in the base worktree alike. A symlink that points outside
the tree, or a path that escapes it, is not read and not judged: the run
ends with an error naming the path, because code the module does not
contain is not evidence about the module and a scanner that followed the
link could be pointed at anything on the machine. A symlink inside the tree
reads normally. Process runners keep the root as a directory string, since
the go command resolves its own paths.

## Base/head comparison

`verify` materialises the base snapshot with `git worktree add --detach` in
a symlink-resolved temporary directory, runs the same checks there, and
compares evidence sets by stable fingerprint:

- a fingerprint is the rule ID, the module-relative file path, the package
  path, the message with every number masked, and an occurrence index. It
  excludes line numbers and the numbers a message carries, so unrelated
  edits do not churn identity and a function still over the complexity
  budget at 27 instead of 30 is the same finding. A producer that knows its
  own identity states it (`identity`): a test failure is its package and
  top-level test, a leak is its site, an API break is its symbol;
- evidence at head and not at base is new and blocks;
- evidence at both is pre-existing debt: reported, not blocking;
- the ungrandfatherable core, the suppression rules and the policy guards,
  blocks on a pre-existing finding too, but only on a line the change wrote.
  One the change left as it found it, in a file it edited or anywhere else,
  is debt for the audit, where every one of them blocks and no ledger may
  acknowledge them;
- the base evidence set is realigned into head's coordinates first, so a
  moved file's findings pair with themselves rather than splitting into a
  new one and a fixed one;
- a check that reads one package directory and owns no ungrandfatherable
  rule examines only the directories the change touched, on both sides. A
  directory identical at both revisions produces identical findings at
  both, which pair and can be neither new nor fixed; the narrowing removes
  pre-existing rows and nothing else. Compilation, vet, `go fix`,
  golangci-lint, the tests, the vulnerability scan, clone detection and the
  native scan are never narrowed;
- the base runs a test package only where head's own run of it produced a
  test failure or a leak, because those are the only rows a base result can
  reclassify.

The temporary base worktree is always removed, on a context that
cancellation cannot reach. `audit` performs no comparison and evaluates the
whole repository at head.

## Execution plan and concurrency

The pipeline builds a deterministic plan: a DAG of checks with explicit
dependencies (compile precedes vet, lint and tests). The scheduler:

- runs independent checks concurrently under `errgroup` with a
  `semaphore.Weighted` bounded by `runtime.GOMAXPROCS(0)`, or `--jobs`;
- propagates one cancellable `context.Context` through every runner;
- collects evidence per check, then sorts globally so repeated runs emit
  byte-identical reports;
- never mutates shared state from check goroutines: each check returns a
  value, and the coordinator owns aggregation;
- runs every check under a recover guard, so a panicking check is a
  `CheckFailure` and an INCONCLUSIVE claim, never a crash.

## Tool integration decisions

- `go vet` runs explicitly with `-json`; the `govet` linter is disabled in
  the embedded configuration so a diagnostic never arrives twice.
- `go fix` runs with `-json` and never with anything else. The go command
  applies fixes to the tree unless asked for JSON or a diff, so one function
  builds the argument vector and a test asserts it never passes `-fix` or
  `-diff`. Only diagnostics that carry an edit become evidence: the suite
  earns the right to report by producing the replacement. The enabled
  analyzers are checked-in policy data (`internal/policy/rules_gofix.go`),
  compared against `go tool fix -flags` before every run; an analyzer the
  toolchain lacks fails the check, and one the registry never classified is
  reported by `doctor` rather than run. `buildtag` is off because `go vet`
  already runs it; `omitzero` is off because it changes what `json.Marshal`
  emits, and a gate may report a defect but may not push a semantic change.
- The linter's own generated-file exclusion is off; the harness decides
  what is exempt. A `Code generated` header is a claim its author writes, so
  a file the change added or rewrote is judged in full, and only generated
  files the change leaves alone are dropped from scope.
- A package the go command could not list (an unobtainable module, a proxy
  that is off, a missing sum) is not a compile finding. It ends the compile
  check as a failure and leaves the claim INCONCLUSIVE.
- golangci-lint runs on package patterns with the embedded strict
  configuration written to a temporary file; the repository's own
  `.golangci.yml` is never read. `nolintlint` stays off: the native
  suppression scanner is authoritative.
- `go mod tidy -diff` runs check-only. `go test` uses `-json`, including the
  overlaid runs that judge mutants, so a package that failed to build is
  told apart from a test that failed. `-race` runs where the change touches
  concurrency, and repository-wide in `audit`. Test binaries run under the
  run's own deadline rather than go test's ten minutes per binary, so a long
  suite is never reported as a failing one; a run that outlives `--timeout`
  says the budget was the cause.
- Goroutine-leak evidence comes from the runtime. The injected `TestMain`
  runs the package's tests, then reads the `goroutineleak` profile, again
  while other goroutines remain, for at most a quarter of a second, so a
  goroutine that had not parked yet is still seen; a goroutine blocked on a
  primitive nothing can ever unblock is a leak, and
  the package fails naming the site that started it and the functions it is
  parked in. A package that declares its own `TestMain` cannot be injected:
  in the change it makes the leak obligation INCONCLUSIVE with the remedy
  spelled out, elsewhere in the closure it is a coverage gap the report
  names.
- Benchmarks run with `-json` too. A benchmark that panics or fails is
  named from the event stream, skipped with `-skip`, and the package is run
  again, so one broken benchmark costs its own measurement rather than every
  measurement of its package.
- Vulnerability scanning is the embedded `golang.org/x/vuln` against a
  local snapshot. `audit` always plans it; `verify` plans it when the
  change touches a dependency file. No snapshot means INCONCLUSIVE for that
  obligation, never a pass.
- Binary discovery for golangci-lint: `GOHARNESS_GOLANGCI_LINT`, then
  `./.tools/`, then the content-addressed cache, then `PATH`; every
  candidate is hashed against the pinned per-platform sha256.

## Native checks

The native scanners in `internal/analyze` cover what no external tool
provides: every dialect of inline suppression, comment hygiene, test
effectiveness and test weakening, goroutine lifecycle and bounded
resources, transaction pairing, the exported-API diff, maintainability
deltas, clone detection, forwarding layers and sole implementations,
deprecations without a `//go:fix inline` directive, architecture rules and
the policy guards. `goharness explain RULE-ID` prints any rule's rationale,
remedy and compliant pattern; the registry in `internal/policy` is the
source.

Rule precision is measured, not asserted. Every exclusion in a scanner
replaced a class of finding the corpus run produced on healthy published
repositories: network rules do not run on test files, a test that hands its
`*testing.T` to a helper is not an assertion-free test, a package comment is
not a comment that restates code. A rule enters advisory and experimental
and is promoted on corpus evidence, never on a fixture written to make it
fire.

## Policy model

The default strict policy composes the Go core, the strict linter pack, the
`go fix` suite, the Uber guide, agent hygiene, test effectiveness,
architecture, maintainability and the diff-evidence rules. Zero
configuration yields strict behaviour. `goharness.yaml` may add rules,
declare architecture rules, raise a rule's classification, and record
scoped exceptions with a rule, a scope, a reason, an owner and an expiry.
It cannot lower a classification, disable a mandatory rule, or except one.
Every rule carries a lifecycle (experimental, advisory, required,
deprecated); modes never change thresholds, only scope and depth.

## Change visibility

Compiling, vetting, linting and testing reach code through the package
graph, so a changed Go file the build configuration excludes is a part of
the change nothing examined. That is missing evidence rather than a defect:
the `change-visible` obligation names those files and leaves the
correctness claim INCONCLUSIVE. Deleted files, `testdata`, `vendor` and
directories the go command never builds from are out of the question by
convention. A test file a build constraint excludes is a different case: its
tests are gone from the suite whatever the file says, and the test-shape
comparison counts them as deleted.

## Read-only guarantee

Verification commands never write inside the worktree:

- every formatter and tidy check runs in diff or check mode, and `go fix`
  runs in `-json` mode;
- temporary state (the embedded configuration, the base worktree, overlays)
  lives under `os.MkdirTemp` and is removed on a context that cancellation
  cannot reach;
- the pipeline captures `git status --porcelain` before and after and goes
  INCONCLUSIVE if the two differ;
- integration tests assert an unchanged status for every command, and the
  corpus run asserts the same against real repositories;
- outside the worktree, verification writes exactly one thing: derived base
  evidence in the cache, keyed by content. `--no-cache` disables it and must
  not change a verdict.

`setup`, `tools update` and `skill install` are the only commands that reach
the network or write outside a repository, and every download is checksum
verified before it is trusted.

## Self-admissibility

goharness passes its own `verify`. The code carries no inline suppression,
no em dash in a comment, no package-level mutable state, no `init`, no
`panic` outside `main`, and no `TestMain`, because a `TestMain` would block
the leak injection into its own suite.

`.github/workflows/verify.yml` runs the suite on Linux and macOS, ends each
job by running the harness against itself, and runs it a second time to
prove the two reports are identical outside the timing block. The linter it
uses comes from `goharness setup`, so CI exercises the same checksum-verified
provisioning a user does.

Two suites exist for properties that only hold while someone keeps checking:

- `internal/verify/bypass_test.go` holds one case per route by which a
  change could once have been admitted without the evidence to justify it.
  Every case asserts a verdict that is not ADMITTED, or that a grant had no
  effect, and is paired with a false-positive guard. A bypass found in use
  becomes a case here before it is fixed.
- `internal/verify/corpus_test.go` runs the harness over published
  repositories at pinned commits, gated behind `GOHARNESS_CORPUS=1`. It
  asserts only what must always hold and prints what every rule fired on,
  which is the evidence a rule is precise enough to be promoted.
