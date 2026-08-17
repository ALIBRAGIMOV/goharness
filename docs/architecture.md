# goharness Architecture Decisions (v0.5)

Status: accepted. This document records the pinned tool versions and the
architecture decisions made before implementing the v0.1 vertical slice.

## Pinned versions

| Component | Pin | Rationale |
|---|---|---|
| Go toolchain | go 1.26 (module directive `go 1.26`) | Current stable; loop-variable semantics of Go 1.22+ assumed. |
| golangci-lint | `v2.12.2` (exact, never `latest`) | Latest stable v2 release at time of pinning. Run as an external executable only; its GPL-licensed internals are never imported or linked. |
| Uber Go Style Guide | commit `1d60a91aa5e87d443002e23c21903c49489dbde5` of `github.com/uber-go/guide` | Versioned policy source. The guide is never fetched at verification runtime; a checked-in rule registry references this SHA. |
| JSON report schema | `goharness.report/v1` | Versioned so consumers can detect breaking changes. |

The pinned golangci-lint version is recorded in `internal/tool/golangci.go` as a
constant, embedded in every JSON report, and enforced at runtime: a version
mismatch yields INCONCLUSIVE with a `doctor` hint, never a silent fallback.

## Module and dependencies

- Module path: `github.com/ALIBRAGIMOV/goharness`.
- CLI: standard library `flag` with hand-rolled subcommand dispatch. No cobra;
  minimal dependencies is a stated constraint and the surface is small.
- Allowed third-party dependencies:
  - `golang.org/x/tools` (`go/packages` for package graph loading,
    `imports` for goimports verification in-process);
  - `golang.org/x/sync` (`errgroup` and `semaphore` for bounded concurrency);
  - `go.uber.org/zap` (structured diagnostic logging; injected explicitly,
    never through a package-level global, always writing to stderr).
- Everything else is standard library. `gofmt` verification uses `go/format`
  in-process; both formatters run check-only and never write files.

## Package layout

```
cmd/goharness        main; wiring only
internal/cli         subcommand dispatch, flags, exit-code mapping
internal/repo        workspace discovery, git snapshot capture, worktree guard
internal/change      base/head resolution, ChangeSet, affected-package calc
internal/policy      embedded policy packs, Uber rule registry, exceptions
internal/verify      pipeline: ExecutionPlan, scheduler, Decision
internal/tool        external tool runners (go, golangci-lint) + version pins
internal/analyze     native AST checks: suppressions, comments, test quality
internal/evidence    Evidence model, fingerprinting, base/head comparison
internal/report      text and JSON (goharness.report/v1) renderers
```

`internal/cache` is deferred past v0.1; the layout reserves the name.
No `util`, `common`, `manager`, or `service` packages. Interfaces live at
consumer boundaries and are introduced only where a test seam requires one
(external process execution and git access are the two seams).

## Verdict and exit codes

- ADMITTED = 0: all required checks completed and passed.
- REJECTED = 1: at least one required rule failed on evidence.
- INCONCLUSIVE = 2: a tool, environment, or infrastructure failure prevented a
  trustworthy answer. A tool crash is never reported as a code violation:
  runner errors flow through a distinct `CheckFailure` channel, not Evidence.

## Change model and scope

- Base resolution order: explicit `--base` flag; else merge-base with the
  default branch; else the parent commit; in a repo with no commits, diff mode
  degrades to full-scope on tracked files.
- ChangeSet = committed diff (base..HEAD) plus staged and unstaged changes.
- Affected packages: changed files map to packages via `go/packages`; `fast`
  extends to direct reverse dependents; `verify` uses the full reverse
  dependency closure. Changed-line filtering alone is explicitly rejected;
  scoping is package-aware and dependency-aware.

## Base/head comparison

`verify` materializes the base snapshot with `git worktree add --detach` in a
temporary directory, runs the same normalized checks there, and compares
evidence sets by stable fingerprint:

- fingerprints exclude line numbers, and exclude the numbers a message carries
  (rule ID, module-relative file path, package path, message with every number
  masked, occurrence index) so unrelated edits do not churn identity. Masking
  measurements matters as much as masking positions: a function still over the
  complexity budget at 27 instead of 30 is the same finding, and without the
  mask a change that partly repaired old debt would be rejected for creating a
  new one;
- evidence present at head but not at base is new and blocks;
- evidence present in both is pre-existing debt: reported, never blocking in
  diff modes;
- suppression directives and agent-hygiene violations are exempt from debt
  grandfathering: they block whenever they are in scope, because inline
  suppression is forbidden outright.

The temporary base worktree is always removed; `deep` skips base comparison
and evaluates the whole repository at head.

## Execution plan and concurrency

The pipeline builds a deterministic ExecutionPlan: a DAG of Check nodes with
explicit dependencies (compile precedes vet, lint, and tests). The scheduler:

- runs independent checks concurrently under `errgroup` with a
  `semaphore.Weighted` bounded by `runtime.GOMAXPROCS(0)`;
- propagates a single cancellable `context.Context` through every runner;
- collects evidence per check, then sorts globally by (rule ID, file, line,
  fingerprint) so repeated runs emit byte-identical reports;
- never mutates shared state from check goroutines; each check returns a
  value, and the coordinator owns aggregation.

## Tool integration decisions

- `go vet` runs explicitly as the official Go check with `-json`; the `govet`
  linter is disabled in the embedded golangci-lint config so diagnostics are
  never duplicated.
- `go fix` runs with `-json` and never with anything else. The go command
  applies fixes to the source tree unless it is asked for JSON or a diff, so a
  single function builds the argument vector, always passes `-json`, and never
  passes `-fix` or `-diff`; a test asserts exactly that, because the failure
  mode is not a wrong verdict but a rewritten worktree. The output is the same
  go/analysis JSON tree `go vet -json` prints, so one decoder serves both, and
  an analyzer that reports an error instead of diagnostics becomes a
  `CheckFailure` rather than a statement about the code.
- The enabled fix analyzers are checked-in policy data (`internal/policy/
  rules_gofix.go`), the same way the strict linter set is: project
  configuration cannot widen or narrow it. Two of the suite's analyzers are
  deliberately off. `buildtag` is the same analyzer `go vet` already runs, and
  one defect must not arrive under two rule IDs. `omitzero` changes what
  `json.Marshal` emits, by its own documentation, and a gate may report a
  defect but may not push a semantic change. Because the set is a function of
  the toolchain, the check compares it against `go tool fix -flags` before
  running: an enabled analyzer this toolchain lacks fails the check, and an
  analyzer the toolchain has added that the registry never classified is
  reported by `doctor` rather than run.
- Only fix diagnostics that carry an edit become evidence. The suite earns the
  right to report by producing the replacement; a diagnostic with no edit is
  the analyzer declining, most visibly on a call inside a generated file, where
  the inliner reports that it will not rewrite the file. The consequence is a
  known limit: a `Code generated` header hides `go fix` findings in a file its
  author wrote. Nothing can be admitted through that gap while every `GO-FIX`
  rule is advisory; closing it is part of promoting the first one to required,
  and `internal/verify/gofix_test.go` holds the case that records it.
- The linter's own generated-file exclusion is off (`generated: disable`); the
  harness decides what is exempt. A `Code generated ... DO NOT EDIT.` header is
  a claim its author writes, so a file the change added or rewrote is judged in
  full whatever it says about itself, and only generated files the change leaves
  alone are dropped from scope. The decision reads the head diff in both trees,
  so a regenerated file is examined at base and at head alike and its unchanged
  findings stay pre-existing debt rather than arriving as new ones.
- A package the go command could not list at all (an unobtainable module, a
  proxy that is off, a missing sum) is not a compile finding. It says nothing
  about the change, so it ends the compile check as a failure and leaves the
  claim INCONCLUSIVE. Parse and type errors remain evidence.
- golangci-lint runs on package patterns, never on isolated files, with the
  embedded strict config written to a temp file and passed via `--config`;
  the target repository's `.golangci.yml` is never trusted by default.
  Output is JSON, normalized into Evidence.
- `nolintlint` stays off; the native suppression scanner in
  `internal/analyze` is authoritative and rejects every suppression directive.
- `go mod tidy -diff` runs check-only. `go test` uses `-json`; `deep` adds
  `-race` and repository-wide scope. govulncheck and fuzzing are `deep`-only
  and tolerate absence of the tool by reporting INCONCLUSIVE for that check
  only when the policy marks it required.
- Binary discovery: `GOHARNESS_GOLANGCI_LINT` env var, then `./.tools/`, then
  `PATH`. `doctor` reports what was found and whether versions match the pin.

## Native checks (agent hygiene)

AST- and token-based scans over in-scope Go files:

- `GH-SUPPRESS-001`: any `//nolint` directive;
- `GH-SUPPRESS-002`: any `//lint:ignore` directive;
- `GH-COMMENT-001`: Unicode em dash U+2014 inside Go comments (string
  literals are exempt by construction: the scan walks comment groups only);
- `GH-COMMENT-002`: comment size budget (function doc comments over 15 lines
  are advisory; over 30 required);
- `GH-COMMENT-003`: comments that restate the code (heuristic: comment token
  overlap with the immediately following statement), advisory;
- `GH-POLICY-003`: a working-tree contract asking for a grant the base revision
  does not give it (see the contract model in `docs/admission-model.md`);
- `GH-SIMP-001`: a function whose whole body forwards its own parameters to
  another function, advisory and experimental;
- `GH-DEPRECATE-001`: a deprecated function or constant whose replacement is a
  single call or value, carrying no `//go:fix inline` directive, so every
  caller has to migrate by hand and the shim outlives the release it was
  written for. Advisory and experimental: a scanner cannot see whether the
  author means the substitution to be automatic;
- `GH-SIMP-002`: an unexported interface exactly one type in its package
  satisfies, advisory and experimental. Exported interfaces are excluded: those
  are a package's contract with the outside, and a test seam is a legitimate
  reason for one;
- test effectiveness (`GH-TEST-*`): tests with no assertion, error check,
  state observation, or panic expectation; unconditional `t.Skip`; empty test
  bodies; assertions comparing identical constants; ignored errors in tests. A
  test that hands its `*testing.T` to a helper is not reported: table-driven
  tests with a shared assertion helper are the idiomatic Go form, and a
  required rule must stay silent where the scan cannot see;
- the network family (`GH-NET-*`) does not run on `_test.go` files. Those rules
  protect a production request path, and a test calling `http.Get(server.URL)`
  against a local server has no caller deadline to propagate.

Rule precision is measured, not asserted. The exclusions above each replaced a
class of finding the corpus run produced on healthy published repositories: 34
network findings that were all in tests, 19 no-assertion findings that were all
table-driven tests with helpers, and a package documentation comment blocking
for the sin of documenting a package. `GH-DEPRECATE-001` was narrowed the same
way: its first corpus run produced one hit, a deprecated exported function whose
single call went to an unexported constructor, where a directive would have
offered callers outside the package a replacement they cannot name. Requiring
both ends to be exported took the rule to zero hits on the corpus, which is
where an experimental rule with fixtures that prove it fires should sit.

The `go fix` suite was calibrated in the same run. Across the four corpus
repositories it produced 223 findings: `any` 147, `rangeint` 33, `fmtappendf`
25, `plusbuild` 10, `forvar` 3, `inline` 2, `slicescontains` 2,
`reflecttypefor` 1. `GCL-modernize` produced 211 in the same run, so the
modernizer families overlap heavily and the two sources currently report the
same defects under different rule IDs. Both stay on for now: deciding which one
owns modernization is a separate change, and the case for `go fix` owning it is
that it is pinned by the toolchain the module already declares and it carries
the edit. `inline` and `plusbuild` overlap with nothing.

## Policy model

The default strict policy composes `go/core`, `golangci/strict`,
`uber/guide`, `agent/hygiene`, and `tests/effectiveness`. Zero configuration
yields strict behavior. Project configuration (`goharness.yaml` at repo root,
parsed with a minimal decoder) may add rules and centralized exceptions with
rule ID, scope, reason, owner, and expiration; it cannot disable mandatory
rules. Every rule carries a lifecycle (experimental, advisory, required,
deprecated); modes never change thresholds, only scope and depth.

The Uber registry maps guide sections to rule IDs (`UBER-*`) with source
anchors into the pinned commit, classification (required, advisory, manual,
not-applicable, superseded), enforcement mechanism (which linter or native
check), and Go version constraints (loop variables are superseded as of Go
1.22; typed `sync/atomic` is preferred over `go.uber.org/atomic`).

## Change visibility

Compiling, vetting, linting and testing all reach code through the package
graph, so a changed Go file the build configuration excludes is a part of the
change nothing examined. That is missing evidence rather than a defect: the file
may be perfectly good on another platform or under another tag. The
`change-visible` obligation names those files and leaves the correctness claim
INCONCLUSIVE, which is the honest answer and still stops an agent from calling
the task finished. Deleted files, `testdata`, `vendor`, and directories the go
command never builds from (a leading dot or underscore) are out of the question
by convention and never reported.

## Read-only guarantee

Verification commands never write inside the worktree. Enforcement:

- all formatter and tidy checks run in diff/check mode, and `go fix` runs in
  `-json` mode, which reports its edits instead of applying them;
- temp files (embedded config, base worktree) live under `os.MkdirTemp`;
- the pipeline captures `git status --porcelain` before and after and fails
  INCONCLUSIVE if the two differ, as a last-line guard;
- integration tests assert an unchanged porcelain status for every command, and
  the corpus run asserts the same against real repositories;
- outside the worktree, verification writes exactly one thing: derived base
  evidence in the cache, under the rules in `docs/toolchain.md`. `--no-cache`
  disables it and must not change a verdict.

## Self-admissibility

goharness must pass its own `verify`. The codebase contains no `nolint` or
`lint:ignore` directives, no U+2014 in comments, is gofmt- and
goimports-clean, and passes go vet plus the embedded strict golangci-lint
configuration.

`.github/workflows/verify.yml` runs the full matrix on Linux and macOS, ends
each job by running the harness against itself, and then runs it a second time
to prove the two reports are identical outside the timing block. The linter it
uses comes from `goharness setup`, not from a third-party install action, so CI
exercises the same checksum-verified provisioning path a user does.

Two test suites exist for properties that only hold if someone keeps checking:

- `internal/verify/bypass_test.go` holds one case per route by which a change
  could once have been admitted without the evidence to justify it. Every case
  asserts a verdict that is not ADMITTED, or asserts that a grant had no effect.
  A bypass found in the field becomes a case here before it is fixed.
- `internal/verify/corpus_test.go` runs the harness over published repositories
  at pinned commits, gated behind `GOHARNESS_CORPUS`. It asserts only what must
  always hold (the harness does not fail on real code, and does not modify the
  tree it was pointed at) and prints what every rule fired on, which is the
  evidence a rule is precise enough to move from advisory to required.
