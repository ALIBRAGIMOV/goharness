# goharness Architecture Decisions (v0.1)

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

- fingerprints exclude line numbers (rule ID, module-relative file path,
  package path, normalized message, occurrence index) so unrelated edits do
  not churn identity;
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
  overlap with the immediately following statement), advisory in v0.1;
- test effectiveness (`GH-TEST-*`): tests with no assertion, error check,
  state observation, or panic expectation; unconditional `t.Skip`; empty test
  bodies; assertions comparing identical constants; ignored errors in tests.

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

## Read-only guarantee

Verification commands never write inside the worktree. Enforcement:

- all formatter and tidy checks run in diff/check mode;
- temp files (embedded config, base worktree) live under `os.MkdirTemp`;
- the pipeline captures `git status --porcelain` before and after and fails
  INCONCLUSIVE if the two differ, as a last-line guard;
- integration tests assert an unchanged porcelain status for every command.

## Self-admissibility

goharness must pass its own `verify`. The codebase contains no `nolint` or
`lint:ignore` directives, no U+2014 in comments, is gofmt- and
goimports-clean, and passes go vet plus the embedded strict golangci-lint
configuration. CI runs the harness against itself.
