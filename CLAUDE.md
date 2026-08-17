# CLAUDE.md

Instructions for coding agents working in this repository.

## What this project is

goharness is a deterministic admission gate for Go changes. It decides ADMITTED (exit 0), REJECTED (exit 1), or INCONCLUSIVE (exit 2) based on evidence across fourteen quality dimensions. Read `README.md` for the product, and the three documents under `docs/` for the normative design:

- `docs/architecture.md`: pinned versions, package layout, core decisions
- `docs/admission-model.md`: claims model, risk planner, CLI and agent contract
- `docs/toolchain.md`: tool provisioning, checksums, offline vulnerability database

Where documents conflict, the newest wins. Do not contradict them in code.

## The completion protocol (non-negotiable)

Every task in this repository ends the same way:

```bash
go build -o /tmp/gh ./cmd/goharness && /tmp/gh verify --agent
```

The task is complete only when the verdict is `ADMITTED`. Resolve every `FAIL` and `INCONCLUSIVE` claim in the JSON output. `goharness fast` is a development aid; it is never sufficient to finish. Use `goharness explain RULE-ID` to understand any finding.

## Self-admissibility: this code must pass its own gate

goharness enforces rules on other codebases, so its own code holds to every one of them:

- Never write `//nolint`, `//lint:ignore`, `//lint:file-ignore`, `#nosec`, `//revive:disable`, or any other inline suppression. If a linter finding is wrong, fix the code or record a scoped, expiring exception in `goharness.yaml` with an owner and a written reason. There are currently zero exceptions; keep it that way.
- Never put the em dash character U+2014 in Go source. Use a plain hyphen. In test fixtures that need the character, write it inside a string literal as a backslash-u escape (backslash, the letter u, then 2014), never as the raw character.
- Every goroutine's termination path must be visible at its launch site.
- No package-level mutable state, no `init()` functions, no `panic` outside the last-resort handler in `main`.
- Comments state constraints the code cannot express. No comments that restate the code, no changelog-style comments, short doc comments on exported symbols.
- Context is the first parameter of anything that blocks, spawns a process, or can be cancelled. Cleanup paths use `context.WithoutCancel` so cancellation never leaks a temp worktree.
- A deprecation this repository introduces carries `//go:fix inline` when its replacement is a single call or value, so callers migrate with one command instead of by hand. The harness reports the omission as `GH-DEPRECATE-001`, and a gate that asks other people for this has to hold itself to it.
- If one of the harness's own checks fires on your new code, fix the code. Never soften a check to make your own code pass. If a check is genuinely too imprecise to block, classify it advisory in the registry with an honest written rationale.

## Verification matrix (run before claiming anything works)

```bash
gofmt -l .                                                        # must print nothing
go build ./...
go vet ./...
go mod tidy -diff                                                 # must be empty
go fix -diff ./...                                                # must print nothing
.tools/golangci-lint run --config internal/tool/golangci_strict.yaml ./...
go test ./...
go test -race ./...
/tmp/gh verify --agent                                            # must be ADMITTED
```

Determinism check when you touched evidence, fingerprints, or reporting: run `verify --agent` twice and compare the JSON byte for byte after removing the `timing` block.

## Hard pins (never change casually)

- golangci-lint: exactly `2.12.2`, external executable, discovered via `GOHARNESS_GOLANGCI_LINT`, then `.tools/`, then the content-addressed cache, then PATH. Every candidate is verified against a pinned per-platform binary sha256; a locally built one (`go install`) reports the right version, hashes to something else, and is refused. Provision with `goharness setup`. Never import its packages (GPL).
- `golang.org/x/vuln`: exactly `v1.7.0` in go.mod, used in-process. No govulncheck binary, no PATH probe.
- `go.uber.org/goleak`: exactly `v1.3.0`, vendored verbatim under `internal/leakcheck/goleaksrc` and injected into race runs via a build overlay. Never add a TestMain to this repository's packages: it would block the injection and turn the leak obligation INCONCLUSIVE.
- Uber Go Style Guide: commit `1d60a91aa5e87d443002e23c21903c49489dbde5`, never fetched at runtime.
- Allowed dependencies: `golang.org/x/tools`, `golang.org/x/sync`, `golang.org/x/vuln`, `go.uber.org/zap`. Everything else is the standard library. Adding a dependency is an architecture decision, not a convenience.

Changing any pin requires updating `docs/architecture.md` or `docs/toolchain.md` in the same change, revalidating the embedded lint config against the new binary, and rerunning the full matrix.

## Architecture in one minute

```
cmd/goharness        main: signal handling, exit codes only
internal/cli         subcommand dispatch, flags, help, colors, progress
internal/admission   TaskContract, QualityClaim, RiskProfile, VerificationPlan, Decide
internal/verify      pipeline engine, check scheduling, base/head orchestration
internal/change      base resolution, ChangeSet, package graph, affected scope
internal/policy      rule registry (GH-*, GCL-*, UBER-*, GO-*), packs, exceptions
internal/tool        external process runners, golangci-lint, go toolchain
internal/toolcache   content-addressed cache, checksummed downloads, vuln DB snapshots
internal/analyze     native AST checks: suppressions, comments, tests, concurrency
internal/evidence    Evidence model, stable fingerprints, base/head comparison
internal/report      text and JSON renderers (schema goharness.report/v2)
```

Rules that keep it healthy:

- Verdict semantics live in `internal/admission` and `internal/verify`. A tool failure becomes a `CheckFailure` and INCONCLUSIVE; it never becomes evidence. Do not blur this line.
- Evidence fingerprints exclude line numbers and any volatile data. Nothing time-based or random may enter the deterministic report portion.
- Checks return values; the coordinator owns all aggregation. No shared mutable state across check goroutines. Concurrency is errgroup plus a weighted semaphore bounded by GOMAXPROCS.
- Interfaces exist only at the two test seams: process execution (`tool.Runner`) and git (`repo.Git`). Do not introduce speculative interfaces.
- Verification commands are read-only: no network, no installs, no worktree writes. The single exception is derived base evidence under `derived/` in the cache, keyed by content and disabled by `--no-cache`; tool payloads and the vulnerability database remain the exclusive business of `setup` and `tools update`, and every download is checksum-verified before trust.
- Subprocesses run with a sanitised environment: no `GOFLAGS`, no `GOHARNESS_*`, `GOTOOLCHAIN=local`. Anything a real repository needs for module resolution (`GOPRIVATE`, `GOPROXY`, `GOMODCACHE`) is passed through untouched.

## Adversarial and corpus suites

Two suites exist because two properties only hold while someone keeps checking:

- `internal/verify/bypass_test.go` holds one case per route by which a change
  could once have been admitted without the evidence to justify it. **A bypass
  found while using the harness becomes a case here before it is fixed.** Every
  case asserts a verdict that is not ADMITTED, or asserts that a grant had no
  effect, and every closure is paired with a false-positive guard so the fix
  cannot be "reject more".
- `internal/verify/corpus_test.go` runs the harness over published repositories
  at pinned commits. It is gated behind `GOHARNESS_CORPUS=1` because it clones
  and downloads; run it before promoting any rule from advisory to required, and
  after touching a scanner. It asserts only what must always hold (no failure on
  real code, no modification of the tree) and prints per-rule hit counts, which
  is the evidence a rule is precise enough to block.

New rules enter as advisory and experimental. They become required only on
corpus evidence, never on the strength of a fixture written to make them fire.

## Testing conventions

- Integration tests build real git repositories in `t.TempDir()` with deterministic committer identity, then run the full pipeline against them.
- Fixture code that must contain forbidden tokens (suppressions, U+2014) puts them inside Go string literals; the comment-only scanners ignore those by construction, and so must any new scanner.
- Network-dependent tests use `httptest` through the injected fetcher. A real-network test must be gated behind an environment variable and skipped by default.
- `testdata/` directories are outside package scope by Go convention; that is what keeps fixtures from tripping self-verification. Preserve that property.

## Git

Do not commit unless explicitly asked. When asked: plain descriptive commit messages, no co-author trailers, no generated-by watermarks of any kind.
