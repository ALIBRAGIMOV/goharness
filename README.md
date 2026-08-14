# goharness

**A deterministic admission gate for Go code. A change gets in only when every quality claim has evidence.**

goharness decides whether a Go change is admissible. Not "the linter passed". Not "the tests are green". Admissible: every applicable quality dimension holds, with proof, and anything unprovable is reported honestly instead of waved through.

```
$ goharness verify
goharness 0.3.0  mode=verify  verdict=ADMITTED

claims: correctness PASS  concurrency-safety PASS  test-effectiveness PASS
        security PASS  maintainability PASS  ... (14 dimensions)

0 blocking, 0 pre-existing, 0 advisory, 0 tool failures  (31s)
ADMITTED: every required check passed in scope.
```

## Why this exists

Modern Go repositories fail in ways no single tool catches:

- Coding agents report "done" while their tests assert nothing.
- `//nolint` comments silently bury real findings forever.
- A goroutine with no termination path ships to production unnoticed.
- A strict linter is unusable on a legacy repo because it drowns you in old debt.
- "Could not run the check" quietly becomes "the check passed".
- A vulnerability is published for a dependency you use, and nothing tells you.

goharness is one binary with one job: refuse to admit a change unless the evidence is actually there. It is built to be the completion gate for both human developers and coding agents.

## Three verdicts, no scores

| Verdict | Exit code | Meaning |
|---|---|---|
| `ADMITTED` | 0 | Every applicable required claim passed with evidence |
| `REJECTED` | 1 | At least one required rule failed |
| `INCONCLUSIVE` | 2 | Required evidence could not be produced; the change is NOT declared safe |

There is no aggregate quality score. A critical failure cannot be bought back by excellence elsewhere. A tool crash is never reported as a code violation; it is an honest `INCONCLUSIVE`.

## Quick start

```bash
go install github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest

goharness setup     # one-time: provisions pinned tools and the vulnerability database
goharness verify    # the admission gate for your current change
```

That is the whole setup. Zero configuration gives you the full strict policy.

## Commands

| Command | What it does |
|---|---|
| `goharness verify` | The admission gate: your diff, its reverse dependencies, base/head comparison, full claims model |
| `goharness verify --agent` | Machine protocol: the admission decision as JSON on stdout |
| `goharness audit` | Repository audit: the whole codebase, every risk domain active, offline vulnerability scan |
| `goharness fast` | Developer loop aid over changed packages. NOT an admission gate, and it says so |
| `goharness explain RULE-ID` | Why a rule exists, what it enforces, whether it blocks |
| `goharness doctor` | Environment health with exact fix commands |
| `goharness setup` | One-time provisioning: pinned golangci-lint (checksum-verified) and the vulnerability database snapshot |
| `goharness tools update` | Refresh the vulnerability database snapshot (atomic swap) |
| `goharness help [command]` | Global or per-command help with examples |

## The admission model

Every run evaluates fourteen quality dimensions: requirements compliance, correctness, simplicity, maintainability, architecture, appropriate reuse, concurrency safety, bounded resource usage, reliability, test effectiveness, performance, security, operability, and policy integrity.

Each dimension produces a claim in one of four states: `PASS`, `FAIL`, `INCONCLUSIVE`, or `NOT_APPLICABLE`. The decision rule is a literal conjunction:

1. Any applicable claim `FAIL` -> `REJECTED`
2. Otherwise any applicable claim `INCONCLUSIVE` -> `INCONCLUSIVE`
3. Otherwise -> `ADMITTED`

A risk-aware planner decides what evidence each change owes:

- Touch goroutines, channels, or sync? You owe race-detector and goroutine-lifecycle evidence.
- Touch tests? You owe anti-weakening and mutation evidence: goharness mutates your changed code in a build overlay and checks that at least one test notices. Tests that observe nothing fail the gate.
- Change a public API? You owe compatibility evidence from a base/head export-surface diff.
- Touch network code? You owe timeout, cancellation, and bounded-retry evidence.
- Hot path with benchmarks? You owe base/head benchmark and allocation deltas.

If required evidence cannot be produced, the claim is `INCONCLUSIVE` and the report names exactly what was missing and how to produce it. Missing evidence is never a pass.

## New debt blocks, old debt does not

goharness fingerprints every finding (line-number independent) and compares your change against its base revision:

- A finding that exists only at head is new: it blocks.
- A finding that exists at both is pre-existing debt: reported, never blocking in diff mode.
- A finding that exists only at base is fixed: credited in the report.

This is why the strict policy is adoptable on a real legacy repository from day one. The exception: suppression directives (`//nolint`, `//lint:ignore`) are forbidden outright and never grandfathered. Exceptions live in one reviewed policy file with a rule ID, scope, reason, owner, and expiration date.

## What runs under the hood

- The Go toolchain as the semantic authority: compilation, `go vet`, `go test`, `gofmt`, `goimports`, `go mod tidy -diff`, the race detector.
- golangci-lint at an exact pinned version (2.12.2) with an embedded strict configuration. Your repo's `.golangci.yml` is never trusted by default. Downloads are verified against the official release checksums.
- An embedded vulnerability scanner (`golang.org/x/vuln`) running strictly offline against a local snapshot of the official Go vulnerability database, with call-graph reachability analysis: it distinguishes "you depend on a vulnerable module" from "your code can actually reach the vulnerable function".
- Native analyzers no other tool provides: the suppression ban across every dialect (`//nolint`, `//lint:ignore`, `#nosec`, `//revive:disable`), comment hygiene (including a ban on the em dash U+2014 in comments, a common agent-generated artifact), comment size budgets, test-effectiveness checks, goroutine-lifecycle and bounded-resource scans, `sql.Tx` pairing, architecture and layout rules, and a policy guard: a change that edits the harness's own configuration is rejected unless a human recorded that decision in the task contract.
- Runtime goroutine-leak evidence with zero setup: when a change touches concurrency, an embedded pinned goleak is injected into every affected test package through a build overlay. Your tests, unchanged, now also prove that no goroutine outlives them. Nothing is installed and your worktree is never modified.
- A versioned registry of Uber Go Style Guide rules, pinned to an upstream commit, with each rule classified honestly: required only where analysis is reliable, advisory where the guide itself is soft, superseded where modern Go made it obsolete.

## For coding agents

goharness is designed as the completion protocol for AI coding agents. The contract:

- An agent must never finish a task after only `fast`. Task completion requires `goharness verify --agent` returning `ADMITTED`.
- In `--agent` mode, stdout is exactly one JSON document (`goharness.report/v2`): the verdict, the full claim table, every piece of evidence with rule ID, position, and doc URL, and `sufficientForCompletion`.
- Every `FAIL` and `INCONCLUSIVE` claim is individually actionable. `goharness explain RULE-ID` explains any finding.

Add one line to your agent instructions:

```
Finish every task by running `goharness verify --agent` and resolving all FAIL and INCONCLUSIVE claims until the verdict is ADMITTED.
```

## Guarantees

- **Read-only.** Verification commands never modify your worktree, never install anything, and never touch the network. `git status` is captured before and after every run; any difference makes the run `INCONCLUSIVE`. Provisioning happens only in `setup` and `tools update`.
- **Deterministic.** Two runs on the same tree produce byte-identical reports. Evidence ordering and fingerprints are stable. Timing lives in a separate block.
- **Interrupt-safe.** Ctrl+C cancels cleanly: child processes are terminated by process group, temporary worktrees are removed, and the verdict is an honest `INCONCLUSIVE`, exit 130 on a forced second signal.
- **Pinned.** golangci-lint 2.12.2 exact, `golang.org/x/vuln` v1.7.0 exact, Uber guide at a pinned commit. Every report records every pin, so a verdict is always attributable to the exact knowledge that produced it.
- **Self-admitting.** goharness passes its own gate. Its own admission run has caught a real data race and real complexity violations in its own code. The checks are not decorative.

## Configuration (optional)

Zero configuration is the intended mode. When you need more:

- `goharness.yaml`: add rules or centralized, expiring exceptions. Mandatory rules cannot be disabled.
- `goharness.task.yaml` or `--contract`: declare the task's goal, allowed scope, known risks, and performance budgets. Files changed outside the declared scope fail requirements compliance.

## Documentation

- [docs/architecture.md](docs/architecture.md): pinned versions and architecture decisions
- [docs/admission-model.md](docs/admission-model.md): the claims model, risk planner, and CLI contract
- [docs/toolchain.md](docs/toolchain.md): tool provisioning, checksums, and the offline vulnerability database
