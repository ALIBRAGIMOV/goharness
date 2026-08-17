# goharness

**A deterministic admission gate for Go. A change gets in only when every quality claim has evidence.**

goharness answers one question about a Go change: is it admissible?

Not "did the linter pass". Not "are the tests green". Admissible means every
applicable quality dimension holds with proof, and whatever could not be proved
is reported as unproven instead of waved through.

One binary. Zero configuration. Three exit codes. Built for the moment when
most code is written by AI coding agents and "done" stopped meaning anything.

```console
$ goharness verify
REJECTED  failing claims: test-effectiveness
goharness 0.5.0  mode=verify  module github.com/acme/billing (go 1.26)
tools: go go1.26.6, golangci-lint 2.12.2 (pin 2.12.2), x/vuln v1.7.0
scope: 7 changed files against 4f2ab1c9d3e5 (merge-base with default branch), 12 packages, 9 test packages
risk domains: concurrency, tests

quality claims:
  PASS           correctness            5 obligation(s) discharged with no required violation
  FAIL           test-effectiveness     2 required violation(s): GH-MUT-001, GH-TEST-001
  INCONCLUSIVE   concurrency-safety     required evidence was not produced: goroutine-leak-clean
  PASS           simplicity             3 obligation(s) discharged with no required violation; 1 advisory finding(s) recorded
  ...            14 dimensions in total

test-effectiveness:
  BLOCK  GH-TEST-001 billing/refund_test.go:41:2
      test TestRefundApplies contains no assertion, error check, state observation, or panic expectation
  BLOCK  GH-MUT-001 billing/refund.go:88:9
      tests still pass with relational operator >= replaced with <, so they execute this code without observing it
  run: goharness explain GH-MUT-001
  run: goharness explain GH-TEST-001

simplicity:
  advise GO-FIX-rangeint billing/ledger.go:24:2 [new]
      for loop can be modernized using range over int
      fix: go fix -rangeint ./billing

next steps (smallest set of actions that would flip each failing claim):
  test-effectiveness: 2 required violation(s): GH-MUT-001, GH-TEST-001
      fix every GH-TEST-001 finding above, then rerun; `goharness explain GH-TEST-001` says why it blocks
  concurrency-safety: goroutine-leak-clean
      a TestMain already exists in billing/worker, so leak verification cannot be injected there
```

## Install

```bash
go install github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest

goharness setup     # one time: pinned tools and the offline vulnerability database
goharness verify    # the admission gate for your current change
```

That is the whole setup. Zero configuration gives you the full strict policy.
Requires Go 1.26 or later.

## Why it exists

Real Go repositories fail in ways no single tool catches:

- An agent reports "done" while its new tests assert nothing.
- One `//nolint` buries a real finding forever, and nobody reads the diff line it sits on.
- A goroutine with no termination path ships to production.
- A strict linter is unusable on a legacy repo because it drowns you in old debt.
- "The check could not run" quietly becomes "the check passed".
- A CVE lands in a dependency you use and nothing tells you.

goharness has one job: refuse to admit a change unless the evidence is
actually there.

## Three verdicts, no scores

| Verdict | Exit | Meaning |
|---|---|---|
| `ADMITTED` | 0 | Every applicable claim passed with evidence |
| `REJECTED` | 1 | At least one required rule failed on evidence |
| `INCONCLUSIVE` | 2 | Evidence could not be produced. The change is **not** declared safe |

There is no aggregate score. A critical failure cannot be bought back by
excellence elsewhere. A tool that crashes is never reported as a code defect;
it is an honest `INCONCLUSIVE` with the command that fixes it.

## New debt blocks, old debt does not

Every finding gets a fingerprint that ignores line numbers, and every run
compares your change against its base revision:

- present only at head: **new**, and it blocks;
- present at both: **pre-existing debt**, reported and never blocking;
- present only at base: **fixed**, and the report credits you.

That is why the strict policy is adoptable on a legacy repository on day one.
The exception is suppression directives, which are forbidden outright and never
grandfathered. Exceptions live in one reviewed file with a rule ID, scope,
reason, owner and expiry date.

## What it actually runs

- **The Go toolchain as the semantic authority:** compilation, `go vet`,
  `go test`, the race detector, `gofmt`, `goimports`, `go mod tidy -diff`, and
  Go 1.26 `go fix`.
- **golangci-lint at an exact pin (2.12.2)** with an embedded strict config.
  Your `.golangci.yml` is not trusted by default. Every candidate binary is
  verified against a pinned sha256.
- **Offline vulnerability scanning** with the embedded `golang.org/x/vuln`
  against a local database snapshot, with call graph reachability: depending on
  a vulnerable module and reaching the vulnerable function are different
  verdicts.
- **Goroutine leak evidence with zero setup.** When a change touches
  concurrency, a pinned goleak is injected into the affected test packages
  through a build overlay. Your tests, unchanged, now also prove that no
  goroutine outlives them.
- **Mutation evidence.** goharness mutates your changed functions in an overlay
  and checks that a test notices. Tests that execute code without observing it
  fail the gate.
- **Machine-applicable fixes.** A `go fix` finding is reported only when the
  toolchain produced the exact edit that closes it, and the report hands you
  that command. Both directions of `//go:fix inline` are covered: calls that
  have not migrated, and deprecations you shipped without a directive.
- **Native analyzers nothing else provides:** the suppression ban across every
  dialect, comment hygiene (including the em dash U+2014, an agent artifact),
  test-effectiveness checks, goroutine lifecycle and bounded resource scans,
  `sql.Tx` pairing, architecture rules, and a policy guard.
- **The Uber Go Style Guide** as a versioned registry pinned to an upstream
  commit, each rule classified honestly: required only where analysis is
  reliable.

## For AI coding agents

goharness is designed as the completion protocol for coding agents, and works
with any of them: Claude Code, Cursor, Codex, Copilot, or your own harness.

Add one line to your agent instructions:

```
Finish every task by running `goharness verify --agent` and resolving every FAIL
and INCONCLUSIVE claim until the verdict is ADMITTED.
```

In `--agent` mode stdout is exactly one `goharness.report/v2` JSON document:
the verdict, the claim table, every finding with `blocking` and, where a tool
can state the fix rather than guess it, `fix.command`, plus every obligation
the run could not discharge with the action that would produce it. Run
`goharness help` and the whole protocol is on one screen.

## What a change cannot do to the gate

An agent that can edit the repository can edit anything in it, so the gate
takes nothing in the tree at its word:

- **It cannot grant itself permissions.** Contract grants count only from the
  copy committed at the base revision.
- **It cannot hide code behind a header.** A `Code generated` comment exempts
  nothing the change wrote.
- **It cannot hide code from the build.** A changed file that nothing compiles
  leaves correctness `INCONCLUSIVE`, naming the file.
- **It cannot swap the linter.** Every binary is checked against a pinned
  sha256. A locally built golangci-lint reports the right version, hashes to
  something else, and is refused.
- **It cannot silence tests through the environment.** Subprocesses run without
  `GOFLAGS`, with `GOTOOLCHAIN=local`, and without the harness's own settings.

Each route has a case in `internal/verify/bypass_test.go` asserting it stays
closed. A bypass found in the field becomes a test before it becomes a fix.

## What it will not blame you for

A gate that rejects changes for things they did not cause gets switched off:

- a test failing at base and at head is pre-existing debt, not your defect;
- a test that fails once and passes on re-run is named as flaky, and the
  verdict is `INCONCLUSIVE`, never a rejection;
- a module the machine cannot download is an environment failure, not a
  compile error in your code;
- a benchmark is slower only when every head sample is slower than every base
  sample, because nanosecond benchmarks swing on a busy machine.

## In CI

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # the gate needs the base revision
- uses: actions/setup-go@v5
  with: { go-version-file: go.mod }
- run: go run github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest setup
- run: go run github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest verify
```

## Questions people ask

**How is this different from golangci-lint?**
golangci-lint reports findings. goharness decides admission. It runs
golangci-lint as one evidence producer among many, adds runtime evidence
(race, leaks, mutation, benchmarks) that static analysis cannot give, compares
head against base so old debt does not block you, and refuses to call a change
safe when a check could not run.

**Will it bury my legacy repository in findings?**
No. Only findings your change introduces can block. Everything else is
reported as debt.

**Does it send my code anywhere?**
No. Verification never touches the network and never writes in your worktree.
`setup` and `tools update` are the only commands that download anything, and
every download is checksum verified.

**Is it deterministic?**
Two runs over one tree produce byte-identical reports, and CI asserts it on
every push. Fingerprints exclude line numbers and everything else volatile.

**Does it pass its own gate?**
Yes, and that is the point. Its own admission run has caught a real data race,
a performance regression and several complexity violations in its own code.

## Configuration, optional

- `goharness.yaml`: extra rules, and centralized expiring exceptions with an
  owner and a reason. Mandatory rules cannot be disabled.
- `goharness.task.yaml`, or `--contract FILE`: the task goal, its allowed
  scope, known risks and benchmark budgets. Run `goharness help contract`.

## Documentation

- [docs/architecture.md](docs/architecture.md): pinned versions and architecture decisions
- [docs/admission-model.md](docs/admission-model.md): claims model, risk planner, CLI and agent contract
- [docs/toolchain.md](docs/toolchain.md): provisioning, checksums, offline vulnerability database

