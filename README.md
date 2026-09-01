# goharness

**A deterministic admission gate for Go. A change gets in only when every
quality claim has evidence.**

goharness answers one question about a Go change: is it admissible?

Not "did the linter pass". Not "are the tests green". Admissible means every
applicable quality dimension holds with proof, and whatever could not be
proved is reported as unproven instead of waved through.

One binary. Zero configuration. Three exit codes. Built for the moment when
most code is written by coding agents and "done" stopped meaning anything.

```console
$ goharness verify
REJECTED  failing claims: maintainability, architecture, reliability, operability
goharness 0.10.0  mode=verify  module github.com/caddyserver/caddy/v2 (go 1.25.1)
tools: go go1.27.0, golangci-lint 2.13.2 (pin 2.13.2), x/vuln v1.7.0, uber guide 1d60a91aa5e8
contract: implicit default
scope: 3 changed files against 62a72977e58c (HEAD, judging uncommitted work), 29 packages, 29 test packages
risk domains: concurrency, network, public-api, tests, hot-path

quality claims:
  PASS           correctness            5 obligation(s) discharged with no required violation
  FAIL           maintainability        1 required violation(s): GCL-predeclared
  FAIL           architecture           1 required violation(s): GCL-gochecknoinits
  PASS           concurrency-safety     3 obligation(s) discharged with no required violation
  FAIL           reliability            1 required violation(s): GCL-errorlint
  PASS           test-effectiveness     3 obligation(s) discharged with no required violation
  PASS           performance            2 obligation(s) discharged with no required violation
  FAIL           operability            3 required violation(s): GCL-noctx
  ...            14 dimensions in total

evidence: 6 new, 1396 pre-existing, 0 fixed, 251 advisory; 0 tool failure(s); 1m29s
mutation: 14 mutant(s) over 11 changed function(s); 1 ran, 1 killed, 0 survived
--evidence diff: 1643 of 1653 finding(s) not shown; rerun with --evidence full to read them
debt in edited files, pre-existing and not shown: modules/caddyhttp/server.go 22; an audit judges it

reliability:
  BLOCK  GCL-errorlint modules/caddyhttp/concurrencylimit_test.go:119:12 [new, added-line]
      type assertion on error will fail on wrapped errors. Use errors.As to check for specific errors
  run: goharness explain GCL-errorlint

operability:
  BLOCK  GCL-noctx modules/caddyhttp/concurrencylimit_test.go:43:30 [new, added-line]
      net/http/httptest.NewRequest must not be called. use net/http/httptest.NewRequestWithContext
  run: goharness explain GCL-noctx

next steps (smallest set of actions that would flip each failing claim):
  reliability: 1 required violation(s): GCL-errorlint
      fix every GCL-errorlint finding above, then rerun; `goharness explain GCL-errorlint` says why it blocks
```

That is a real run: a 300-line feature added to a 105,000-line repository
with 1,396 findings of its own. The change is judged on the ten rows it
wrote. The rest is counted, named per file, and left for the audit.

## Install

```sh
go install github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest

goharness setup     # once: pinned tools, the offline vulnerability database, the agent skill
goharness verify    # the admission gate for the change in your working tree
```

Zero configuration gives you the full strict policy. Requires Go 1.27 or
later on the machine; the repository under test may declare any Go version.

## Why it exists

Real Go repositories fail in ways no single tool catches:

- An agent reports "done" while its new tests assert nothing, or while the
  gate it ran saw no change at all.
- One `//nolint` buries a real finding forever, and nobody reads the diff
  line it sits on.
- A goroutine with no termination path ships to production.
- A strict linter is unusable on a legacy repository because it drowns you
  in old debt.
- "The check could not run" quietly becomes "the check passed".
- A CVE lands in a dependency you use and nothing tells you.

goharness has one job: refuse to admit a change unless the evidence is there.

## Three verdicts, no scores

| Verdict | Exit | Meaning |
|---|---|---|
| `ADMITTED` | 0 | Every applicable claim passed with evidence |
| `REJECTED` | 1 | At least one required rule failed on evidence |
| `INCONCLUSIVE` | 2 | Evidence could not be produced. The change is **not** declared safe |

There is no aggregate score. A critical failure cannot be bought back by
excellence elsewhere. A tool that crashes is never reported as a code
defect; it is an honest `INCONCLUSIVE` with the command that fixes it. A
diff that holds nothing is `INCONCLUSIVE` too: an empty change is not a
clean one, and the gate never certifies work it did not see.

## The change is judged, not the repository

Every finding carries a fingerprint that ignores line numbers, and every run
compares your change against its base revision:

- present only at head: **new**, and it blocks;
- present at both: **pre-existing debt**, reported and not blocking;
- present only at base: **fixed**, and the report credits you.

Every finding also says how close it sits to what you wrote: `added-line`,
`changed-file`, `changed-package`, `untouched`. `new` plus `untouched` is a
package your change broke without editing, and it blocks. `preexisting` plus
`changed-file` is debt in a file you happen to be in: counted per file in
`summary.debtInChangedFiles`, printed on one line, and not something this
change has to fix.

The exception is the ungrandfatherable core: inline suppressions and the
policy guards. Those block on the lines you wrote, however old the directive
you rewrote or moved, and they can never be excepted, baselined or
configured away. One that predates your change on a line you did not touch
is reported as debt and rejects an `audit` instead, because a change gate
that demanded the cleanup of every legacy file an agent opened was a gate
nobody could pass.

`verify` renders the diff view by default: everything blocking, everything
new or fixed, everything on a line you wrote. `--evidence full` prints the
rest. **No view ever drops a finding that blocks**, and `evidenceOmitted`
counts what a view withheld, so a short list is never mistaken for a clean
run.

The base is the merge-base with the default branch. On the default branch
itself it is `HEAD` while you have uncommitted work, and the parent commit
once everything is committed; `--base REV` names it explicitly, and the
report records which applied.

## What it runs

- **The Go toolchain as the semantic authority:** compilation, `go vet`,
  `go test`, the race detector, `gofmt`, `goimports`, `go mod tidy -diff`,
  and the `go fix` analyzer suite, which reports a finding only when the
  toolchain produced the exact edit that closes it.
- **golangci-lint at an exact pin (2.13.2)** with an embedded strict
  configuration. Your `.golangci.yml` is not read. Every candidate binary is
  verified against a pinned sha256; a locally built one is refused.
- **Goroutine-leak evidence with zero setup.** When a change touches
  concurrency, goharness injects a `TestMain` into the affected test
  packages through a build overlay and reads the Go runtime's own
  `goroutineleak` profile after the tests finish. A goroutine blocked on
  something that can never wake it is a leak, named by the site that started
  it. Nothing is vendored, nothing is installed.
- **Mutation evidence.** goharness mutates the functions you changed in an
  overlay and checks that a test notices. Tests that execute code without
  observing it fail the gate. A change with nothing to mutate is discharged
  with the count that says so, never left INCONCLUSIVE with no remedy.
- **Benchmark evidence** in the packages you edited, at base and head,
  interleaved so the machine's load cannot masquerade as a regression. A
  benchmark that fails at both revisions is skipped and reported; one your
  change broke makes the claim unmeasurable and says which.
- **Offline vulnerability scanning** with the embedded `golang.org/x/vuln`
  against a local database snapshot, with call-graph reachability. `audit`
  scans every time; `verify` scans when `go.mod`, `go.sum`, `go.work` or
  `vendor/modules.txt` changed, at base as well as head.
- **Native analyzers nothing else provides:** the suppression ban across
  every dialect, comment hygiene, test-effectiveness and test-weakening
  checks (assertions removed, skips added, tolerances widened, a test file
  excluded by a build constraint), goroutine lifecycle and bounded-resource
  scans, `sql.Tx` pairing, an exported-API diff, architecture rules, a
  policy guard.
- **The Uber Go Style Guide** as a versioned registry pinned to an upstream
  commit, each rule classified honestly: required only where analysis is
  reliable.

## For coding agents

goharness is the completion protocol for coding agents, and it ships as an
agent skill. `goharness setup` installs it for Claude Code
(`~/.claude/skills/goharness/SKILL.md`) and Codex
(`~/.agents/skills/goharness/SKILL.md`); `goharness skill install --project`
writes the same two files into a repository so a commit carries the protocol
to every checkout and cloud session. The skill holds the completion
protocol, the order to read the report in, what each INCONCLUSIVE remedy
means, and the routes an agent must never take.

If your agent reads none of those locations, one line in its instruction
file is enough:

```
Finish every task by running `goharness verify --agent` and resolving every FAIL
and INCONCLUSIVE claim until the verdict is ADMITTED.
```

In `--agent` mode stdout is exactly one `goharness.report/v2` JSON document:
the verdict, `sufficientForCompletion`, the claim table, every finding with
`blocking`, `state`, `origin` and, where a tool can state the fix, the
`fix.command` that closes it, plus every obligation the run could not
discharge with the action that would produce it. `evidence[]` is ordered by
consequence: silent data loss first, then unsafe behaviour, structural,
hygiene. `goharness explain` prints any rule, or any finding by fingerprint.
`goharness diff before.json after.json` states what was fixed, introduced
and remains, which is progress accounting a reviewer can check without
trusting the agent's account of its own work.

[docs/agent-contract.md](docs/agent-contract.md) has the details.

## What a change cannot do to the gate

An agent that can edit the repository can edit anything in it, so the gate
takes nothing in the tree at its word:

- **It cannot grant itself permissions.** Contract grants count only from
  the copy committed at the base revision.
- **It cannot write off its own findings.** Only the debt ledger committed at
  `HEAD` counts, and the suppression rules can never be in it.
- **It cannot hide code behind a header, a build tag or a directory.** A
  `Code generated` comment exempts nothing the change wrote; a changed file
  that nothing compiles leaves correctness `INCONCLUSIVE`; a test file a
  build constraint excludes counts its tests as deleted.
- **It cannot shrink the change.** An empty diff is `INCONCLUSIVE`, the
  report records how the base was chosen, and no view drops a blocking row.
- **It cannot swap the linter or silence the tests through the
  environment.** Binaries are checked against a pinned sha256; subprocesses
  run without `GOFLAGS`, with `GOTOOLCHAIN=local`, and without the
  harness's own settings.
- **It cannot read outside the tree.** Every file the scanners judge is
  opened through an `os.Root` at the module; a symlink that escapes it
  aborts the run naming the path.

Each route has a case in `internal/verify/bypass_test.go` asserting it stays
closed, paired with a guard that the legitimate shape still passes. A bypass
found in the field becomes a test before it becomes a fix.
[docs/threat-model.md](docs/threat-model.md) has the reasoning, route by
route, with its residual risk.

## What it will not blame you for

A gate that rejects changes for things they did not cause gets switched off:

- a test failing at base and at head is pre-existing debt, not your defect;
- a test that fails once and passes on re-run is named as flaky, and the
  verdict is `INCONCLUSIVE`, never a rejection;
- a module the machine cannot download is an environment failure, not a
  compile error in your code;
- a benchmark is slower only when every head sample is slower than every
  base sample, because nanosecond benchmarks swing on a busy machine;
- a `TestMain` in a package you never opened is a gap in the repository's
  coverage, reported as such, not a task for your change;
- on the default branch, the last commit is somebody else's work, not
  yours: uncommitted work is judged against `HEAD`.

## In CI

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # the gate needs the base revision
- uses: actions/setup-go@v5
  with: { go-version: '1.27' }
- run: go run github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest setup --no-skill
- run: go run github.com/ALIBRAGIMOV/goharness/cmd/goharness@latest verify --base origin/main --no-cache
```

A shallow clone has no base revision to compare against, and a run that
sees no change is `INCONCLUSIVE` rather than green. `--no-cache` keeps a CI
runner from trusting a cache it did not write.

## Questions people ask

**How is this different from golangci-lint?**
golangci-lint reports findings. goharness decides admission. It runs
golangci-lint as one evidence producer among many, adds runtime evidence
(race, leaks, mutation, benchmarks) that static analysis cannot give,
compares head against base so old debt does not block you, and refuses to
call a change safe when a check could not run.

**Will it bury my legacy repository in findings?**
No. Only findings your change introduces can block, and `verify` prints what
your change is answerable for: what it introduced, what it fixed, what it
broke elsewhere, and what sits on the lines it wrote. Debt in the files it
edited is one line with a count per file; `--evidence full` has the rest.

**Does it send my code anywhere?**
No. Verification never touches the network and never writes in your
worktree. `setup`, `tools update` and `skill install` are the only commands
that write outside the repository, and every download is checksum verified.

**Is it deterministic?**
Two runs over one tree produce byte-identical reports, and CI asserts it on
every push. Fingerprints exclude line numbers and everything else volatile.

**Does it pass its own gate?**
Yes, and that is the point. Its own admission run has caught a real data
race, an allocation regression from a logging change, and several complexity
violations in its own code.

## Configuration, optional

- `goharness.yaml`: extra rules, architecture rules, and centralised
  expiring exceptions with an owner and a reason. Mandatory rules cannot be
  disabled or excepted.
- `goharness.task.yaml`, or `--contract FILE`: the task goal, its allowed
  scope, declared risks, benchmark budgets, and the two grants a person can
  commit ahead of a change. Run `goharness help contract`.
- `goharness.debt.yaml`: the acknowledged-debt ledger `goharness audit
  --baseline` records, a ratchet for legacy repositories.

## Documentation

- [docs/philosophy.md](docs/philosophy.md): the bet, the three layers, the six principles, and the ideology the code holds to
- [docs/architecture.md](docs/architecture.md): pinned versions, dependencies, package layout, the decisions the code holds to
- [docs/admission-model.md](docs/admission-model.md): claims, obligations, risk domains, the comparison, the report, the ledger, the CLI
- [docs/toolchain.md](docs/toolchain.md): provisioning, checksums, the cache, the offline vulnerability database
- [docs/agent-contract.md](docs/agent-contract.md): the agent skill and the instruction-file fragment
- [docs/adopting-alongside-golangci.md](docs/adopting-alongside-golangci.md): adopting the gate in a repository that already runs golangci-lint
- [docs/threat-model.md](docs/threat-model.md): the routes to an unearned ADMITTED, the mechanism closing each, and the test that pins it
- [docs/releases/](docs/releases/): what each release changed

## License

[MIT](LICENSE).
