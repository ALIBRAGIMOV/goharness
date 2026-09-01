---
name: goharness
description: Deterministic admission gate for Go changes. Use it to finish any change in a Go module where goharness is installed or the repository's instructions name it; run `goharness verify --agent` once after the last edit, read the goharness.report/v2 JSON, repair every FAIL and INCONCLUSIVE claim, and never suppress or soften a check. Also use it to read a goharness report, a verdict (ADMITTED, REJECTED, INCONCLUSIVE), or a rule ID (GH-*, GCL-*, UBER-*, GO-*).
metadata:
  source: goharness
---

# goharness

goharness decides whether a Go change may be admitted. It runs the toolchain
(gofmt, goimports, vet, go fix, go mod tidy), golangci-lint at a pinned
version, the tests under the race detector with goroutine-leak detection,
benchmarks and mutation testing where they apply, native checks, and a
vulnerability scan when dependencies moved, then compares head against the
base revision. The verdict rests on evidence, never on a narrative:

| exit | verdict      | meaning                                                  |
|------|--------------|----------------------------------------------------------|
| 0    | ADMITTED     | every applicable claim has sufficient evidence           |
| 1    | REJECTED     | at least one claim failed                                |
| 2    | INCONCLUSIVE | evidence was missing, or a tool could not be trusted     |
| 130  | aborted      | a second interrupt stopped the run                       |

INCONCLUSIVE is never a pass. Missing evidence is a different job from a
failing claim, and the report says which one you have.

## The completion protocol

1. Do the work. While iterating, run narrow checks on what you touched:
   `gofmt -l .`, `go build ./... && go vet ./...`, and the tests you wrote
   by name (`go test ./internal/pkg -run TestName -count=1`).
2. After the last edit, run the gate exactly once:

   ```sh
   go build ./... && goharness verify --agent
   ```

   It already contains gofmt, vet, go fix, tidy, golangci-lint, the race
   suite, benchmarks and mutation. Do not run `go test ./...`,
   `go test -race ./...` and the gate back to back: the gate contains both.
3. Read stdout as one `goharness.report/v2` JSON document (the human report
   is on stderr). If the run could not start, stdout is empty and the exit
   code is 2, so check the exit code before parsing.
4. The task is complete only when `sufficientForCompletion` is `true`.
   `goharness fast` is a loop aid and always reports it `false`.

If the shell you run through caps a command at ten minutes, run the gate
detached and write the document to a file:

```sh
nohup goharness verify --agent --report report.json > /dev/null 2> verify.txt &
```

A run that is killed reports nothing. Raise `--timeout` (default 20m) when
the report's `timing` shows the budget was the problem, and say so.

## What the gate judges

The change is the diff between the base revision and the working tree. The
base is the merge-base with the default branch; on the default branch itself
it is HEAD while there is uncommitted work, and the parent commit once
everything is committed. `change.baseOrigin` in the report says which
applied. Work on a branch, or pass `--base REV` naming the commit your work
started from, and never choose a base that shrinks the change: a diff that
holds nothing is INCONCLUSIVE, not admitted.

Reverse dependencies stay in scope: a package the change never opened can
reject it when the change broke it, and that row says `untouched`.

## Reading the report

Work the document in this order and no other.

1. `verdict`, `exitCode`, `sufficientForCompletion`.
2. `claims[]`: `state` is PASS, FAIL or INCONCLUSIVE. FAIL: fix the code.
   INCONCLUSIVE: produce the evidence named in `missingEvidence`.
3. `unproducible[]`: why an obligation could not be discharged, each with the
   `remedy` that would produce it.
4. `failures[]`: a tool that could not run, with a `hint`. A failure is a
   statement about the environment, never about the code.
5. `evidence[]`: already in consequence order (silent-loss, unsafe-behavior,
   structural, hygiene). Work it in that order, never by count.
   - `blocking: true` stops admission. `false` is advisory or pre-existing
     debt and does not have to be fixed for this change.
   - `state`: `new` (this change introduced it), `preexisting` (the base
     revision had it), `fixed`.
   - `origin`: how close the row sits to what you wrote: `added-line`,
     `changed-file`, `changed-package`, `untouched`. `new` plus `untouched`
     is a package the change broke without editing; it blocks like anything
     new.
   - `fix.command`: the exact command that closes the row, when one exists.
   - `fingerprint`: stable across line moves; `goharness explain FINGERPRINT
     --report report.json` explains that one row.
6. `summary` and `coverage`: the totals of the whole run and what it left
   out. `evidenceScope` names the view (`diff` by default) and
   `evidenceOmitted` counts the rows it withheld. No view ever withholds a
   blocking row, so a short list is never a reason to doubt the verdict.
   `summary.debtInChangedFiles` counts, per edited file, the pre-existing
   findings on lines you did not write; they are the repository's debt, an
   audit judges them, and this change does not have to.

`goharness explain RULE-ID` prints the rule: what it defends, its remedy, and
a compliant pattern where one exists. Read it before touching code you do not
understand.

## The repair loop

- Fix blocking rows first, in the order the report lists them. A row whose
  `fix` carries a command: run `goharness fix --rule RULE-ID --dry-run` to
  see the diff, then without `--dry-run` to apply it. `fix` writes files, so
  re-verification is still required.
- A failing test row names the test and its package; run that test alone
  with `-count=3` before deciding it is flaky. A flaky test is reported
  INCONCLUSIVE, not REJECTED; make it deterministic.
- A goroutine-leak row (GH-LEAK-001) names the site where the goroutine was
  started and the functions it is parked in; give the goroutine a
  termination path visible at its launch site (a context, a stop channel,
  a WaitGroup).
- Re-run narrow checks while iterating. Re-run `goharness verify --agent`
  after the last edit, not after every edit.

## INCONCLUSIVE, and what each remedy means

| reason in the report                        | what to do                                                |
|---------------------------------------------|-----------------------------------------------------------|
| nothing differs between base and worktree   | the gate saw no change; check the base, see above         |
| golangci-lint not provisioned or wrong hash | `goharness setup` (downloads once; needs the network)     |
| no vulnerability snapshot                   | `goharness setup`, or `goharness tools update`            |
| host go below the module's toolchain line   | install the toolchain the module names                    |
| a TestMain in a package this change touches | follow the remedy text; the leak check cannot be injected |
| the worktree changed during the run         | stop editing while the gate runs, then verify again       |
| the run hit its `--timeout`                 | raise it and say so; a timeout bounds cost, not quality   |
| a tool crashed (`failures[]`)               | read the `hint`; this is never a code finding             |

`goharness doctor` reports the environment, every pin, and the exact command
that fixes each problem.

## Never do these

- **Never write an inline suppression**: `//nolint`, `//lint:ignore`,
  `//lint:file-ignore`, `#nosec`, `//revive:disable` or any linter directive.
  They are mandatory findings (GH-SUPPRESS-001 to GH-SUPPRESS-004) that no
  configuration, exception or baseline can silence. One that predates the
  change on a line you did not write is reported as debt and leaves the
  verdict alone; one you add, rewrite or move rejects the change.
- **Never edit the gate to pass it.** Editing `goharness.yaml` or
  `goharness.debt.yaml` is reported as GH-POLICY-001; a permission a change
  grants itself in the working tree is ignored and reported as
  GH-POLICY-003. Grants count only when committed at the base revision.
- **Never weaken tests to pass**: deleting assertions, adding `t.Skip`,
  loosening tolerances or excluding a test file with a build constraint is
  reported (GH-WEAK-001 to GH-WEAK-004) and blocks.
- **Never hide code**: a `Code generated` header on hand-written code is still
  judged (GH-POLICY-002), and choosing `--base` or `--evidence` to shrink
  what the report shows changes nothing about the verdict.
- **Never narrate a pass.** The exit code, `sufficientForCompletion` and
  `goharness diff before.json after.json` are what a reviewer checks.

If a rule is genuinely wrong for this code, say so and stop. The honest
route is a scoped, expiring exception in `goharness.yaml` with an owner and a
written reason, or a rule override for a project convention, committed by a
person and never by the change that needs it.

## When the task legitimately needs more

- Removing or re-signing an exported symbol is GH-API-001. It is admitted only
  by `allowApiBreak: true` in `goharness.task.yaml` committed at the base
  revision. If the task requires it, tell the person and ask for that commit;
  do not write the grant yourself.
- A task contract may narrow scope from the working tree (`scope:` paths,
  extra `risks:`). Narrowing needs no authority; widening does.
  `goharness help contract` documents the file.

## Large repositories

- The report is about the change: `--evidence diff` (the default) carries
  every blocking row, every new or fixed row, and every finding on a line you
  wrote. Read `summary` first, then the blocking rows:

  ```sh
  jq '.summary, [.evidence[] | select(.blocking)]' report.json
  ```

- `--jobs N` bounds parallelism; `--report FILE` keeps stdout free.
- A vulnerability scan runs only when `go.mod`, `go.sum`, `go.work` or
  `vendor/modules.txt` changed.

## Commands

```
goharness verify --agent              the gate; finish with this
goharness verify --explain-plan       what the gate will ask for, and why
goharness fast                        loop aid; never sufficient
goharness audit [--baseline]          whole repository at head; the ledger
goharness explain ID | FP --report F  a rule, or one finding
goharness fix --rule ID [--dry-run]   the mechanical remediation
goharness diff OLD.json NEW.json      fixed, introduced, remaining
goharness doctor                      environment, pins, cache, remedies
goharness setup                       provision tools and the vuln database
goharness help contract               the task contract format
```
