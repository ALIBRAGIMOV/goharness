---
name: goharness
description: Deterministic admission gate for Go changes, and the engineering standard it holds Go code to (Effective Go, Go Code Review Comments, Go Test Comments, the Google and Uber Go style guides). Use it while writing or finishing any change in a Go module where goharness is installed or the repository's instructions name it; write to the standard, run `goharness verify --agent` once after the last edit, read the goharness.report/v2 JSON, repair every FAIL and INCONCLUSIVE claim, and never suppress or soften a check. Also use it to read a goharness report, a verdict (ADMITTED, REJECTED, INCONCLUSIVE), or a rule ID (GH-*, GCL-*, UBER-*, GO-*).
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

0. Read before you write: the package you are changing, its tests, and
   `goharness verify --explain-plan`, which lists the obligations your change
   will activate and why. Make the smallest change that does the task; code
   you were not asked to touch is not yours to rewrite.
1. Do the work, to the standard below. While iterating, run narrow checks on
   what you touched:
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

## Write to the standard

The gate holds Go to standards the Go community already works by. It grades
no taste and invents nothing: each line below comes from one of these
sources, in this order of authority, or states a check the gate itself runs.

1. The Go specification and the standard library's own documentation.
2. The Go project: Effective Go (https://go.dev/doc/effective_go), Go Code
   Review Comments (https://go.dev/wiki/CodeReviewComments), Go Test Comments
   (https://go.dev/wiki/TestComments), Go Doc Comments
   (https://go.dev/doc/comment), the Go FAQ (https://go.dev/doc/faq), the Go
   blog, and Rob Pike's Go Proverbs (https://go-proverbs.github.io).
3. The Google Go Style Guide (https://google.github.io/styleguide/go/), which
   builds on Effective Go. Readable code is, in order of importance, clear,
   simple, concise, maintainable and consistent. Least mechanism: a core
   language construct before the standard library, the standard library
   before a new dependency.
4. The Uber Go Style Guide at the commit goharness pins
   (https://github.com/uber-go/guide/blob/1d60a91aa5e87d443002e23c21903c49489dbde5/style.md).
   `goharness explain UBER-ERR-002` prints any of its sections the gate maps.

Where these sources leave a choice, follow the repository's established
convention. No convention licenses breaking a rule the gate enforces. Each
line names its enforcing rule in brackets; a line without one is checked in
review, and a reviewer will check it.

Errors
- Check every error: handle it, or return it with context. Never `_ =` one.
  [GCL-errcheck; GH-TEST-005 in tests]
- Wrap with `fmt.Errorf("reading %s: %w", name, err)` and inspect with
  `errors.Is`, `errors.As` or `errors.AsType`, never `==` or string matching.
  Use `%v` where the cause is a detail callers must not depend on.
  [GCL-errorlint]
- Combine independent failures with `errors.Join`.
- Handle each error once: return it or log it, never both. [UBER-ERR-004]
- Error strings are lower case and end without punctuation. [staticcheck ST1005]
- Report failure as an error or an `ok` result, never an in-band value such as
  -1 or "". Never `return nil, nil`, and never return nil after `err != nil`.
  [GCL-nilnil, GCL-nilerr]
- Return a literal `nil` error. A nil pointer stored in an `error` is not a nil
  interface (Go FAQ, "Why is my nil error value not equal to nil?").
- Handle the error and return early, so the normal path stays at the left
  margin. [GH-CX-002]
- No panic in library code; `os.Exit` and `log.Fatal` belong to `main`.
  [GCL-revive deep-exit]

Concurrency
- Before you write `go`, know how the goroutine stops and who waits for it:
  a context, a closed channel, `sync.WaitGroup.Go`, an `errgroup`.
  [GH-CONC-001, GH-LEAK-001]
- Bound concurrency by something a reader can see: `errgroup.SetLimit` or a
  fixed pool, never one goroutine per input item. [GH-CONC-002]
- `ctx context.Context` is the first parameter of anything that blocks, does
  I/O or can be cancelled. Pass the caller's context down; never store one in
  a struct. [GH-NET-002, GCL-noctx, GCL-containedctx]
- In a function that holds a context, a select that can block also waits on
  `ctx.Done()`.
- Only the sender closes a channel, and a signature states the direction it
  allows (`<-chan T`, `chan<- T`).
- Prefer synchronous functions; let the caller add concurrency.
- Never copy a value that holds a `sync.Mutex`; the zero value is ready to
  use. [GO-VET copylocks]
- A channel is unbuffered or has a buffer of one unless a measurement says
  otherwise; a buffer sized from a variable is reported. [GH-RES-002]
- Every HTTP client has a timeout, every retry loop an attempt bound, and no
  `time.After` sits inside a loop. [GH-NET-001, GH-NET-003, GH-RES-001]

Design
- Write the least mechanism that does the task: no speculative abstraction, no
  option nobody asked for, no layer that only forwards its arguments.
  [GH-SIMP-001]
- No mutable package-level variables and no `init()`: pass dependencies in.
  [GCL-gochecknoglobals, GCL-gochecknoinits]
- Return concrete types. Define an interface in the package that consumes it,
  when it is needed, and keep it small: the bigger the interface, the weaker
  the abstraction. [GH-SIMP-002]
- Use generics when the same code would otherwise be written for several
  types, and an interface when the behaviour differs (Go blog, "When To Use
  Generics"). `any`, not `interface{}`. [GO-FIX-any]
- Make the zero value useful. A nil map in a zero value panics on first write.
- Name a package for what it provides: short, lower case, never `util`,
  `common`, `misc` or `helpers`, and without stutter (`chubby.File`, not
  `chubby.ChubbyFile`). [GH-ARCH-001]
- A little copying is better than a little dependency: a new module
  requirement is a decision to justify. [GH-DEP-001]
- Copy slices and maps at an API boundary unless ownership is meant to move.
- Keep one receiver kind per type, all pointer or all value. [GCL-recvcheck]
- Exported API does not break silently: a removal or re-signature needs a
  grant committed at base, and a deprecation of an API you own carries
  `// Deprecated:` plus `//go:fix inline` when the replacement is one call.
  [GH-API-001, GH-DEPRECATE-001]
- Use what the language and standard library now provide (`slices`, `maps`,
  `min`, `max`, range over an integer) over hand-written equivalents.
  [GCL-modernize]

Security
- Treat every value that crosses a trust boundary as hostile: no shell
  command built from it, and request bodies read through
  `http.MaxBytesReader`.
- Parameterised SQL, and `crypto/rand` for anything secret. [GCL-gosec]
- A dependency with a known vulnerability your code can reach blocks.
  [GO-VULN]
- Fuzz parsers and decoders of untrusted input with `go test -fuzz`
  (https://go.dev/doc/security/fuzz/).

Names, comments, logging, formatting
- `gofmt` and `goimports`, with two import groups: standard library, then
  everything else. [GH-FMT-001, GH-FMT-002]
- MixedCaps; an initialism keeps one case (`userID`, `ServeHTTP`); short names
  for short scopes; receiver names of one or two letters, consistent, never
  `this` or `self`; no `Get` prefix on a getter. [staticcheck ST1006, ST1016]
- Every exported name has a doc comment: a full sentence that begins with the
  name. [staticcheck ST1020 to ST1022, GH-MNT-002]
- A comment states what the code cannot: a constraint, a reason, an
  invariant. It never restates the code or narrates history, and a doc
  comment stays short. [GH-COMMENT-003, GH-COMMENT-002]
- No em dash (U+2014) in a Go comment; use a hyphen or a new sentence.
  [GH-COMMENT-001, mandatory]
- Log through `log/slog` with a constant message and key-value attributes.
  [GO-VET slog]
- Clear is better than clever.

Tests
- A test must be able to fail. Compare results, and report
  `Func(input) = got, want want`, got before want. [GH-TEST-001, GH-MUT-001]
- Prefer `t.Error` and keep going; `t.Fatal` only when the test cannot
  continue. A helper calls `t.Helper()` first.
- Use the `testing` package. Do not bring an assertion library into a
  repository that has none; where one is in use, use it correctly.
  [GCL-testifylint]
- Table-driven tests when cases share a shape, with readable subtest names.
- Exercise real implementations: an `httptest.Server` and a real client before
  a hand-written mock of the transport.
- `t.TempDir`, `t.Setenv`, `t.Chdir` and `t.Context`, never their `os` and
  `context` counterparts. [GCL-usetesting]
- An `Example` carries an `// Output:` comment, or it never runs.
  [GCL-testableexamples]
- Never weaken a test to pass it. [GH-WEAK-001 to GH-WEAK-004]
- The gate runs the tests under `-race`. A data race is a bug, not a flake.

Before running the gate, review your own diff as a reviewer who knows these
sources would, and fix what you find:
- Is every added line needed for the task?
- Is every error handled exactly once, with context?
- Does every goroutine you started stop, and does something wait for it?
- Would every test you wrote fail if the code it covers were wrong?
- Does every comment say something the code cannot?

The gate will find the rest, but each REJECTED run costs a full suite.

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
