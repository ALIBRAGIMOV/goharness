# Philosophy

This document states what goharness is for, the principles it holds to, and
the engineering ideology its own code follows. The other documents under
`docs/` describe the mechanism; this one describes the bet behind it. Where
a design choice in the code cannot be explained from this page, the choice
is suspect.

## The bet

Strong coding agents make code cheap. What they do not make cheap is the
proof that a change may be accepted: that it compiles everywhere it is used,
that its tests observe it, that it leaks nothing, breaks no caller, hides
nothing behind a comment, and moves no bar to get in. When the writing is
nearly free, the scarce good is admission, and admission has to rest on
evidence that does not depend on who, or what, wrote the change.

goharness is the trust and control layer between autonomous software agents
and production Go codebases. It is not a linter with more rules. It is the
answer to one question, asked once per change: is this admissible?

## Three layers

**Verification.** Deterministic evidence from the toolchain and from runtime:
compilation, vet, `go fix`, tidy, a pinned golangci-lint, the tests under the
race detector, the runtime's goroutine-leak profile, mutation of the changed
functions, benchmark deltas, a vulnerability scan, native scanners, and a
comparison of head against the base revision. Every producer is either a
tool the module already trusts or a scanner whose precision the corpus has
measured.

**Engineering policy, a constitution as code.** What is admissible in *this*
repository: the strict pack, the rules a project adds, the exceptions it
records with an owner and an expiry, the debt it has acknowledged. Policy
only ever tightens. Nothing in a repository's configuration can lower the
floor, and the floor itself, the suppression ban and the policy guards,
cannot be configured at all.

**Agent completion.** The loop an agent finishes with: `goharness verify
--agent`, one JSON document, `sufficientForCompletion`, a remedy on every
obligation the run could not discharge, and escalation to a person as a
valid outcome. The gate is a control loop around the agent, never inside
it. It has no opinion about how the change was made and takes nothing in
the working tree at its word.

## Six principles

1. **Evidence over confidence.** A verdict rests on what ran, and a tool that
   could not run produces INCONCLUSIVE, never a pass. Missing evidence is a
   different job from a failing claim, and the report says which one you
   have.
2. **Minimal change over cleverness.** The report is about the change: what
   it wrote, what it broke, what it fixed. Debt it did not write is counted
   and left for the audit, so that an agent is never pushed into rewriting
   code it was not asked to touch in order to get its own code in.
3. **Project intent over generic best practice.** A repository's policy
   file, contract and ledger are the project speaking, and they are read in
   preference to any general rule, in the one direction they are allowed to
   speak: stricter.
4. **Invariants over implementation path.** The gate judges properties of
   the result, not the route taken to it. Two runs over one tree produce
   byte-identical reports; a report is a function of the repository, the
   revision, the policy and the database, and of nothing else.
5. **Independent verification.** The author is never the judge. That holds
   for an agent verifying its own change, for a contract that grants itself
   permission, for a ledger written by the change it would excuse, and for
   this harness judging its own code.
6. **Human escalation is a valid result.** A rule that is wrong for a piece
   of code is an argument to have with a person, in a reviewed file, with a
   reason. It is never an argument to have with the gate.

## No model in the verdict path

Nothing probabilistic decides admission. A language model may order
attention, draft a remedy, or explain a rule; it may never turn a FAIL into
a PASS or decide what counts as evidence. The verdict is a conjunction over
claims, each claim a conjunction over obligations, each obligation
discharged by a named producer with a recorded version. That is what makes
the verdict reproducible by anyone with the same tree, and what makes it
worth trusting when the author is a model.

## Engineering memory

Reasons travel with findings. Every rule carries its rationale and its
remedy; every exception carries an owner and a reason; every closed bypass
carries the test that keeps it closed and the field report that found it.
The repository's own history of what it decided and why lives in reviewed
files, not in the heads of the people who were there. An agent that reads
the report reads the reasons too.

## Go first

goharness is written for Go and holds itself to the standard the language's
maintainers hold the standard library to: simple over clever, explicit over
implicit, deterministic over fast, honest about what it does not know. The
standard library comes first; adding a dependency is an architecture
decision recorded in `docs/architecture.md`, and the module carries three.
The Go toolchain is the semantic authority: where it can answer, no other
tool is asked.

## The ideology the code holds to

These are the rules the harness enforces on other repositories, and so the
rules it cannot break in its own:

- **Never write an inline suppression.** A finding that is wrong is fixed in
  the code, or excepted in `goharness.yaml` with a scope, an owner, a reason
  and an expiry. The suppression rules are mandatory and ungrandfatherable
  everywhere, including here.
- **Never soften a check to make your own code pass.** A check that fires on
  new code here means the code is wrong. A check too imprecise to block is
  reclassified advisory in the registry, in public, with a written
  rationale, and the corpus is the evidence.
- **INCONCLUSIVE over PASS.** When the harness does not know, it says so and
  names the remedy. It never rounds an absence of evidence up.
- **Determinism.** Fingerprints exclude line numbers and every volatile
  value. Nothing time-based or random enters the deterministic part of a
  report, and CI proves two runs are byte-identical on every push.
- **A tool fault is never a code fact.** A crash, a timeout or an
  unresolvable path is a failure attributed to the tool or to goharness,
  with a hint, and is never phrased as a statement about the repository.
- **Read-only verification.** No network, no installs, no writes inside the
  tree. The base worktree is temporary, the cache holds only derived
  evidence keyed by content, and a change to the tree during a run makes
  the run INCONCLUSIVE.
- **Comments state constraints the code cannot express.** No comment
  restates the code; no comment narrates a changelog; every exported symbol
  has a short doc comment.
- **Context first, termination visible.** Anything that blocks, spawns a
  process or can be cancelled takes a context first; every goroutine's
  termination path is visible where it is launched; cleanup runs on a
  context that cancellation cannot reach.
- **No globals, no `init`, no `panic`** outside the last-resort handler in
  `main`. Checks return values; the coordinator owns aggregation.
- **New rules enter advisory and experimental.** They become required on
  corpus evidence over published repositories, never on the strength of a
  fixture written to make them fire.
- **A bypass becomes a test before it becomes a fix.** Every route to an
  unearned ADMITTED that was ever open has a case in the bypass suite, red
  before the closure and paired with a guard that the legitimate shape still
  passes.
