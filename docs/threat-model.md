# Threat model

goharness decides whether a change is admissible. It runs inside the repository
it is judging, invoked by the party whose work it is judging. That party is
usually a coding agent under instruction to reach ADMITTED, and reaching
ADMITTED by editing the gate is cheaper than reaching it by fixing the code.
The operator is therefore not a user to be served but a party whose incentives
point the wrong way, and every mechanism in this document exists because some
route to a verdict the evidence did not support was open and had to be closed.

This is not a document about malice. An agent optimising "pass the gate with
minimum effort" produces the same edits a malicious one would, without intent
and without a record. The design assumption is that anything in the working
tree can be rewritten by the change under judgement, so nothing in the working
tree is taken at its word.

Each section states one route, the mechanism that closes it, the test that
pins it, and the residual risk. Symbol names drift; the test names are the
stable references, and **`internal/verify/bypass_test.go` is the source of
truth**. Where this document and that suite disagree, the suite is right and
this document is stale.

---

## 1. Self-authorization: a change that grants itself permissions

**The route.** A task contract can widen what a change may do: `allowPolicyEdit`
admits an edit to the quality policy, `allowApiBreak` admits a removed or
re-signed exported symbol, `scope` narrows which files are judged. All three
live in a file inside the repository. A change that writes that file has written
its own permission slip.

**The mechanism.** Grants count only from the copy of the contract committed at
the base revision. The working-tree copy contributes narrowing and nothing
else. A grant that appears only in the working tree is dropped, listed in
`contract.ignoredGrants`, and emitted as `GH-POLICY-003`, which is mandatory
and ungrandfatherable.

**Pinned by.** `TestBypassSelfGrantedPolicyEditIsRefused` and
`TestBypassSelfGrantedAPIBreakIsRefused`, with
`TestContractMayStillTightenTheGate` as the false-positive guard: a contract
that only narrows scope or declares extra risk domains still works from the
working tree, because narrowing needs no authority. Both run under every cell
of the layout matrix.

**Residual risk.** A grant committed in an earlier change applies until someone
removes it. That is the intended shape: a commit is reviewable and a
working-tree edit is not. The report names every grant in force under
`contract`, so a reviewer sees it without reading the file. The contract file
itself is deliberately not a policy file of section 2: a `--contract FILE` flag
would route around any check on one path, and what matters is that a grant is
inert until committed.

## 2. Gate editing: rewriting the policy instead of the code

**The route.** `goharness.yaml` carries exceptions; `goharness.debt.yaml`
carries acknowledged debt. Weakening either is the shortest path from REJECTED
to ADMITTED.

**The mechanism.** A change that touches either file without `allowPolicyEdit`
granted at base emits `GH-POLICY-001`, mandatory and ungrandfatherable: project
configuration cannot downgrade it or except it, and identical evidence at base
does not let it ride in. Separately, the configuration parser refuses an
exception missing a rule, a scope, a reason, an owner or an expiry, refuses any
exception naming a mandatory rule, and refuses an override that lowers a
classification.

**Pinned by.** `TestPolicyFileEditIsRejected`,
`TestPolicyFileEditIsAllowedWhenTheBaseContractDeclaresIt`,
`TestMandatoryRulesCannotBeExceptedOrDowngraded`,
`TestEveryMandatoryRuleIsRefusedAnException`,
`TestParseConfigRejectsIncompleteExceptions`.

**Residual risk.** The path comparison is exact, which is why it had to be made
robust to a module that is not the git root. The layout matrix in
`internal/verify/fixture_test.go` keeps that class of defect visible to the
suite rather than to the first user whose module is not the git root.

## 3. Suppression laundering: silencing the linter instead of the finding

**The route.** `//nolint`, `//lint:ignore`, `#nosec` and `//revive:disable`
silence a finding in place. An outer gate is the only thing that can see a
silencer, so this is the one route no in-repository configuration can be
trusted to police.

**The mechanism.** `GH-SUPPRESS-001` through `GH-SUPPRESS-004` are mandatory
and ungrandfatherable. They cannot be excepted, they block on a pre-existing
finding on any line the change wrote, and the debt machinery refuses to record
them, so a ledger entry for a suppression can be typed by hand and still has no
effect. The scanners read comments off parsed syntax, so the same text inside a
string literal is untouched by construction.

**Pinned by.** `TestSuppressionRulesAreMandatoryAndUngrandfatherable`,
`TestBypassDebtLedgerCannotAcknowledgeASuppression`, and
`TestDebtLedgerAdmitsOnlyBaselineableDebt` as the guard that ordinary debt is
still acknowledged.

**Residual risk.** The gate detects the suppression syntaxes it knows. A linter
this harness does not run, with a directive syntax nobody has seen, would not
be recognised; the strict pack is fixed and the directive vocabulary finite,
which keeps the surface small.

## 4. Baseline self-authorization: writing off today's findings today

**The route.** `goharness audit --baseline` records the current blocking
findings as acknowledged debt. A change that writes that file as part of itself
would launder its own defects into history.

**The mechanism.** Only the ledger committed at HEAD is read; the working-tree
copy is read by nothing. Recording happens in the command layer after the run
has finished and been rendered, so verification never writes the tree. An
INCONCLUSIVE run records nothing.

**Pinned by.** `TestBypassUncommittedDebtLedgerHasNoEffect`,
`TestVerifyIgnoresTheDebtLedger`, `TestInconclusiveAuditRecordsNothing`.

**Residual risk.** A committed ledger is a real acceptance surface,
deliberately. Its guards are that the file is reviewable, that the commit
writing it fires `GH-POLICY-001`, that the ungrandfatherable core is never in
it, and that the report's `baseline` block carries the burn-down.

## 5. Grandfathering abuse: hiding a defect in the base revision

**The route.** Pre-existing findings do not block, so a defect committed first
and judged second rides in as debt. For inline suppressions and the policy
guards that is laundering exactly the signal the rule exists to catch.

**The mechanism.** `UngrandfatherableRuleIDs` names the rules that block on a
pre-existing finding: the four suppression rules, both policy guards, and
`GH-COMMENT-001`. In a change gate they do so on the lines the change wrote,
which is where laundering would have to happen: a directive the change adds is
`new` and blocks wherever it is, and one it rewrites or moves sits on an added
line and blocks however old it is. In an audit they block everywhere.
`MandatoryRuleIDs` additionally names `GH-BUILD-001`. Neither set may shrink by
accident.

A pre-existing directive the change leaves as it found it, in a file it edited,
does not block the change. It is reported beside it, counted per file in
`summary.debtInChangedFiles`, and rejects an audit. The previous rule, that
any directive in an edited file blocks, made a repository with legacy debt
unable to admit anything: an author who appended one function to a file carrying three old
directives could neither fix findings they did not write nor except them,
because the exception is a policy edit no change may grant itself, and a gate
nobody can pass is routed around rather than obeyed.

**Pinned by.** `TestMandatoryCoreDoesNotShrink` lists both sets literally;
`TestBypassARewrittenOldSuppressionStillRejects` is the case that a rewritten
directive blocks; `TestAnOldSuppressionInAnEditedFileIsDebtNotRejection` and
`TestAnOldSuppressionTheChangeNeverOpenedDoesNotReject` are the guards that
old debt on untouched lines is reported and does not reject.

**Residual risk.** The base is what decides "pre-existing", so this closure is
only as good as the base revision (section 16). The core is small on purpose:
it holds the rules whose whole value is that history cannot excuse them.

## 6. Hallucinated completion: claiming done without the evidence

**The route.** The most common failure is not an edit at all. It is an agent
reporting a task complete on the strength of a run that did not prove it: a
`fast` run, a run whose tools could not start, or a rejection narrated as a
pass.

**The mechanism.** `sufficientForCompletion` is set in one place, as an
admission gate whose verdict is ADMITTED. `fast` is not an admission gate, so
its document always carries `false`. Missing evidence produces INCONCLUSIVE
and never a pass; a tool that could not run becomes a `CheckFailure`
attributed to that tool and never evidence about the code.

**Pinned by.** `TestFastIsNeverSufficientForCompletion`,
`TestFastJSONIsNeverSufficientForCompletion`,
`TestAHarnessFaultIsNeverAttributedToTheRepositoryOrItsTools`,
`TestAToolFailureKeepsItsTool`, `TestAuditWithoutASnapshotIsInconclusive`,
`TestToolchainBelowTheModuleFloorMakesSecurityInconclusive`, and
`TestFlakyTestIsInconclusiveNotRejected` as the guard in the other direction.

**Residual risk.** Nothing in the harness can stop a supervisor from believing
a summary instead of reading the document. What it can do is make the
disagreement mechanical: the exit code, `sufficientForCompletion`, and
`goharness diff` between two runs are checkable without trusting a narration.
Section 15 closes the one case where the document itself was the narration.

## 7. Scanner decoration: teaching operators to write for the checker

**The route.** A defect in the gate, not in the operator. A rule that fires on
the canonical form of the property it defends teaches people to add code that
satisfies the scanner and changes nothing about the program.

**The mechanism.** `GH-CONC-002` consults a spawn loop's own bound before its
body: a literal, a named constant, or a struct or config field. A bound derived
from a variable stays reportable at advisory severity.

**Pinned by.** `TestCanonicalWorkerPoolsAreNotReported` and
`TestUnboundedSpawnLoopsAreStillReported`. This pairing is required of every
precision fix in this repository.

**Residual risk.** Precision is a judgement. The corpus suite
(`internal/verify/corpus_test.go`, gated behind `GOHARNESS_CORPUS=1`) prints
per-rule hit counts over published repositories, and a rule is promoted from
advisory to required on that evidence.

## 8. Generated-file laundering: hiding code behind a header

**The route.** Files carrying a `Code generated ... DO NOT EDIT` header are
exempt from judgement. Writing that header at the top of hand-written code
converts the exemption into a bypass.

**The mechanism.** Only the generated files a change does not touch are
exempt. A generated file the change modified is judged like any other file, and
modifying one is separately reported as `GH-POLICY-002`, advisory.

**Pinned by.** `TestBypassGeneratedHeaderOnNewCodeIsStillLinted`, with
`TestGeneratedCodeTheChangeLeavesAloneStaysExempt` as the guard, both under
every layout.

**Residual risk.** A generator whose output does not carry the conventional
marker is judged as hand-written code. That direction is the safe one.

## 9. Evidence-cache tampering: a cached answer that was never computed

**The route.** Verification reuses derived evidence to stay fast enough for a
repair loop. A cache entry the judged party can write is a way to supply a
verdict rather than earn one.

**The mechanism.** Base evidence is keyed by the base revision, the resolved
policy, the analyzer options, the tool versions, the leak-check method and the
scanned standard library, and the base revision is a commit that cannot change.
Head evidence covers only the non-mandatory formatting checks, is keyed by file
content per package, and carries an integrity hash verified on read.
`--no-cache` recomputes everything and must reach the same verdict.

**Pinned by.** `TestBypassHeadCacheCannotReachTheMandatoryCore`,
`TestPoisonedHeadEntryIsRecomputed`, `TestAnalyzeOptionsAreFullyKeyed`,
`TestBaseEvidenceCacheChangesNothingButTheClock`,
`TestHeadFormatCacheChangesNothingButTheClock`,
`TestHeadFormatCacheInvalidatesOnlyTheEditedPackage`.

**Residual risk, stated plainly.** Anyone who can write the cache directory
can replace an entry together with its integrity hash. The hash detects
corruption and version drift, not a determined local writer. The root is a
per-user directory outside the repository, so this needs write access to the
operator's own machine; CI runs with `--no-cache`.

## 10. Worktree mutation during verification

**The route.** Evidence is only about the tree that produced it. A tool with
side effects, a concurrent editor, or a check that wrote a fixture would leave
the report describing a tree that no longer exists.

**The mechanism.** The worktree is snapshotted before the run and re-read
afterwards on a context cancellation cannot reach. A difference is a
`CheckFailure` attributed to git plus an unproducible `worktree-readonly`
obligation, so the run is INCONCLUSIVE. Every write command is outside
verification: `setup`, `tools update`, `skill install`, `fix`, and the ledger
recording that happens after the run has returned.

**Pinned by.** `TestEveryCommandLeavesTheWorktreeUnchanged`, and the corpus
suite asserts the same property over real repositories.

**Residual risk.** The snapshot is a status comparison, so a change written and
reverted inside one run is invisible to it.

## 11. Environment and toolchain substitution

**The route.** A verdict that depends on the operator's environment can be
moved by the operator: `GOFLAGS=-tags=nonsense` excludes the test suite,
`GOTOOLCHAIN` selects a standard library, a locally built golangci-lint reports
the pinned version while behaving differently.

**The mechanism.** Subprocesses run under a sanitised environment that strips
`GOFLAGS` and every `GOHARNESS_*` setting and forces `GOTOOLCHAIN=local`.
Every golangci-lint candidate is verified against a pinned per-platform sha256.
The scanned standard library is resolved through the same sanitised runner and
recorded as `versions.goStdlib`.

**Pinned by.** `TestBypassGoflagsCannotSilenceTheTestSuite`,
`TestBypassForgedLinterIsNotTrusted`,
`TestHostileEnvironmentCannotMoveTheReport`,
`TestReportsAreByteIdenticalAcrossWorkingDirectories`,
`TestVerificationMakesNoNetworkRequests`.

**Residual risk.** A module whose `go.mod` declares a `toolchain` newer than
the host's is judged against a standard library the module forbids; the
security claim is INCONCLUSIVE naming both versions rather than downloading a
toolchain during verification.

## 12. A compiler error standing in for a test

**The route.** `go test` exits 1 whether a test failed or the mutated package
never compiled. A change whose only mutable construct was a `return err` on a
value that is not an error produced one mutant, which did not build, which
counted as killed, which discharged the test-effectiveness claim for the whole
change. The tests never ran.

**The mechanism.** The overlaid run reads the `-json` event stream. A package
that did not build is a third outcome beside passed and failed; a mutant that
did not build is neither a kill nor a survivor, and a change where no mutant
compiled is INCONCLUSIVE.

**Pinned by.** `TestBypassUncompilableMutantIsNotAKill`, with
`TestMutationEvidencePassesWhenTestsKillMutants` as the guard and
`TestOverlayOutcomeTellsAFailedBuildFromAFailedTest` on the decoder.

**Residual risk.** The operators are few, and a change whose functions offer
them nothing is discharged with `coverage.mutation` recording zero mutants
rather than left INCONCLUSIVE with no remedy. That is a stated limit, visible
in the report: code without a branch, a comparison or an error return is code
the operators cannot damage, and the tests, the race detector and every other
producer still apply to it.

## 13. A dependency the gate never scanned

**The route.** Only `audit` planned the vulnerability scan, so `verify`
admitted a change that added a requirement on a module with a known reachable
vulnerability.

**The mechanism.** The `dependency` risk domain, activated by `go.mod`,
`go.sum`, `go.work`, `go.work.sum` and `vendor/modules.txt`, adds the
vulnerability scan to the security claim in `verify`, at base as well as head.
`GH-DEP-001` reports every new direct requirement, advisory.

**Pinned by.** `TestBypassVulnerableDependencyIsNotAdmittedByVerify`, with
`TestVerifyWithoutADependencyChangeDoesNotScan`,
`TestPreexistingVulnerabilityIsDebtInVerify`,
`TestSQLMigrationRewriteIsRejected` and `TestNewDirectRequirementIsReported`.

**Residual risk.** Reachability can change without the module set changing;
that case is found by `audit`, and the plan says so in its coverage.

## 14. A build constraint that hides a failing test

**The route.** A test that would fail stays in the tree, and the change adds
`//go:build integration` above it, or renames the file onto another platform's
suffix. `go test` runs nothing there and reports nothing; the test-shape
comparison still parsed the file and saw the test present at both revisions,
so no deletion was reported either.

**The mechanism.** Test shapes are measured as the build the gate runs sees
them: a test file is evaluated against the default build context with the same
`go/build` matching the toolchain uses, and one the build excludes contributes
no shapes. A constraint typed above a failing test is therefore the test's
deletion and is reported as `GH-WEAK-003`.

**Pinned by.** `TestBypassABuildConstraintCannotHideAFailingTest`, with
`TestASatisfiedBuildConstraintKeepsATestCounted` as the guard that a
constraint this configuration satisfies leaves the test counted.

**Residual risk.** The judgement is per configuration. A constraint another
platform satisfies is honest on that platform and a deletion on this one, and
the run states which configuration it judged; CI on more than one platform
judges both.

## 15. An empty change certified as completion

**The route.** An agent commits its work and verifies against the commit it
just made, or verifies a tree it never edited. The diff holds nothing, every
claim is vacuously discharged, and the document says ADMITTED with
`sufficientForCompletion: true`: a completion certificate for work the gate
never saw, and the one case where the document itself was the narration of
section 6.

**The mechanism.** A change set with no entry, in this module or outside it,
makes the `change-visible` obligation unproducible with the reason that nothing
differs between the base revision and the working tree, so the verdict is
INCONCLUSIVE and completion is not sufficient. A change that touches no Go
file is still a change and is judged normally. `audit` is exempt: it answers
for the repository, not for a diff.

**Pinned by.** `TestBypassAnEmptyChangeIsNotSufficientForCompletion`, with
`TestADocumentationOnlyChangeIsStillAChange` as the guard.

**Residual risk.** A base chosen to shrink the change without emptying it is
section 16's problem; the report records `change.baseOrigin` either way.

## 16. The wrong base: blaming a working tree for the last commit

**The route.** On the default branch, the merge-base with that branch is HEAD
itself, and the harness fell back to the parent commit. The change under
judgement then included the last commit, which on a shared clone is somebody
else's work: the working tree was blamed for that commit's suppressions and
debt, and would have been credited for its fixes. Conversely, an agent working
on the default branch could commit a suppression and have it judged as the
previous commit's.

**The mechanism.** When HEAD is on the default branch and the working tree
carries uncommitted work, the base is HEAD: the uncommitted work is the change.
With a clean tree the last commit is the only candidate there is and is still
judged against its parent. An explicit `--base` overrides both, and the report
records which rule applied.

**Pinned by.**
`TestBypassUncommittedWorkOnTheDefaultBranchDoesNotInheritTheLastCommit`, with
`TestACleanTreeOnTheDefaultBranchJudgesTheLastCommit` as the guard.

**Residual risk.** The base is chosen from what the repository offers, and an
explicit `--base` is the operator's word. A reviewer checks
`change.baseOrigin` and `change.base` in the document, which is why both are
in it; the agent skill says never to choose a base that shrinks the change.

## 17. A leak that had not parked when the tests returned

**The route.** The injected `TestMain` read the `goroutineleak` profile once,
the moment the package's tests returned. The runtime reports a goroutine as
leaked only once it is parked on something nothing reachable can wake, and a
goroutine that has not run yet has not parked. On a loaded machine, or on one
processor, a test that starts a goroutine and drops the only way to stop it
returns before that goroutine is scheduled, and the package came out clean.
The change leaked and was admitted; CI on a shared runner was where it showed.

**The mechanism.** The generated `TestMain` samples the profile again, with
pauses doubling from one millisecond to 128, while any goroutine other than
its own remains. A leaked goroutine stays leaked, so waiting can only find
more, and a package whose goroutines have all exited ends after the first
sample. The detector's name in the report and in the base-evidence cache key
changed with it, so evidence from the single-sample detector never answers
for this one.

**Pinned by.** `TestBypassALeakNotYetParkedWhenTheTestsReturnIsCaught` and
`TestInjectedTestMainCatchesALeakBeforeItIsScheduled`, with
`TestInjectedTestMainDoesNotReportAReachableGoroutine` as the guard.

**Residual risk.** A goroutine that parks after the quarter of a second the
sampling allows is still missed. That is a test that sleeps past its own end,
and the leak shows on the next change that exercises the same code.

---

## Future work

Runtime probes beyond goroutine leaks (file-descriptor and socket leaks,
flakiness detection, fuzz-smoke for decoders of external input) are the
category static analysis cannot follow into, and they are deferred rather than
dropped. New rule machinery enters advisory and experimental and is promoted
only on corpus evidence, and that calibration is the gating work.

## Adding a bypass case

`internal/verify/bypass_test.go` holds one case per route by which a change
could once have been admitted without the evidence to justify it. The
discipline around it is fixed:

1. **A bypass found in use becomes a red test before it becomes a fix.**
   The test is written first, against the shape that actually occurred, and it
   fails. Only then is the mechanism changed.
2. **Every case asserts a verdict that is not ADMITTED, or asserts that a grant
   had no effect.** Asserting that a particular finding appeared is weaker: the
   property being defended is the verdict, not the message.
3. **Every closure is paired with a false-positive guard.** For each case, a
   second test asserts that the legitimate shape still passes, so the fix
   cannot be "reject more". A closure without a guard is not finished.
4. **Cases run under `eachLayout`.** A case that holds only where the module is
   the git root is a case that does not hold.
5. **Never soften a check to make your own code pass.** If one of the
   harness's own rules fires on new code here, the code is wrong. A rule that
   is genuinely too imprecise to block is reclassified advisory in the
   registry, in public, with a written rationale, and the corpus suite is the
   evidence.
