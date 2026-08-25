# Threat model

goharness decides whether a change is admissible. It runs inside the repository
it is judging, invoked by the party whose work it is judging. That party is
usually an AI coding agent under instruction to reach ADMITTED, and reaching
ADMITTED by editing the gate is cheaper than reaching it by fixing the code.
The operator is therefore not a user to be served but a party whose incentives
point the wrong way, and every mechanism in this document exists because some
route to a verdict the evidence did not support was open and had to be closed.

This is not a document about malice. An agent optimising "pass the gate with
minimum effort" produces the same edits a malicious one would, without intent
and without a record. The design assumption is that anything in the working
tree can be rewritten by the change under judgement, so nothing in the working
tree is taken at its word.

Each section below states one route, the mechanism that closes it, the code and
test that pin it, and the residual risk. Symbol names in this file drift; the
test names are the stable references, and **`internal/verify/bypass_test.go` is
the source of truth**. Where this document and that suite disagree, the suite is
right and this document is stale.

---

## 1. Self-authorization: a change that grants itself permissions

**The route.** A task contract can widen what a change may do: `allowPolicyEdit`
admits an edit to the quality policy, `allowApiBreak` admits a removed or
re-signed exported symbol, `scope` narrows which files are judged. All three
live in a file inside the repository. A change that writes that file has written
its own permission slip.

**The mechanism.** Grants count only from the copy of the contract committed at
the base revision. `resolveContract` reads the base copy through `contractAt`
and merges it with the working-tree copy using `admission.Merge`, which takes
narrowing from the working tree and permissions from the base and from nowhere
else. A grant that appears only in the working tree is dropped, listed in
`contract.ignoredGrants` in the report, and emitted as `GH-POLICY-003`
(`policy.RulePolicyGrant`), which is mandatory and ungrandfatherable.

**Pinned by.** `TestBypassSelfGrantedPolicyEditIsRefused` and
`TestBypassSelfGrantedAPIBreakIsRefused` write a granting contract in the
working tree and require a verdict that is not ADMITTED plus the grant having
had no effect. `TestContractMayStillTightenTheGate` is the paired
false-positive guard: a contract that only narrows scope or declares extra risk
domains still works from the working tree, because narrowing needs no authority.
Both run under every cell of the layout matrix, so the closure holds where the
module is not the git root as well as where it is.

**Residual risk.** A grant committed in an earlier change is at the base
revision of every change after it, and applies until someone removes it. That is
the intended shape: a commit is reviewable and a working-tree edit is not, so
the authority comes from something a human can see in history. It does mean a
grant left in place outlives the task it was written for. The report names every
grant in force under `contract`, so a reviewer sees it without reading the file.

The contract file itself is deliberately not covered by the policy-file guard of
section 2. A `--contract FILE` flag would route around any check on one path, so
guarding it would add friction without adding protection. What matters is that
the grant is inert until committed and that using one leaves an explicit,
reportable record.

## 2. Gate editing: rewriting the policy instead of the code

**The route.** `goharness.yaml` carries exceptions; `goharness.debt.yaml`
carries acknowledged debt. Weakening either is the shortest path from REJECTED
to ADMITTED.

**The mechanism.** `isPolicyFile` (`internal/verify/target.go`) names both
files, and a change that touches either without `allowPolicyEdit` granted at
base emits `GH-POLICY-001` (`policy.RulePolicyEdit`). That rule is in
`MandatoryRuleIDs` and in `UngrandfatherableRuleIDs`: project configuration
cannot downgrade it or except it away, and identical evidence at the base
revision does not let it ride in. Separately, `policy.ParseConfig` refuses an
exception that is missing a rule, a scope, a reason, an owner, or an expiry, and
refuses any exception naming a mandatory rule at all.

**Pinned by.** `TestPolicyFileEditIsRejected`,
`TestPolicyFileEditIsAllowedWhenTheBaseContractDeclaresIt` (the false-positive
guard: the documented, authenticated route still works),
`TestMandatoryRulesCannotBeExceptedOrDowngraded`,
`TestEveryMandatoryRuleIsRefusedAnException`, and
`TestParseConfigRejectsIncompleteExceptions`.

**Residual risk.** The path comparison is exact, which is why it had to be made
robust to a module that is not the git root; before 0.6 the comparison was
against a repository-relative path and the rule did not fire in any monorepo.
The layout matrix in `internal/verify/fixture_test.go` exists so that class of
defect is visible to the suite rather than to a field report.

## 3. Suppression laundering: silencing the linter instead of the finding

**The route.** `//nolint`, `//lint:ignore`, `#nosec` and `//revive:disable` all
silence a finding in place. An outer gate is the only thing that can see a
silencer, so this is the one route that no in-repository configuration can be
trusted to police.

**The mechanism.** `GH-SUPPRESS-001` through `GH-SUPPRESS-004` are mandatory and
ungrandfatherable. They cannot be excepted in `goharness.yaml`, they block even
when identical evidence exists at base, and `DebtRecordable`
(`internal/verify/debt.go`) refuses to write them into a ledger: the debt
machinery is defined as `Blocking(e) && !policy.IsUngrandfatherable(e.RuleID)`,
so an entry for a suppression can be typed into the file by hand and still has
no effect. The scanners read comments off parsed syntax, so the same text inside
a string literal is untouched by construction rather than by a heuristic.

**Pinned by.** `TestSuppressionRulesAreMandatoryAndUngrandfatherable`,
`TestBypassDebtLedgerCannotAcknowledgeASuppression` (which writes a valid
ledger entry for a suppression and requires it to change nothing), and
`TestDebtLedgerAdmitsOnlyBaselineableDebt` as the paired guard that ordinary
debt is still acknowledged.

**Residual risk.** The gate detects the four suppression syntaxes it knows. A
linter this harness does not run, with a directive syntax nobody has seen,
would not be recognised; the strict pack is fixed and the directive vocabulary
is finite, which is what keeps the surface small rather than open-ended.

## 4. Baseline self-authorization: writing off today's findings today

**The route.** `goharness audit --baseline` records the current blocking
findings as acknowledged debt. A change that writes that file as part of itself
would launder its own defects into history.

**The mechanism.** Only the ledger committed at HEAD is read. `ledgerAt`
(`internal/verify/engine.go`) resolves the file at a revision through git, using
the same mechanism `contractAt` uses for grants; the working-tree copy is read
by nothing. Recording happens in `recordBaseline` (`internal/cli/baseline.go`)
after the run has finished and been rendered, so verification itself never
writes the tree. An INCONCLUSIVE run records nothing, because its finding set is
not a complete enumeration and a ledger built from an incomplete one would
acknowledge debt that was never measured.

**Pinned by.** `TestBypassUncommittedDebtLedgerHasNoEffect`,
`TestVerifyIgnoresTheDebtLedger` (the ledger is an audit-mode instrument; the
admission gate compares against a real base revision), and
`TestInconclusiveAuditRecordsNothing`.

**Residual risk.** A committed ledger is a real acceptance surface, deliberately.
Its guards are that the file is reviewable, that the commit that writes it fires
`GH-POLICY-001`, that the ungrandfatherable core is never in it, and that the
report's `baseline` block carries the burn-down and the recorded revision, so a
ratchet that has stopped moving is visible rather than silent.

## 5. Grandfathering abuse: hiding a defect in the base revision

**The route.** Pre-existing findings do not block, so a defect committed first
and judged second rides in as debt. For generated prose and for suppressions,
that is laundering exactly the signal the rule exists to catch.

**The mechanism.** `UngrandfatherableRuleIDs` names the rules that block
whenever they are in scope, regardless of what the base revision contains: the
four suppression rules, both policy guards, and `GH-COMMENT-001`.
`MandatoryRuleIDs` additionally names `GH-BUILD-001`. Neither set may shrink
by accident.

**Pinned by.** `TestMandatoryCoreDoesNotShrink`
(`internal/policy/policy_test.go`) lists both sets literally and fails if a
member disappears. Removing a rule from the core is then a deliberate edit to a
test that says what it is doing, not a line inside a refactor. That guard is
the reason a proposal to reclassify `GH-COMMENT-001` during 0.6 was caught and
retracted rather than shipped.

**Residual risk.** The core is small on purpose: it holds the rules whose whole
value is that history cannot excuse them. Everything else is grandfatherable,
which is what keeps the gate adoptable on a repository with years of debt, and
is a deliberate trade rather than an oversight.

## 6. Hallucinated completion: claiming done without the evidence

**The route.** The most common failure is not an edit at all. It is an agent
reporting a task complete on the strength of a run that did not prove it: a
`fast` run, a run whose tools could not start, or a rejection narrated as a
pass.

**The mechanism.** `sufficientForCompletion` is set in one place, as
`mode.IsAdmissionGate() && verdict == admission.VerdictAdmitted`
(`internal/verify/engine.go`). `fast` is not an admission gate, so its document
always carries `false` however clean the run was. Missing evidence produces
INCONCLUSIVE and never a pass: an obligation that could not be discharged
becomes an `Unproducible` with a remedy, and the claim it belonged to states
that it was not proved. A tool that could not run becomes a `CheckFailure`
attributed to that tool and never becomes evidence about the code.

**Pinned by.** `TestFastIsNeverSufficientForCompletion` and
`TestFastJSONIsNeverSufficientForCompletion`;
`TestAHarnessFaultIsNeverAttributedToTheRepositoryOrItsTools` and
`TestAToolFailureKeepsItsTool`, which enforce the taxonomy line that a harness
fault is never phrased as a fact about the repository;
`TestAuditWithoutASnapshotIsInconclusive` and
`TestToolchainBelowTheModuleFloorMakesSecurityInconclusive`, which are the two
cases where the honest answer is "no answer";
`TestFlakyTestIsInconclusiveNotRejected` as the guard in the other direction.

**Residual risk.** Nothing in the harness can stop a supervisor from believing a
summary instead of reading the document. What it can do is make the disagreement
mechanical: the exit code, `sufficientForCompletion`, and `goharness diff`
between two runs are all checkable without trusting a narration.

## 7. Scanner decoration: teaching operators to write for the checker

**The route.** This one is a defect in the gate, not in the operator. A rule
that fires on the canonical form of the property it defends teaches people to
add code that satisfies the scanner and changes nothing about the program. Once
that habit exists, the gate is producing worse code than it prevents.

**The mechanism.** `GH-CONC-002` used to inspect only a spawn loop's body for a
semaphore or a token channel, so `for range workerCount { go w.run(ctx) }`, the
idiomatic fixed-size pool, was reported as unbounded and adding a redundant
semaphore would have silenced it. `hasStaticIterationBound`
(`internal/analyze/concurrency.go`) now consults the loop's own bound first: a
literal, a named constant, or a struct or config field. A bound derived from a
variable stays reportable at advisory severity, because that is the shape that
can actually be input-derived.

**Pinned by.** `TestCanonicalWorkerPoolsAreNotReported` carries both shapes a
production audit flagged; `TestUnboundedSpawnLoopsAreStillReported` is the
must-still-fire guard, so the fix could not be "report less". This pairing is
required of every precision fix in this repository.

**Residual risk.** Precision is a judgement, and a rule can be wrong in the
other direction without any test noticing. The corpus suite
(`internal/verify/corpus_test.go`, gated behind `GOHARNESS_CORPUS=1`) is the
instrument: it prints per-rule hit counts over published repositories, and a
rule is promoted from advisory to required on that evidence rather than on a
fixture written to make it fire.

## 8. Generated-file laundering: hiding code behind a header

**The route.** Files carrying a `Code generated ... DO NOT EDIT` header are
exempt from judgement, because holding an author responsible for a generator's
output is how a gate gets switched off. Writing that header at the top of
hand-written code converts the exemption into a bypass.

**The mechanism.** `partitionGenerated` (`internal/verify/engine.go`) exempts
only the generated files a change does not touch. A generated file the change
modified is judged like any other file, and modifying one is separately reported
as `GH-POLICY-002` (`policy.RuleGeneratedEdit`), which is advisory: re-running
the generator is the fix, and the edit will be erased either way.

**Pinned by.** `TestBypassGeneratedHeaderOnNewCodeIsStillLinted`, with
`TestGeneratedCodeTheChangeLeavesAloneStaysExempt` as the false-positive guard,
so a repository full of generated code stays adoptable. Both run under every
layout, which is what closed the monorepo case where the exemption test
compared paths in two different coordinate systems and exempted the file
instead of judging it.

**Residual risk.** The header is read from the file's own head, so a generator
whose output does not carry the conventional marker is judged as hand-written
code. That direction is the safe one.

## 9. Evidence-cache tampering: a cached answer that was never computed

**The route.** Verification reuses derived evidence to stay fast enough to run
in a repair loop. A cache entry that can be written by the party being judged is
a way to supply a verdict rather than earn one.

**The mechanism.** Two caches, with different rules. Base evidence
(`internal/verify/basecache.go`) is keyed by the base revision, the resolved
policy, the analyzer options, the tool versions, and the scanned standard
library: every input that can change a finding is in the key, and the base
revision is a commit that cannot change. Head evidence
(`internal/verify/headcache.go`) is deliberately narrower: it covers only the
non-mandatory formatting checks, it is keyed by file content per package, and
every entry carries an integrity hash of its own payload that is verified on
read, with a mismatch treated as a miss. `--no-cache` recomputes everything and
must reach the same verdict.

**Pinned by.** `TestBypassHeadCacheCannotReachTheMandatoryCore` (no mandatory or
ungrandfatherable rule can be answered from the head cache),
`TestPoisonedHeadEntryIsRecomputed`, `TestAnalyzeOptionsAreFullyKeyed`,
`TestBaseEvidenceCacheChangesNothingButTheClock`,
`TestHeadFormatCacheChangesNothingButTheClock`, and
`TestHeadFormatCacheInvalidatesOnlyTheEditedPackage` as the guard that the cache
is doing real work rather than being disabled.

**Residual risk, stated plainly.** Anyone who can write the cache directory can
delete entries, and can replace an entry's payload together with its integrity
hash. The integrity hash detects corruption and version drift, not a determined
local writer. The cache root is a per-user directory outside the repository, so
this requires local write access to the operator's own machine rather than a
commit to the repository; a caller that needs to exclude it entirely runs with
`--no-cache`, and CI should.

## 10. Worktree mutation during verification

**The route.** Evidence is only about the tree that produced it. A tool with
side effects, a concurrent editor, or a check that wrote a fixture would leave
the report describing a tree that no longer exists.

**The mechanism.** `repo.CaptureSnapshot` records the worktree before the run
and `applyWorktreeGuard` (`internal/verify/engine.go`) re-reads it afterwards. A
difference is a `CheckFailure` attributed to git plus an `Unproducible` for
`worktree-readonly`, which makes the run INCONCLUSIVE rather than letting it
report a verdict about a vanished tree. Every write command is outside
verification: `setup`, `tools update`, `fix`, and the ledger recording that
happens after `verify.Run` has returned.

**Pinned by.** `TestEveryCommandLeavesTheWorktreeUnchanged`
(`internal/cli/cli_test.go`) runs every command against a fixture and compares
`git status --porcelain` before and after, and the corpus suite asserts the same
property over real repositories.

**Residual risk.** The snapshot is a status comparison, so a change that is
written and reverted inside one run is invisible to it. Nothing in the harness
writes the tree, and the guard exists to catch the case where something else
does.

## 11. Environment and toolchain substitution

**The route.** A verdict that depends on the operator's environment can be moved
by the operator. `GOFLAGS=-tags=nonsense` can exclude the test suite;
`GOTOOLCHAIN` can select a standard library; a locally built golangci-lint can
report the pinned version while behaving differently.

**The mechanism.** Subprocesses run under `VerificationEnv`, which strips
`GOFLAGS` and every `GOHARNESS_*` setting and forces `GOTOOLCHAIN=local`,
passing through only what module resolution genuinely needs (`GOPRIVATE`,
`GOPROXY`, `GOMODCACHE`). Every golangci-lint candidate is verified against a
pinned per-platform binary sha256, so a `go install` build is refused however it
identifies itself. The scanned standard library is resolved through the same
sanitised runner and recorded as `versions.goStdlib`, so two runs that disagree
about it are visibly not comparable.

**Pinned by.** `TestBypassGoflagsCannotSilenceTheTestSuite`,
`TestBypassForgedLinterIsNotTrusted`, `TestHostileEnvironmentCannotMoveTheReport`,
`TestReportsAreByteIdenticalAcrossWorkingDirectories`, and
`TestVerificationMakesNoNetworkRequests`.

**Residual risk.** A repository whose `go.mod` declares a `toolchain` newer than
the host's is scanning a standard library the repository forbids. Rather than
downloading a toolchain during verification, the harness detects the gap and
makes the security claim INCONCLUSIVE naming both versions
(`TestToolchainBelowTheModuleFloorMakesSecurityInconclusive`), with
`TestToolchainAtOrAboveTheFloorStillScans` as the guard.

---

## Future work

Runtime probes beyond goroutine leaks (file-descriptor and socket leaks,
flakiness detection, fuzz-smoke for decoders of external input) are the category
static analysis cannot follow into, and they are deferred rather than dropped.
New rule machinery enters advisory and experimental and is promoted only on
corpus evidence, and that calibration is the gating work.

## Adding a bypass case

`internal/verify/bypass_test.go` holds one case per route by which a change
could once have been admitted without the evidence to justify it. The discipline
around it is fixed:

1. **A bypass found in the field becomes a red test before it becomes a fix.**
   The test is written first, against the shape that actually occurred, and it
   fails. Only then is the mechanism changed.
2. **Every case asserts a verdict that is not ADMITTED, or asserts that a grant
   had no effect.** Asserting that a particular finding appeared is weaker: the
   property being defended is the verdict, not the message.
3. **Every closure is paired with a false-positive guard.** For each case above,
   a second test asserts that the legitimate shape still passes, so the fix
   cannot be "reject more". A closure without a guard is not finished.
4. **Cases run under `eachLayout`.** Five of six defects in the first field
   report were invisible to a suite that built one repository layout and ran
   from one directory. A case that holds only where the module is the git root
   is a case that does not hold.
5. **Never soften a check to make your own code pass.** If one of the harness's
   own rules fires on new code here, the code is wrong. A rule that is genuinely
   too imprecise to block is reclassified advisory in the registry with a
   written rationale, in public, and the corpus suite is the evidence.
