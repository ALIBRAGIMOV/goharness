package cli

import (
	"maps"
	"strings"
)

const usageText = `goharness - trustworthy admission of production-grade Go changes

A change is ADMITTED only when every applicable quality claim has sufficient
evidence. Missing evidence is INCONCLUSIVE, never a pass.

Commands
  verify        admission gate: the diff, its reverse dependencies, base/head
                comparison, and the full claims model
  audit         repository audit: the whole codebase at head, every risk domain
                active, plus vulnerability scanning and repo-wide race detection
  fast          developer loop aid over changed packages and their direct
                dependents; NOT an admission gate
  setup         provision the pinned tools and the vulnerability database once
  tools update  refresh the vulnerability database and re-provision moved pins
  fix           apply one rule's mechanical remediation (writes files)
  explain       explain a rule ID, or a finding by fingerprint with --report
  diff          compare two reports: fixed, introduced, remaining, by identity
  doctor        report the environment, tool pins, cache, and stale state
  skill         print the agent skill, or install it for Claude Code and Codex
  help, version this text, "help <command>", "help contract"; the version and pins

Flags for verify, audit and fast
  --json              emit the goharness.report/v2 document
  --agent             machine protocol: JSON on stdout, human text on stderr
  --report FILE       write the JSON document to FILE, not to stdout
  --dir DIR           any directory inside the module to verify (default ".")
  --base REV          explicit base revision (verify only)
  --contract FILE     task contract (default: goharness.task.yaml, else implicit)
  --timeout DURATION  wall-clock budget (default 20m; audit is unlimited)
  --jobs N            checks to run at once (default: one per CPU)
  --explain-plan      print the obligation set and exit
  --no-cache          recompute the base snapshot instead of reusing evidence
  --evidence MODE     full, diff, new or top (verify defaults to diff)
  --quiet             reduce output to the verdict line
  --no-color          never colourise (NO_COLOR is honoured too)
  -v, -vv, --log-json INFO, then DEBUG diagnostics on stderr, JSON with --log-json

The other commands take their own flags; "goharness help <command>" lists them.

Exit codes (verification commands; "goharness help diff" gives diff's own)
  0   ADMITTED       every applicable claim has sufficient evidence
  1   REJECTED       at least one applicable claim failed
  2   INCONCLUSIVE   evidence was missing, or a tool could not be trusted
  130 aborted        a second interrupt stopped the run immediately

Agent protocol
  Finish a task only via "goharness verify --agent". Stdout is then one
  goharness.report/v2 JSON document and the human report goes to stderr. If the
  run cannot start (no module, unknown flag) stdout is empty and the exit code
  is 2, so check it before parsing.

  Work the document in this order:
    sufficientForCompletion  the task may be called done only when it is true
    claims[].state           FAIL: fix it. INCONCLUSIVE: produce the evidence
                             named in claims[].missingEvidence
    unproducible[]           why an obligation could not be discharged, each
                             with .remedy, the action that would produce it
    evidence[].blocking      true stops admission; false is advisory or
                             pre-existing debt and does not have to be fixed
    evidence[].origin        added-line, changed-file, changed-package or
                             untouched: how close it is to what this change
                             wrote. new plus untouched blocks like anything new
    evidence[]               consequence order: silent-loss, unsafe-behavior,
                             structural, hygiene; work it so, never by count
    evidence[].fix.command   the exact command that closes that finding
    summary, coverage        counts of the whole run; what it left out; a
                             narrowed evidence[] declares evidenceOmitted
    failures[]               a tool that could not run, each with .hint; a
                             failure is never a statement about the code

  "goharness explain RULE-ID", or FINGERPRINT with --report, explains any
  finding; where one carries a goharness fix command, that command applies it.
  "goharness fast" is never sufficient. "goharness setup" provisions tools
  once; verification never installs anything or uses a network.

Examples
  goharness verify --agent
  goharness verify --agent --evidence full > report.json

Run "goharness help <command>" for details on any command.
`

func commandUsage(command string) string {
	if text, ok := perCommandUsage()[command]; ok {
		return text
	}
	return usageText
}

// hasCommandUsage reports whether a help topic exists.
func hasCommandUsage(command string) bool {
	_, ok := perCommandUsage()[command]
	return ok
}

// perCommandUsage holds every help topic. Topics outnumber commands: the task
// contract is a file format an agent has to get right and has nowhere else to
// be documented at the terminal.
func perCommandUsage() map[string]string {
	usage := verificationUsage()
	maps.Copy(usage, provisioningUsage())
	maps.Copy(usage, referenceUsage())
	usage["update"] = usage["tools"]
	return usage
}

// verifyUsage is its own constant because it is the topic an agent reads
// first and the longest of them; inlining it made the map that holds every
// verification topic too large to read.
const verifyUsage = `usage: goharness verify [--agent] [--json] [--report FILE]
                        [--dir DIR] [--base REV] [--contract FILE]
                        [--evidence MODE] [--timeout D] [--jobs N] [--explain-plan]
                        [--no-cache] [--quiet] [--no-color] [-v|-vv] [--log-json]

Admission gate. Verifies the diff plus its reverse dependency closure,
compares evidence against the base revision, and produces the full claim
table. This is the command an agent must finish with.

The report is about the change. Every finding carries two axes. state says
whether the base revision already had it: new, preexisting, fixed. origin says
how close it sits to the code this change wrote:

  added-line       on a line this change wrote
  changed-file     in a file it edited, on a line that predates it
  changed-package  in a package holding a file it edited, in another file
  untouched        anywhere else in the reverse dependency closure

--evidence selects which of them the report carries. verify defaults to diff:
everything blocking, everything new or fixed, and every finding on a line this
change wrote. Debt that predates the change in a file it edited is counted per
file, in summary.debtInChangedFiles and on one line of the text report, rather
than listed. full prints everything, new prints only what the change moved,
and top prints full cut to --evidence-limit. Every mode keeps every blocking
row, so a narrower report changes how much there is to read and never what
has to be fixed; evidenceScope names the view and evidenceOmitted counts what
it withheld.

--report FILE writes the JSON document to a file and leaves the stream for the
human report, which is what an editor or agent bridge with a short timeout
needs.

Reverse dependencies stay in scope whatever the report shows, because a change
in one package can break another it never opened. Such a finding is new and
untouched, and it blocks.

Rules that block even on a finding the base revision already had, inline
suppressions above all, do so on the lines this change wrote: one it adds,
rewrites or moves rejects the change. One that predates the change, in a file
it edited or anywhere else, is reported as debt and rejects an audit instead.

The base revision is the merge-base with the default branch; on the default
branch itself it is HEAD while the working tree carries uncommitted work, and
the parent commit once everything is committed. --base names it explicitly,
and the report records which applied. A commit cannot change, so base
evidence is cached and reused; --no-cache recomputes it and must reach the
same verdict.

A task contract narrows scope or records a permission: see
"goharness help contract".

Examples
  goharness verify --agent
  goharness verify --base HEAD~3
  goharness verify --evidence full
  goharness verify --agent --report report.json
  goharness verify --contract task.yaml --json
`

func verificationUsage() map[string]string {
	return map[string]string{
		"verify": verifyUsage,
		"audit": `usage: goharness audit [--agent] [--json] [--dir DIR] [--timeout D] [--jobs N]
                       [--baseline] [--quiet] [--no-color] [-v|-vv] [--log-json]

Repository audit. Evaluates the whole codebase at head with every risk
domain active, adding vulnerability scanning against the provisioned
database snapshot and repository-wide race detection. No base comparison:
every finding is judged on its own, except the debt an accepted ledger
already records.

The debt ledger (goharness.debt.yaml)
  --baseline records this audit's blocking findings as acknowledged debt,
  after the run, in goharness.debt.yaml at the module root. It is a ratchet,
  not a discount:

    * only the copy committed at HEAD counts, so a change can never baseline
      itself; an uncommitted ledger changes nothing;
    * editing the file is an edit to the gate and is reported as
      GH-POLICY-001 like any other edit to the policy;
    * the mandatory core (inline suppressions, the policy guards, generated
      prose) is never recorded and never silenced by any ledger;
    * the bar for anything the ledger does not name does not move, and the
      report carries a baseline block with the burn-down.

  An INCONCLUSIVE run records nothing: its finding set is not a complete
  enumeration. "verify" ignores the ledger entirely; it compares against a
  real base revision.

The policy shadow
  Where the repository carries its own .golangci.yml or .golangci.yaml, an
  audit also reports what that configuration hides from itself, measured
  against the strict pack. It is a report section only: it never changes a
  claim, the verdict, or the exit code.

Examples
  goharness audit
  goharness audit --json > audit.json
  goharness audit --baseline && git add goharness.debt.yaml
`,
		"fast": `usage: goharness fast [--agent] [--json] [--dir DIR] [--timeout D] [--jobs N]
                      [--quiet] [--no-color] [-v|-vv] [--log-json]

Developer loop aid over changed packages and their direct dependents.
It is NOT an admission gate: its JSON always carries
sufficientForCompletion: false. Finish with goharness verify --agent.

Examples
  goharness fast
  goharness fast --json
`,
	}
}

func provisioningUsage() map[string]string {
	return map[string]string{
		"setup": `usage: goharness setup [--platform OS-ARCH] [--no-skill]

Provisions everything this machine is missing: the pinned golangci-lint
release, verified against its checksum before extraction, an initial
vulnerability database snapshot, and the agent skill, installed where Claude
Code and Codex read skills from (--no-skill leaves it out; "goharness help
skill" has the paths). Idempotent, so running it twice downloads nothing the
second time.

Together with "goharness tools update" and "goharness skill install" this is
the only command that reaches the network or writes outside the repository.

Environment
  GOHARNESS_CACHE            where tools and snapshots live
  GOHARNESS_GOLANGCI_LINT    an explicit golangci-lint binary, checked against
                             the pinned version and checksum like any other

Examples
  goharness setup
  GOHARNESS_CACHE=/opt/goharness-cache goharness setup
`,
		"skill": `usage: goharness skill print
       goharness skill install [--project] [--dir DIR] [--force]

The agent skill: the completion protocol, the report's reading order and the
routes an agent must not take, in the Agent Skills format that Claude Code
and Codex read. "goharness setup" installs it for the current user; this
command prints it, or installs it for a repository.

  print       write the skill to stdout
  install     write it where the agents read it:
                ~/.claude/skills/goharness/SKILL.md   Claude Code
                ~/.agents/skills/goharness/SKILL.md   Codex
              --project writes the same two paths under the repository root
              found from --dir (default "."), where a commit carries them to
              every checkout and every cloud session
  --force     replace a file at one of those paths that goharness did not
              write; without it such a file is named and left alone

A copy goharness wrote is replaced by every newer release, so the protocol an
agent follows is always the one the installed binary enforces.

Examples
  goharness skill install
  goharness skill install --project && git add .claude .agents
  goharness skill print
`,
		"tools": `usage: goharness tools update [--platform OS-ARCH]

Refreshes the vulnerability database snapshot and re-provisions any tool
whose pin has changed. The snapshot is replaced atomically: a failed update
leaves the previous snapshot in service.

Examples
  goharness tools update
`,
	}
}

func referenceUsage() map[string]string {
	return map[string]string{
		"explain": `usage: goharness explain RULE-ID
       goharness explain FINGERPRINT --report FILE

Prints the registry entry for any rule the harness can emit: GH-*, GCL-*,
UBER-*, and GO-* (including the GO-FIX-* analyzers). Unknown IDs suggest the
nearest match. Rules whose remediation has a shape worth copying also print a
compliant pattern.

Given an evidence fingerprint and the report it came from, prints that one
finding (rule, location, message, consequence, remedy class, state, whether it
blocks) followed by the rule's entry. This is what makes a truncated report
usable: every row it omits is still resolvable by its fingerprint.

Examples
  goharness explain GH-SUPPRESS-001
  goharness explain GCL-errcheck
  goharness explain 3f2a91c4d0b7e615 --report report.json
`,
		"diff": `usage: goharness diff [--json] [--no-color] [--allow-scope-mismatch]
                      OLD.json NEW.json

Compares two goharness.report/v2 documents on fingerprint identity and reports
what was fixed, what was introduced, and what remains, split blocking from
advisory, grouped by consequence class and then by rule. It also states the
verdict transition and every claim that moved.

Fingerprints are content-based and carry no line numbers, so a finding keeps
its name across unrelated edits: this measures repair rather than movement.
It reads nothing but the two files: no git, no cache, no worktree, no network.

Exit codes, which are NOT the verification exit codes
  0   nothing blocking was introduced; fixed and remaining findings are fine
  1   the newer report carries blocking evidence the older one did not
  2   a report could not be read, parsed, or is not goharness.report/v2

Two reports of different modules or modes are still compared, with a warning
line and subjectMismatch: true, because refusing would hide the mismatch
rather than state it.

Two reports written under different --evidence scopes are refused with exit 2,
because that comparison is arithmetic rather than a burn-down: rows the
narrower one never carried come out as repairs nobody made.
--allow-scope-mismatch reads the counts as the mechanical comparison they are.
A truncated report says so too, and the comparison then covers the rows it
carries rather than the whole run.

Examples
  goharness verify --agent --json > before.json
  goharness verify --agent --json > after.json
  goharness diff before.json after.json
  goharness diff --json before.json after.json > burndown.json
`,
		"fix": `usage: goharness fix --rule RULE-ID [--dry-run] [--dir DIR]

Applies the mechanical remediation for one rule across the module. This is a
write command: no verification command can reach it, and admission still
re-verifies afterwards, so a fix is a convenience and never evidence.

  --rule RULE-ID  the rule to fix; without one, the supported rules are listed
  --dry-run       print a unified diff and write nothing
  --dir DIR       directory inside the module to fix (default ".")

Rewrites work on parsed syntax, so a string literal that contains the same text
as a comment is untouched by construction rather than by a pattern that tries to
tell them apart. Files that do not parse are left alone; so are testdata,
vendor, and directories beginning with a dot or an underscore.

Examples
  goharness fix --rule GH-COMMENT-001 --dry-run
  goharness fix --rule GH-COMMENT-001
`,
		"doctor": `usage: goharness doctor [--dir DIR]

Reports the toolchain, git, module, golangci-lint discovery and pin match,
the go fix analyzer set this toolchain registers, the embedded vulnerability
scanner and its database snapshot, the cache root and size, and stale
goharness worktrees, with the exact command that fixes each problem. Doctor
only reads the cache; it never writes it, and its output is never colourised.

Exit codes: 0 healthy, 2 problems found.

Examples
  goharness doctor
`,
		"contract": `usage: goharness help contract

A task contract is an optional goharness.task.yaml at the repository root, or
any file passed with --contract. It declares what a task may do. It can narrow
scope and record a permission; it can never lower the quality bar.

  goal: migrate the retry loop off the deprecated helper
  scope:
    - internal/verify/
    - internal/tool/exec.go
  risks:
    - concurrency
    - hot-path
  allowApiBreak: false
  allowPolicyEdit: false
  budgets:
    BenchmarkFingerprint:
      maxTimeIncreasePercent: 5
      maxAllocIncreasePercent: 0

Every key is optional.

  goal             one sentence, recorded in the report
  scope            paths the change may touch: an exact file, a glob, or a
                   subtree written with a trailing slash or "...". A changed
                   file outside it is GH-SCOPE-001
  risks            domains to activate even where detection would not:
                   concurrency, network, persistence, public-api, tests,
                   hot-path, dependency
  allowApiBreak    admit a removed or re-signed exported symbol
  allowPolicyEdit  admit a change to goharness.yaml
  budgets          per-benchmark limits for the base/head comparison

Grants count only when they were committed at the base revision, because a
change that writes its own permission is authorising itself. A grant that
appears only in the working tree is ignored, reported as GH-POLICY-003, and
listed under contract.ignoredGrants in the report.

Examples
  goharness verify --contract task.yaml --agent
`,
		"help": `usage: goharness help [command]

With no argument, prints the global usage: the command table, common flags,
the exit-code table, and the agent protocol. With a command, prints that
command's usage and examples. "goharness help contract" documents the task
contract file.

Examples
  goharness help
  goharness help verify
  goharness help contract
`,
		"version": "usage: goharness version\n\nPrints the harness version and every pinned component.\n\nExamples\n  goharness version\n",
	}
}

// knownCommands is the set nearest-match suggestion searches.
func knownCommands() []string {
	return []string{
		"verify", "audit", "fast", "setup", "tools", "fix",
		"explain", "diff", "doctor", "skill", "help", "version",
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n") + "\n"
}
