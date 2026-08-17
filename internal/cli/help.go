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
  deep          deprecated alias for audit
  setup         provision the pinned tools and the vulnerability database once
  tools update  refresh the vulnerability database and re-provision moved pins
  explain       print the registry entry for any rule ID
  doctor        report the environment, tool pins, cache, and stale state
  help          print this text, "help <command>", or "help contract"
  version       print the version and every pin

Flags for verify, audit, fast and deep
  --json              emit the goharness.report/v2 document
  --agent             machine protocol: JSON on stdout, human text on stderr
  --dir DIR           directory inside the module to verify (default ".")
  --base REV          explicit base revision (verify only)
  --contract FILE     task contract (default: goharness.task.yaml, else implicit)
  --timeout DURATION  wall-clock budget (default 10m; audit is unlimited)
  --explain-plan      print the obligation set and exit
  --no-cache          recompute the base snapshot instead of reusing evidence
  --quiet             reduce output to the verdict line
  --no-color          never colourise (NO_COLOR is honoured too)
  -v, -vv             INFO, then DEBUG diagnostics on stderr
  --log-json          structured log lines instead of console format

The other commands take their own flags and reject these: setup and
tools update take --platform OS-ARCH, doctor takes --dir DIR, explain takes one
rule ID and no flags.

Exit codes
  0   ADMITTED       every applicable claim has sufficient evidence
  1   REJECTED       at least one applicable claim failed
  2   INCONCLUSIVE   evidence was missing, or a tool could not be trusted
  130 aborted        a second interrupt stopped the run immediately

Agent protocol
  Finish a task only via "goharness verify --agent". Stdout is then one
  goharness.report/v2 JSON document and the human report goes to stderr. If the
  run cannot start at all (no module, unknown flag) stdout is empty, stderr
  says why, and the exit code is 2, so check the exit code before parsing.

  Work the document in this order:
    sufficientForCompletion  the task may be called done only when it is true
    claims[].state           FAIL: fix it. INCONCLUSIVE: produce the evidence
                             named in claims[].missingEvidence
    unproducible[]           why an obligation could not be discharged, each
                             with .remedy, the action that would produce it
    evidence[].blocking      true stops admission; false is advisory or
                             pre-existing debt and does not have to be fixed
    evidence[].fix.command   the exact command that closes that finding, where
                             a tool could state it rather than guess
    failures[]               a tool that could not run, each with .hint; a
                             failure is never a statement about the code

  "goharness explain RULE-ID" explains any finding you see.
  "goharness fast" is never sufficient to finish a task. "goharness setup"
  provisions tools once; verification never installs anything and never
  touches the network.

Examples
  goharness verify --agent
  goharness verify --base origin/main --json > report.json
  goharness help contract

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
	usage["deep"] = usage["audit"] + "\nNote: deep is a deprecated alias for audit.\n"
	usage["update"] = usage["tools"]
	return usage
}

func verificationUsage() map[string]string {
	return map[string]string{
		"verify": `usage: goharness verify [--agent] [--json] [--dir DIR] [--base REV]
                        [--contract FILE] [--timeout D] [--explain-plan]
                        [--no-cache] [--quiet] [--no-color] [-v|-vv] [--log-json]

Admission gate. Verifies the diff plus its reverse dependency closure,
compares evidence against the base revision, and produces the full claim
table. This is the command an agent must finish with.

The base revision is a commit that cannot change, so its evidence is cached
and reused; --no-cache recomputes it and must reach the same verdict.

A task contract narrows scope or records a permission: see
"goharness help contract".

Examples
  goharness verify --agent
  goharness verify --base HEAD~3
  goharness verify --contract task.yaml --json
`,
		"audit": `usage: goharness audit [--agent] [--json] [--dir DIR] [--timeout D]
                       [--quiet] [--no-color] [-v|-vv] [--log-json]

Repository audit. Evaluates the whole codebase at head with every risk
domain active, adding vulnerability scanning against the provisioned
database snapshot and repository-wide race detection. No base comparison:
every finding is judged on its own.

Examples
  goharness audit
  goharness audit --json > audit.json
`,
		"fast": `usage: goharness fast [--agent] [--json] [--dir DIR] [--timeout D]
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
		"setup": `usage: goharness setup [--platform OS-ARCH]

Provisions everything this machine is missing: the pinned golangci-lint
release, verified against its checksum before extraction, and an initial
vulnerability database snapshot. Idempotent, so running it twice downloads
nothing the second time.

Together with "goharness tools update" this is the only command that reaches
the network or writes the cache.

Environment
  GOHARNESS_CACHE            where tools and snapshots live
  GOHARNESS_GOLANGCI_LINT    an explicit golangci-lint binary, checked against
                             the pinned version and checksum like any other

Examples
  goharness setup
  GOHARNESS_CACHE=/opt/goharness-cache goharness setup
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

Prints the registry entry for any rule the harness can emit: GH-*, GCL-*,
UBER-*, and GO-* (including the GO-FIX-* analyzers). Unknown IDs suggest the
nearest match.

Examples
  goharness explain GH-SUPPRESS-001
  goharness explain GO-FIX-inline
  goharness explain UBER-ERR-001
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
                   hot-path
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
		"verify", "audit", "fast", "deep", "setup", "tools",
		"explain", "doctor", "help", "version",
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n") + "\n"
}
