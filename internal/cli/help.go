package cli

import "strings"

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
  help          print this text, or per-command help with "help <command>"
  version       print the version and every pin

Common flags
  --json              emit the goharness.report/v2 document
  --agent             machine protocol: JSON on stdout, human text on stderr
  --dir DIR           directory inside the module to verify (default ".")
  --base REV          explicit base revision (verify only)
  --contract FILE     task contract (default: goharness.task.yaml, else implicit)
  --timeout DURATION  wall-clock budget (default 10m for verify, unlimited for audit)
  --explain-plan      print the obligation set and exit
  --quiet             reduce output to the verdict line
  --no-color          never colourise (NO_COLOR is honoured too)
  -v, -vv             INFO, then DEBUG diagnostics on stderr
  --log-json          structured log lines instead of console format

Exit codes
  0   ADMITTED       every applicable claim has sufficient evidence
  1   REJECTED       at least one applicable claim failed
  2   INCONCLUSIVE   evidence was missing, or a tool could not be trusted
  130 aborted        a second interrupt stopped the run immediately

Agent protocol
  Finish a task only via "goharness verify --agent". In that mode stdout is
  exactly one goharness.report/v2 JSON AdmissionDecision; the human report goes
  to stderr. Treat the task as done only when sufficient_for_completion is true.
  Otherwise work the claims table: fix every FAIL claim, and produce the missing
  evidence named by every INCONCLUSIVE claim. "goharness explain RULE-ID"
  explains any finding you see. "goharness fast" is never sufficient to finish.
  "goharness setup" provisions tools once; verification never installs anything
  and never touches the network.

Examples
  goharness verify --agent
  goharness verify --base origin/main --json > report.json

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

func perCommandUsage() map[string]string {
	usage := map[string]string{
		"verify": `usage: goharness verify [--agent] [--json] [--dir DIR] [--base REV]
                        [--contract FILE] [--timeout D] [--explain-plan]
                        [--quiet] [--no-color] [-v|-vv] [--log-json]

Admission gate. Verifies the diff plus its reverse dependency closure,
compares evidence against the base revision, and produces the full claim
table. This is the command an agent must finish with.

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
		"fast": `usage: goharness fast [--json] [--dir DIR] [--quiet] [--no-color] [-v|-vv]

Developer loop aid over changed packages and their direct dependents.
It is NOT an admission gate: its JSON always carries
sufficient_for_completion: false. Finish with goharness verify --agent.

Examples
  goharness fast
  goharness fast --json
`,
		"setup": `usage: goharness setup [--platform OS-ARCH]

Provisions everything this machine is missing: the pinned golangci-lint
release, verified against its checksum before extraction, and an initial
vulnerability database snapshot. Idempotent, so running it twice downloads
nothing the second time.

Together with "goharness tools update" this is the only command that reaches
the network or writes the cache.

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
		"explain": `usage: goharness explain RULE-ID

Prints the registry entry for any rule the harness can emit: GH-*, GCL-*,
UBER-*, and GO-*. Unknown IDs suggest the nearest match.

Examples
  goharness explain GH-SUPPRESS-001
  goharness explain UBER-ERR-001
`,
		"doctor": `usage: goharness doctor [--dir DIR] [--no-color]

Reports the toolchain, git, module, golangci-lint discovery and pin match,
the embedded vulnerability scanner and its database snapshot, the cache root
and size, and stale goharness worktrees, with the exact command that fixes
each problem. Doctor only reads the cache; it never writes it.

Exit codes: 0 healthy, 2 problems found.

Examples
  goharness doctor
`,
		"help": `usage: goharness help [command]

With no argument, prints the global usage: the command table, common flags,
the exit-code table, and the agent protocol. With a command, prints that
command's usage and examples.

Examples
  goharness help
  goharness help verify
`,
		"version": "usage: goharness version\n\nPrints the harness version and every pinned component.\n",
	}
	usage["deep"] = usage["audit"] + "\nNote: deep is a deprecated alias for audit.\n"
	usage["update"] = usage["tools"]
	return usage
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
