# Toolchain provisioning

This document states how goharness obtains, verifies and caches the tools it
runs, and what verification is allowed to write. `docs/architecture.md`
holds the pins; where the two disagree, either is a defect.

## Principles

- Verification commands (`fast`, `verify`, `audit`, `doctor`, `explain`,
  `diff`, `version`) never install tools and never touch the network.
  Provisioning is the job of `goharness setup` and `goharness tools update`.
- Verification writes nothing inside the worktree, and outside it only one
  thing: derived base evidence, under `derived/` in the cache. `--no-cache`
  disables it, and a run with the flag must reach the same verdict as a run
  without it.
- Every tool the harness executes is identified by the sha256 of its bytes,
  never by what it prints when asked its version.
- Every downloaded artifact is verified against a checksum pinned in source
  before it is trusted, extracted or cached. A mismatch aborts the install
  and leaves the cache untouched.
- The vulnerability scanner is embedded; no govulncheck executable, no PATH
  lookup for it anywhere in the code.
- Goroutine-leak evidence needs no tool at all: the Go runtime's
  `goroutineleak` profile is read by a `TestMain` the harness generates.

## Pins

| Component | Pin |
|---|---|
| Go, on the host | `go1.27.0` or later (`go/version` decides; a release candidate is below its release, and the bare language version is below both) |
| golangci-lint | `2.13.2`, release archive sha256 per platform from the official checksums file, and the sha256 of the executable inside it |
| `golang.org/x/vuln` | `v1.7.0` exact in `go.mod` |
| goroutine-leak detection | `runtime/pprof` profile `goroutineleak`, Go 1.27 or later on the host |

Pinned archive checksums. The archive sums authorise a download; the binary
sums authorise an execution:

```
a9c54498731b3128f79e090be6110f3e5fffccc617b08142ed244d4126c73f29  darwin-arm64.tar.gz
f6f06d94b6241521c53d15450c5209b028270bf966f842afb11c030c79f5bc16  darwin-amd64.tar.gz
8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553  linux-amd64.tar.gz
44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a  linux-arm64.tar.gz
bd42e3ebc8cb4ececb86941983baaf1dc221bbb04d838e94ce63b49cc91e02bb  windows-amd64.zip
```

Pinned binary checksums:

```
691b9100ce968ff0009b6b7757ef6a585e31ae9ab11dfe0340ebb6e8e21fdc3d  darwin-arm64
aed31dd446edae61f420d663369578ab9ddacea4594cafa5bc22b9f59c786cf0  darwin-amd64
e26335d9bd381a60e5769a13b0ccc7967db5b6fb9c39a896a1f6fd0befe0a661  linux-amd64
66dbbe60d3e1fc6b07807be7cbe58fe9ed45afe190018fba2112870e2e30b737  linux-arm64
bed205a512d6ce48a6cce052878fcceb06591bd72d7e6b5e138204ef720eef66  windows-amd64
```

Download URL template:
`https://github.com/golangci/golangci-lint/releases/download/v<ver>/golangci-lint-<ver>-<os>-<arch>.<ext>`

## Binary identity

Discovery order is `GOHARNESS_GOLANGCI_LINT`, the repository's `.tools/`,
the cache, then `PATH`, and no source is trusted on its word. Every
candidate is hashed and must equal the pinned sum for the platform; one that
does not match is passed over with the reason recorded, and `doctor` prints
it.

The reason is the threat model. `.tools/` lives inside the repository the
change under verification can write to, the environment variable is one
line of shell away, and a program that prints `golangci-lint has version
2.13.2` and an empty JSON report takes three lines to write. A version
self-report proves nothing; the bytes do. When nothing trustworthy is found,
the linter's obligations are unproducible and the run is INCONCLUSIVE with
`goharness setup` as the remedy. The harness never falls back to an
unverified binary, and a locally built one (`go install`) reports the right
version, hashes to something else, and is refused.

The sha256 of the binary that produced a verdict is recorded in the report's
`versions` block.

## Subprocess environment

Every process the harness starts inherits a sanitised environment:

- `GOFLAGS` is removed. It is spliced into every go invocation, so a single
  `-run` pattern would turn an empty test run into a passing one, and
  `-tags` would change which files exist as far as the toolchain is
  concerned.
- `GOTOOLCHAIN` is forced to `local`. Verification downloads nothing, and a
  module requiring a toolchain this machine lacks has to fail loudly rather
  than fetch one. When the installed toolchain is older than the module's
  `toolchain` directive, the vulnerability obligation goes unproducible
  naming both versions, and `doctor` reports the gap first.
- `GOHARNESS_*` are removed, so code under test cannot read or redirect the
  cache its own verdict depends on.

Everything else is inherited untouched, `GOPRIVATE`, `GOPROXY`, `GOMODCACHE`
and `GONOSUMDB` among them: module resolution in a real repository depends on
them, and a gate that silently rewrote them would report failures its user
cannot reproduce. The package loader and the vulnerability scanner get the
same environment. `doctor` prints what is taken away.

## The content-addressed cache

Package `internal/toolcache`. Root: `GOHARNESS_CACHE`, else
`os.UserCacheDir()/goharness`. Layout:

```
blobs/sha256/<hex>                immutable content-addressed payloads
tools/golangci-lint/<version>/manifest.json
    {platform, archiveSHA256, binarySHA256, blob, installedAt}
vulndb/current/                   the active database snapshot
vulndb/current/manifest.json
    {source, modified, fetchedAt, treeChecksum, entryCount}
derived/base-evidence/<key>.json  cached base-revision results
```

- Payloads land in `blobs/` under the hex of their own sha256, written to a
  temporary file and renamed into place.
- A cached binary is re-hashed at use and rejected on manifest mismatch.
- All network fetches go through one injected fetcher, so tests substitute
  `httptest` servers and the verification-command tests prove zero network
  use.

## Derived evidence

`verify` re-examines the base revision on every run, and in an agent's
repair loop that is the same untouched commit ten times over. The result is
cached under `derived/base-evidence/`, keyed by a sha256 over everything
that could change it: the goharness version, the go toolchain and the
standard library it judges, the linter version and binary hash, the scanner
version, the leak-check method, the digest of `goharness.yaml`, the base
commit, the native scanner options, the lint and test scope, the exact file
set examined, the generated files exempted, and the planned check IDs.

- Only derived evidence is cached this way. Tool payloads and snapshots are
  the business of `setup` and `tools update`, and nothing here reaches the
  network.
- An entry is written only when the base run had no check failures, so a
  broken environment is never remembered as a result.
- An unreadable or unwritable cache costs time and nothing else; a verdict
  never depends on the cache being healthy.
- `--no-cache` recomputes, and a test asserts the two reports are
  byte-identical.
- The directory is bounded, oldest entries first.

Anyone who can write the cache directory can replace an entry together with
its integrity hash; the hash detects corruption and drift, not a determined
local writer. The root is a per-user directory outside the repository, so
this needs write access to the operator's own machine. CI runs with
`--no-cache`.

## setup, tools update, skill install

- `goharness setup` provisions everything this machine is missing: the
  pinned golangci-lint for the platform (download, verify, extract, blob,
  manifest), an initial vulnerability database snapshot, and the agent skill
  for the current user (`--no-skill` leaves it out). Idempotent: it reports
  what exists and installs only gaps.
- `goharness tools update` refreshes the snapshot and re-provisions any tool
  whose pin moved. Replacement is atomic: download into a temporary
  directory, verify, rename-swap; a failed update leaves the previous
  snapshot in service.
- `goharness skill install` writes the skill for the current user, or with
  `--project` into a repository. A file goharness did not write is left
  alone and named; `--force` replaces it.

These three are the only commands that reach the network or write outside a
repository, and each prints exactly what it downloaded, verified and wrote.

## Embedded vulnerability scanning

`golang.org/x/vuln/scan` runs in-process, in source mode, against the module
patterns, with `-db file://<cache>/vulndb/current`, so scans are strictly
offline. The snapshot mirrors `https://vuln.go.dev` in its v1 layout:
`index/db.json`, `index/modules.json`, `index/vulns.json`, and every entry
file the index lists. Its manifest records the database `modified` time, the
fetch time, an entry count and a tree checksum over the sorted
`path:sha256` lines of every file. An integration test runs a real scan
against a snapshot served from `httptest`, so the `file://` layout is
verified rather than assumed.

No snapshot means the vulnerability obligation is INCONCLUSIVE with
`goharness setup` as the hint; a stale snapshot still scans, and the report
and `doctor` say how old it is. `audit` plans the scan on every run;
`verify` plans it when the change touches `go.mod`, `go.sum`, `go.work`,
`go.work.sum` or `vendor/modules.txt`, at base as well as head, so a
vulnerability the base already carried is debt and one the change brought in
blocks.

## Reporting and doctor

- The report's `versions` block carries the go toolchain, the standard
  library judged, the linter version, pin, match and sha256, the scanner
  version, the leak-check method and the Uber guide commit. When the scanner
  ran, a `vulnDb` block records the snapshot's source, modified time, fetch
  time, checksum and entry count, all stable per snapshot. Volatile values
  such as an age in days appear only in the human report and in `doctor`.
- `doctor` reports the toolchain, git, the module and its toolchain floor,
  golangci-lint discovery and pin match, the `go fix` analyzer set, stale
  worktrees, the sanitised environment, the scanner and its snapshot with
  freshness, the cache root and size, and the agent skill copies for each
  supported agent, with the exact command that fixes each problem. Doctor
  reads the cache; it never writes it.
