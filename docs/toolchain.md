# goharness Toolchain Provisioning (v0.5)

Status: accepted. Extends `docs/architecture.md` and `docs/admission-model.md`.
Where documents conflict, the newest wins.

## Principles

- Verification commands (`fast`, `verify`, `audit`, `doctor`, `explain`,
  `version`) never install tools and never touch the network. Provisioning is
  the exclusive job of `goharness setup` and `goharness tools update`.
- Verification writes nothing inside the worktree, and outside it only one
  thing: derived evidence, under `derived/` in the cache. That carve-out is
  narrow on purpose (see "Derived evidence" below), and `--no-cache` disables
  it; a run with the flag must reach the same verdict as a run without it.
- Every tool the harness executes is identified by the sha256 of its bytes, not
  by what it prints when asked its version.
- Every downloaded artifact is verified against a checksum pinned in source
  before it is trusted, extracted, or cached. A mismatch aborts the install
  and leaves the cache untouched.
- The vulnerability scanner is embedded; there is no govulncheck executable
  dependency and no PATH lookup for it anywhere in the codebase.

## Pinned versions (additions)

| Component | Pin |
|---|---|
| golang.org/x/vuln (embedded scanner, module dependency) | `v1.7.0` exact in go.mod |
| go.uber.org/goleak (embedded goroutine-leak detector) | `v1.3.0`, sources vendored verbatim under `internal/leakcheck/goleaksrc` (MIT, license included); injected into race runs through a `go test -overlay` virtual package, never installed and never on the network |
| golangci-lint v2.12.2 release archive sha256 | pinned per platform, from the official `golangci-lint-2.12.2-checksums.txt` |

Pinned archive checksums (source: official release checksums file). The archive
sums authorise a download; the binary sums below authorise an execution:

```
a9c54498731b3128f79e090be6110f3e5fffccc617b08142ed244d4126c73f29  darwin-arm64.tar.gz
f6f06d94b6241521c53d15450c5209b028270bf966f842afb11c030c79f5bc16  darwin-amd64.tar.gz
8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553  linux-amd64.tar.gz
44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a  linux-arm64.tar.gz
bd42e3ebc8cb4ececb86941983baaf1dc221bbb04d838e94ce63b49cc91e02bb  windows-amd64.zip
```

Pinned binary checksums (the executable inside each verified archive):

```
691b9100ce968ff0009b6b7757ef6a585e31ae9ab11dfe0340ebb6e8e21fdc3d  darwin-arm64
aed31dd446edae61f420d663369578ab9ddacea4594cafa5bc22b9f59c786cf0  darwin-amd64
e26335d9bd381a60e5769a13b0ccc7967db5b6fb9c39a896a1f6fd0befe0a661  linux-amd64
66dbbe60d3e1fc6b07807be7cbe58fe9ed45afe190018fba2112870e2e30b737  linux-arm64
bed205a512d6ce48a6cce052878fcceb06591bd72d7e6b5e138204ef720eef66  windows-amd64
```

Download URL template:
`https://github.com/golangci/golangci-lint/releases/download/v<ver>/golangci-lint-<ver>-<os>-<arch>.<ext>`

## Binary identity (normative)

Discovery order is unchanged (env override, repository `.tools/`, the cache,
then PATH), but no source is trusted on its word. Every candidate is hashed and
must equal the pinned sum for the platform; a candidate that does not match is
passed over with the reason recorded on the result, and doctor prints it.

The reason is the threat model. `.tools/` lives inside the repository the change
under verification can write to, `GOHARNESS_GOLANGCI_LINT` is one line of shell
away, and a program that prints `golangci-lint has version 2.12.2` and an empty
JSON report takes three lines to write. A version self-report proves nothing;
the bytes do. When nothing trustworthy is found, the linter's obligations are
unproducible and the run is INCONCLUSIVE with `goharness setup` as the remedy;
the harness never falls back to an unverified binary.

A locally built linter is not the pinned release. `go install
github.com/golangci/golangci-lint/...` produces a binary that reports the right
version and hashes to something else, so it is refused: `goharness setup` is the
only supported route.

The sha256 of the binary that produced a verdict is recorded in the report's
versions block.

## Subprocess environment (normative)

Every process the harness starts inherits a sanitised environment:

- `GOFLAGS` is removed. It is spliced into every go invocation, so a single
  `-run` pattern would turn an empty test run into a passing one, and `-tags`
  would change which files exist as far as the toolchain is concerned.
- `GOTOOLCHAIN` is forced to `local`. Verification downloads nothing, and a
  module requiring a toolchain this machine lacks has to fail loudly rather than
  quietly fetching one over the network.
- `GOHARNESS_*` are removed, so code under test cannot read or redirect the
  cache its own verdict depends on.

The same environment is what makes `go fix` safe to run: it is invoked with
`-json`, which reports edits instead of applying them, and with `GOTOOLCHAIN=local`,
so the analyzer set that produced a verdict is the one installed on the machine
and recorded in the report.

Everything else is inherited untouched, `GOPRIVATE`, `GOPROXY`, `GOMODCACHE` and
`GONOSUMDB` among them: module resolution in a real repository depends on them,
and a gate that silently rewrote them would report failures its user cannot
reproduce. The same sanitised environment is given to the package loader and to
the vulnerability scanner, which run the go command too. `doctor` prints what it
takes away, and names the variables your shell sets that will not apply.

## Content-addressed tool cache

Package: `internal/toolcache`. Root: `GOHARNESS_CACHE` env override, else
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

Rules:

- payloads land in `blobs/` under the hex of their own sha256; a blob is
  written to a temp file first and renamed into place (atomic, idempotent);
- the golangci-lint binary is used through its manifest: discovery order
  becomes env override, repository `.tools/`, cache manifest, PATH; a cached
  binary is re-hashed at use and rejected on manifest mismatch;
- the version-pin check applies to every discovery source, unchanged;
- all network fetches go through one injected fetcher (base URL + HTTP
  client) so tests substitute `httptest` servers and verification-command
  tests can prove zero network use.

## Derived evidence (normative)

`verify` re-examines the base revision on every run, and in an agent's repair
loop that is the same untouched commit ten times over. The result is cached
under `derived/base-evidence/`, keyed by a sha256 over everything that could
change it: the goharness version, the go toolchain, the linter version and
binary hash, the x/vuln and goleak versions, the digest of `goharness.yaml`, the
base commit, the native scanner options, the lint and test scope, the exact file
set examined, the generated files exempted, and the planned check IDs.

Rules:

- only derived evidence is cached this way. Tool payloads and vulnerability
  database snapshots remain the exclusive business of `setup` and
  `tools update`, and nothing here ever reaches the network;
- a cache entry is written only when the base run had no check failures, so a
  broken environment is never remembered as a result;
- an unreadable or unwritable cache costs time and nothing else: the run
  recomputes and says so in the log. A verdict never depends on a cache being
  healthy;
- `--no-cache` recomputes. A run with it and a run without it must produce
  byte-identical reports, and a test in `internal/verify` asserts exactly that;
- the directory is bounded (`MaxDerivedEntries`), oldest first, because a cache
  the harness itself would call unbounded has no business shipping in it.

## setup and tools update

- `goharness setup`: provisions everything missing for this machine - the
  pinned golangci-lint for the current platform (download, verify pinned
  sha256, extract, blob, manifest) and an initial vulnerability database
  snapshot. Idempotent: reports what already exists, installs only gaps.
- `goharness tools update`: refreshes the vulnerability database snapshot
  and re-provisions any tool whose pin changed. Snapshot replacement is
  atomic: download into a temp directory, verify, then rename-swap; a
  failed update leaves the previous snapshot in service.
- Both commands print exactly what they downloaded, verified, and wrote,
  with checksums. They are the only commands allowed network access or
  cache writes.

## Embedded vulnerability scanning

`golang.org/x/vuln/scan` replaces the external govulncheck binary. The
scanner runs in-process with `-format json -mode source` against the module
patterns, with `-db file://<cache>/vulndb/current` so scans are strictly
offline. JSON parsing and evidence mapping are unchanged (`GO-VULN`).

The vulnerability database snapshot mirrors https://vuln.go.dev in its v1
layout: `index/db.json`, `index/modules.json`, `index/vulns.json`, and every
entry file the index lists, fetched with bounded concurrency. The snapshot
manifest records the database `modified` timestamp from `index/db.json`, the
fetch time, an entry count, and a tree checksum (sha256 over the sorted
`path:sha256` lines of every file). The implementation must verify
empirically that the x/vuln client accepts the `file://` layout by running a
real scan against a snapshot in an integration test.

If no snapshot exists, the vulnerability-scan obligation is INCONCLUSIVE
with the hint `run goharness setup`; a stale snapshot still scans (the
report and doctor surface its age). Missing evidence is never a pass.

## Reporting and doctor

- The report's versions block gains the x/vuln module version (from build
  info). When the scanner runs, a `vulnDB` block records `source`,
  `modified`, `fetchedAt`, `treeChecksum`, and `entryCount` - all stable per
  snapshot, so byte-determinism of repeated runs is preserved. Volatile
  derived values (age in days) appear only in the human text report and in
  doctor, never in the deterministic JSON portion.
- `doctor` replaces the govulncheck PATH probe with: embedded scanner
  version, snapshot presence, manifest checksum re-verification, and
  freshness (warn when `modified` is older than 7 days, with the exact fix
  command `goharness tools update`). It also reports the cache root, its
  size, and per-tool manifest status. Doctor reads the cache; it never
  writes it.
