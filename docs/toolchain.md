# goharness Toolchain Provisioning (v0.3)

Status: accepted. Extends `docs/architecture.md` and `docs/admission-model.md`.
Where documents conflict, the newest wins.

## Principles

- Verification commands (`fast`, `verify`, `audit`, `doctor`, `explain`,
  `version`) never install tools, never touch the network, and never mutate
  anything outside `os.MkdirTemp` scratch space. Provisioning is the
  exclusive job of `goharness setup` and `goharness tools update`.
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

Pinned archive checksums (source: official release checksums file):

```
a9c54498731b3128f79e090be6110f3e5fffccc617b08142ed244d4126c73f29  darwin-arm64.tar.gz
f6f06d94b6241521c53d15450c5209b028270bf966f842afb11c030c79f5bc16  darwin-amd64.tar.gz
8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553  linux-amd64.tar.gz
44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a  linux-arm64.tar.gz
bd42e3ebc8cb4ececb86941983baaf1dc221bbb04d838e94ce63b49cc91e02bb  windows-amd64.zip
```

Download URL template:
`https://github.com/golangci/golangci-lint/releases/download/v<ver>/golangci-lint-<ver>-<os>-<arch>.<ext>`

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
