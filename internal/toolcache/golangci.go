package toolcache

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"runtime"
	"slices"
	"strings"
	"time"
)

// ToolGolangci is the cache name of the linter.
const ToolGolangci = "golangci-lint"

// MaxArchiveBytes bounds decompression. A release archive of this era is tens
// of megabytes; refusing to expand past this stops a crafted archive from
// exhausting memory, and the checksum has already been verified by the time we
// get here anyway.
const MaxArchiveBytes = 512 << 20

// ArchiveKind is the container a release is shipped in.
type ArchiveKind string

// Supported release archive kinds.
const (
	ArchiveTarGz ArchiveKind = "tar.gz"
	ArchiveZip   ArchiveKind = "zip"
)

// ArchiveSpec fully describes one downloadable tool release: where it comes
// from, what it must hash to, and which file inside it is the binary.
type ArchiveSpec struct {
	Tool       string
	Version    string
	Platform   string
	URL        string
	SHA256     string
	Kind       ArchiveKind
	BinaryName string
}

// golangciArchiveSums are the official per-platform sha256 sums of the pinned
// golangci-lint release, transcribed from the release's checksums file. They
// are the trust anchor for provisioning: an archive that does not match one of
// these is never extracted.
func golangciArchiveSums() map[string]string {
	return map[string]string{
		"darwin-arm64":  "f4bf83f0b64f055c42b28fc9a38861839f69c096e61c788e72dfaae412011789",
		"darwin-amd64":  "8a13aaf9cbbb1dee52824e862cf0d0720e5bb97c1f4260d1e51623a09492b57b",
		"linux-amd64":   "2277d43b98ec0054280f2ac26b53268bae97682444678a59a657dd565da021d6",
		"linux-arm64":   "a2a4e0065aa41be71f7c5ac90f271b61751331e5d04314e62afe4027855f0893",
		"windows-amd64": "4735fdc8e84a0cfb7a15a1c364a650942f88215e0d36c674ebc4024f7b554524",
	}
}

// golangciBinarySums are the sha256 sums of the executable inside each pinned
// release archive. They are the trust anchor for use rather than for download:
// whatever discovery turns up, the file that is about to lint the code must
// hash to the sum recorded here, because a binary that merely prints the right
// version number proves nothing about what it will report.
func golangciBinarySums() map[string]string {
	return map[string]string{
		"darwin-arm64":  "78ffa18bf2d9ffbde06ae76d1a266c0f83d354990bcf9028cb22111dcc3f443e",
		"darwin-amd64":  "f7098c0e8abaaa821d5aa2789d0e5fc06a6a95fd7eef690849d822c9883b6021",
		"linux-amd64":   "97aa6134a250a0f964d112a5e6c01c80f87e4b0512872ebe0845834b5a03b76b",
		"linux-arm64":   "85cc0601d07afb7474837d615ae2efe0c1715d1010a0fedf86a4a6fd4630dfe0",
		"windows-amd64": "6fabccdca5e1f938534194437b114bcd6eedc0a9e58b04994df57c893c565e66",
	}
}

// GolangciBinarySum returns the pinned sha256 of the executable for one
// platform, and whether one is pinned at all.
func GolangciBinarySum(platform string) (string, bool) {
	sum, ok := golangciBinarySums()[platform]
	return sum, ok
}

// SupportedPlatforms lists the platforms with a pinned checksum, sorted.
func SupportedPlatforms() []string {
	return slices.Sorted(slices.Values(keysOf(golangciArchiveSums())))
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// CurrentPlatform is the "os-arch" key this machine provisions for.
func CurrentPlatform() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}

// GolangciSpec builds the archive spec for one platform, refusing any platform
// without a pinned checksum rather than downloading something unverifiable.
func GolangciSpec(version, platform, baseURL string) (ArchiveSpec, error) {
	sum, ok := golangciArchiveSums()[platform]
	if !ok {
		return ArchiveSpec{}, fmt.Errorf(
			"no pinned golangci-lint checksum for platform %q; pinned platforms are %s",
			platform, strings.Join(SupportedPlatforms(), ", "))
	}
	kind, binary := ArchiveTarGz, ToolGolangci
	if strings.HasPrefix(platform, "windows-") {
		kind, binary = ArchiveZip, ToolGolangci+".exe"
	}
	name := fmt.Sprintf("golangci-lint-%s-%s.%s", version, platform, kind)
	return ArchiveSpec{
		Tool:       ToolGolangci,
		Version:    version,
		Platform:   platform,
		URL:        fmt.Sprintf("%s/v%s/%s", strings.TrimRight(baseURL, "/"), version, name),
		SHA256:     sum,
		Kind:       kind,
		BinaryName: binary,
	}, nil
}

// Installation reports what a provisioning step did.
type Installation struct {
	Manifest       ToolManifest
	AlreadyPresent bool
	ArchiveBytes   int
}

// ErrChecksumMismatch reports that a download did not match its pinned sum. The
// cache is untouched when this is returned.
var ErrChecksumMismatch = errors.New("downloaded archive does not match its pinned sha256")

// ProvisionTool installs one pinned release if it is missing or corrupt. The
// archive checksum is verified before anything is extracted, and nothing is
// written to the cache until verification and extraction have both succeeded,
// so a mismatch or a cancellation leaves the cache exactly as it was.
func ProvisionTool(ctx context.Context, cache *Cache, fetcher Fetcher, spec ArchiveSpec) (Installation, error) {
	if existing, err := cache.ReadToolManifest(spec.Tool, spec.Version); err == nil {
		if _, verifyErr := cache.VerifiedToolBinary(spec.Tool, spec.Version); verifyErr == nil &&
			existing.ArchiveSHA256 == spec.SHA256 && existing.Platform == spec.Platform {
			return Installation{Manifest: existing, AlreadyPresent: true}, nil
		}
	}

	archive, err := fetcher.Fetch(ctx, spec.URL)
	if err != nil {
		return Installation{}, err
	}
	if sum := Sum(archive); sum != spec.SHA256 {
		return Installation{}, fmt.Errorf(
			"%w: %s hashes to %s, pinned %s", ErrChecksumMismatch, spec.URL, sum, spec.SHA256)
	}

	binary, err := extractBinary(archive, spec)
	if err != nil {
		return Installation{}, err
	}
	if err := ctx.Err(); err != nil {
		return Installation{}, err
	}

	blob, err := cache.WriteBlob(binary, 0o700)
	if err != nil {
		return Installation{}, err
	}
	manifest := ToolManifest{
		Tool:          spec.Tool,
		Version:       spec.Version,
		Platform:      spec.Platform,
		ArchiveSHA256: spec.SHA256,
		BinarySHA256:  blob,
		Blob:          blob,
		InstalledAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := cache.WriteToolManifest(manifest); err != nil {
		return Installation{}, err
	}
	return Installation{Manifest: manifest, ArchiveBytes: len(archive)}, nil
}

// extractBinary pulls exactly the named executable out of a verified archive.
// Only the base name is compared, so an entry cannot direct the write anywhere:
// nothing from the archive reaches the filesystem as a path.
func extractBinary(archive []byte, spec ArchiveSpec) ([]byte, error) {
	switch spec.Kind {
	case ArchiveTarGz:
		return extractFromTarGz(archive, spec.BinaryName)
	case ArchiveZip:
		return extractFromZip(archive, spec.BinaryName)
	default:
		return nil, fmt.Errorf("unsupported archive kind %q", spec.Kind)
	}
}

func extractFromTarGz(archive []byte, binaryName string) (_ []byte, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("opening the release archive: %w", err)
	}
	defer func() { err = errors.Join(err, gz.Close()) }()

	reader := tar.NewReader(io.LimitReader(gz, MaxArchiveBytes))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the release archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || path.Base(header.Name) != binaryName {
			continue
		}
		binary, err := io.ReadAll(io.LimitReader(reader, MaxArchiveBytes))
		if err != nil {
			return nil, fmt.Errorf("extracting %s: %w", binaryName, err)
		}
		return binary, nil
	}
	return nil, fmt.Errorf("release archive contains no %s", binaryName)
}

func extractFromZip(archive []byte, binaryName string) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("opening the release archive: %w", err)
	}
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() || path.Base(entry.Name) != binaryName {
			continue
		}
		return readZipEntry(entry, binaryName)
	}
	return nil, fmt.Errorf("release archive contains no %s", binaryName)
}

func readZipEntry(entry *zip.File, binaryName string) (_ []byte, err error) {
	file, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("opening %s in the release archive: %w", binaryName, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	binary, err := io.ReadAll(io.LimitReader(file, MaxArchiveBytes))
	if err != nil {
		return nil, fmt.Errorf("extracting %s: %w", binaryName, err)
	}
	return binary, nil
}

// BinaryMode is the permission a provisioned executable carries.
const BinaryMode fs.FileMode = 0o700
