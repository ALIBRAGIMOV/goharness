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
		"darwin-arm64":  "a9c54498731b3128f79e090be6110f3e5fffccc617b08142ed244d4126c73f29",
		"darwin-amd64":  "f6f06d94b6241521c53d15450c5209b028270bf966f842afb11c030c79f5bc16",
		"linux-amd64":   "8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553",
		"linux-arm64":   "44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a",
		"windows-amd64": "bd42e3ebc8cb4ececb86941983baaf1dc221bbb04d838e94ce63b49cc91e02bb",
	}
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
