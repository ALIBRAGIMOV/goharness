package cli

import (
	"context"
	"errors"
	"flag"
	"strings"

	"github.com/ALIBRAGIMOV/goharness/internal/tool"
	"github.com/ALIBRAGIMOV/goharness/internal/toolcache"
)

// runSetup provisions everything this machine is missing. It is one of the two
// commands allowed to reach the network or write the cache, and it is
// idempotent: an already provisioned tool is reported, not re-downloaded.
func runSetup(ctx context.Context, args []string, streams Streams) int {
	fs := flag.NewFlagSet("goharness setup", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	platform := fs.String("platform", toolcache.CurrentPlatform(),
		"provision for this os-arch instead of the current machine")
	noSkill := fs.Bool("no-skill", false, "do not install the agent skill for Claude Code and Codex")
	if err := fs.Parse(args); err != nil {
		return ExitInconclusive
	}

	out := newPrinter(streams.Out)
	errOut := newPrinter(streams.Err)
	cache, err := toolcache.Open()
	if err != nil {
		errOut.line("goharness setup: %v", err)
		return ExitInconclusive
	}
	fetcher := toolcache.NewHTTPFetcher(nil)

	out.line("cache: %s", cache.Root())
	if recovered, err := cache.RecoverVulnDB(); err != nil {
		errOut.line("goharness setup: %v", err)
		return ExitInconclusive
	} else if recovered {
		out.line("recovered a vulnerability snapshot left by an interrupted swap")
	}

	if code := provisionGolangci(ctx, out, errOut, cache, fetcher, *platform); code != ExitAdmitted {
		return code
	}
	if cache.HasVulnDB() {
		manifest, err := cache.ReadVulnDBManifest()
		if err != nil {
			errOut.line("goharness setup: %v", err)
			return ExitInconclusive
		}
		reportSnapshot(out, "vuln database: already present", manifest)
		provisionSkill(out, errOut, *noSkill)
		out.line("\nsetup complete: nothing to download.")
		return exitFor(out, ExitAdmitted)
	}
	if code := refreshSnapshot(ctx, out, errOut, cache, fetcher, "setup"); code != ExitAdmitted {
		return code
	}
	provisionSkill(out, errOut, *noSkill)
	out.line("\nsetup complete.")
	return exitFor(out, ExitAdmitted)
}

// provisionSkill installs the agent skill for the current user as part of
// setup, so provisioning the binary provisions the protocol an agent follows
// with it. A copy that cannot be written is reported and does not fail the
// setup: the tools were provisioned, and the skill has its own command.
func provisionSkill(out, errOut *printer, skip bool) {
	if skip {
		return
	}
	targets, err := userSkillTargets()
	if err != nil {
		errOut.line("agent skill: not installed: %v", err)
		return
	}
	installSkill(out, errOut, targets, false)
}

func provisionGolangci(
	ctx context.Context, out, errOut *printer,
	cache *toolcache.Cache, fetcher toolcache.Fetcher, platform string,
) int {
	spec, err := toolcache.GolangciSpec(tool.GolangciLintPin, platform, toolcache.DefaultSources().GolangciBaseURL)
	if err != nil {
		errOut.line("goharness setup: %v", err)
		return ExitInconclusive
	}
	installation, err := toolcache.ProvisionTool(ctx, cache, fetcher, spec)
	if err != nil {
		errOut.line("goharness setup: provisioning golangci-lint %s: %v", spec.Version, err)
		if errors.Is(err, toolcache.ErrChecksumMismatch) {
			errOut.line("the cache was left untouched; retry, or check the mirror you are downloading from")
		}
		return ExitInconclusive
	}
	if installation.AlreadyPresent {
		out.line("golangci-lint %s: already provisioned for %s (binary sha256 %s)",
			spec.Version, installation.Manifest.Platform, short(installation.Manifest.BinarySHA256))
		return ExitAdmitted
	}
	out.line("golangci-lint %s: downloaded %s", spec.Version, spec.URL)
	out.line("  archive sha256 %s (matches the pin)", spec.SHA256)
	out.line("  extracted %d bytes; binary sha256 %s", installation.ArchiveBytes, installation.Manifest.BinarySHA256)
	out.line("  wrote blobs/sha256/%s and the tool manifest", installation.Manifest.Blob)
	return ExitAdmitted
}

// runToolsUpdate refreshes the vulnerability snapshot and re-provisions any
// tool whose pin has moved. A failed refresh leaves the previous snapshot in
// service, so the machine never loses the ability to scan.
func runToolsUpdate(ctx context.Context, args []string, streams Streams) int {
	fs := flag.NewFlagSet("goharness tools update", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	platform := fs.String("platform", toolcache.CurrentPlatform(),
		"re-provision for this os-arch instead of the current machine")
	if err := fs.Parse(args); err != nil {
		return ExitInconclusive
	}

	out := newPrinter(streams.Out)
	errOut := newPrinter(streams.Err)
	cache, err := toolcache.Open()
	if err != nil {
		errOut.line("goharness tools update: %v", err)
		return ExitInconclusive
	}
	fetcher := toolcache.NewHTTPFetcher(nil)

	out.line("cache: %s", cache.Root())
	if recovered, err := cache.RecoverVulnDB(); err != nil {
		errOut.line("goharness tools update: %v", err)
		return ExitInconclusive
	} else if recovered {
		out.line("recovered a vulnerability snapshot left by an interrupted swap")
	}

	if code := provisionGolangci(ctx, out, errOut, cache, fetcher, *platform); code != ExitAdmitted {
		return code
	}
	if code := refreshSnapshot(ctx, out, errOut, cache, fetcher, "tools update"); code != ExitAdmitted {
		return code
	}
	out.line("\nupdate complete.")
	return exitFor(out, ExitAdmitted)
}

func refreshSnapshot(
	ctx context.Context, out, errOut *printer,
	cache *toolcache.Cache, fetcher toolcache.Fetcher, command string,
) int {
	source := toolcache.DefaultSources().VulnDBBaseURL
	out.line("vuln database: mirroring %s", source)
	result, err := toolcache.SnapshotVulnDB(ctx, cache, fetcher, source)
	if err != nil {
		errOut.line("goharness %s: refreshing the vulnerability database: %v", command, err)
		if cache.HasVulnDB() {
			errOut.line("the previous snapshot is still in service; nothing was replaced")
		} else {
			errOut.line("no snapshot is in service; `goharness audit` will report INCONCLUSIVE until one is")
		}
		return ExitInconclusive
	}
	verb := "wrote"
	if result.Replaced {
		verb = "replaced the previous snapshot with"
	}
	out.line("  %s %d files (%d bytes) at %s", verb, result.Files, result.Bytes, cache.VulnDBDir())
	reportSnapshot(out, "  snapshot", result.Manifest)
	return ExitAdmitted
}

func reportSnapshot(out *printer, prefix string, manifest toolcache.VulnDBManifest) {
	out.line("%s: %d entries, modified %s, tree sha256 %s",
		prefix, manifest.EntryCount,
		manifest.Modified.UTC().Format("2006-01-02T15:04:05Z"),
		manifest.TreeChecksum)
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// runTools dispatches the tools subcommands.
func runTools(ctx context.Context, args []string, streams Streams) int {
	if len(args) == 0 {
		p := newPrinter(streams.Err)
		p.printf("%s", commandUsage("tools"))
		return ExitInconclusive
	}
	switch args[0] {
	case "update":
		return runToolsUpdate(ctx, args[1:], streams)
	default:
		p := newPrinter(streams.Err)
		p.line("unknown tools subcommand %q", args[0])
		if suggestions := nearest(args[0], []string{"update"}, 2); len(suggestions) > 0 {
			p.line("did you mean: %s", strings.Join(suggestions, ", "))
		}
		p.printf("\n%s", commandUsage("tools"))
		return ExitInconclusive
	}
}
