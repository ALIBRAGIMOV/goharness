package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"golang.org/x/vuln/scan"
)

// XVulnModulePath is the module providing the embedded scanner.
const XVulnModulePath = "golang.org/x/vuln"

// XVulnPin is the version required in go.mod. It is only a fallback: build
// info is the authority whenever it is available, and it always is in the
// released binary. Test binaries carry no dependency list, so a test keeps this
// constant honest by comparing it with go.mod.
const XVulnPin = "v1.7.0"

// vulnerabilitiesFoundExit is govulncheck's exit status when it completes
// successfully and has something to report. It is a finding, not a failure.
const vulnerabilitiesFoundExit = 3

// XVulnVersion reports the version of the embedded scanner linked into this
// binary. Build info is the authority, so the reported version can never drift
// from what is actually linked; the pin is used only where the toolchain omits
// the dependency list, which is the case for test binaries.
func XVulnVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return XVulnPin
	}
	for _, dep := range info.Deps {
		if dep.Path == XVulnModulePath {
			return dep.Version
		}
	}
	return XVulnPin
}

// VulnFinding is one vulnerability the scanner attributed to a source position.
type VulnFinding struct {
	OSV     string
	Package string
	File    string
	Line    int
	Message string
}

type vulnMessage struct {
	OSV *struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
	} `json:"osv"`
	Finding *struct {
		OSV   string      `json:"osv"`
		Trace []vulnFrame `json:"trace"`
	} `json:"finding"`
}

type vulnFrame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

// RunVulnScan scans a module in process against a local database snapshot.
//
// The scanner is a library dependency, not an executable: there is no PATH
// lookup and no subprocess. The database is addressed as a file URL so the scan
// is strictly offline, and -C selects the directory without touching the
// process working directory, which keeps concurrent checks independent.
func RunVulnScan(ctx context.Context, dir, dbURL string, patterns []string) ([]VulnFinding, error) {
	args := []string{"-C", dir, "-format", "json", "-mode", "source", "-db", dbURL}
	args = append(args, patterns...)

	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the vulnerability scan: %w", err)
	}
	err := cmd.Wait()
	if err != nil && !isVulnerabilitiesFound(err) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("vulnerability scan: %w", ctxErr)
		}
		return nil, fmt.Errorf("vulnerability scan failed: %w (%s)",
			err, strings.TrimSpace(firstLines(stderr.String(), 10)))
	}
	return parseVulnStream(stdout.String())
}

// isVulnerabilitiesFound reports whether an error is only the scanner's way of
// saying it found something.
func isVulnerabilitiesFound(err error) bool {
	var coded interface{ ExitCode() int }
	return errors.As(err, &coded) && coded.ExitCode() == vulnerabilitiesFoundExit
}

func parseVulnStream(stdout string) ([]VulnFinding, error) {
	dec := json.NewDecoder(strings.NewReader(stdout))
	summaries := map[string]string{}
	var findings []VulnFinding
	for {
		var msg vulnMessage
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decoding the vulnerability scan output: %w", err)
		}
		if msg.OSV != nil {
			summaries[msg.OSV.ID] = msg.OSV.Summary
		}
		if msg.Finding == nil || len(msg.Finding.Trace) == 0 {
			continue
		}
		frame := msg.Finding.Trace[0]
		if frame.Position == nil {
			continue
		}
		findings = append(findings, VulnFinding{
			OSV:     msg.Finding.OSV,
			Package: frame.Package,
			File:    frame.Position.Filename,
			Line:    frame.Position.Line,
			Message: strings.TrimSpace(msg.Finding.OSV + ": " + summaries[msg.Finding.OSV]),
		})
	}
	return findings, nil
}
