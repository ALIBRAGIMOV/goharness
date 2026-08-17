package tool

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// The go command prints go/analysis results as one JSON object per compilation
// unit: package ID, then analyzer name, then either the diagnostics or the
// error that stopped that analyzer. `go vet -json` and `go fix -json` print the
// same schema, so both are decoded here rather than once per caller.

// analysisTextEdit is one replacement inside a file, as byte offsets.
type analysisTextEdit struct {
	Filename string `json:"filename"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	New      string `json:"new"`
}

// analysisSuggestedFix is an edit set that applies whole or not at all.
type analysisSuggestedFix struct {
	Message string             `json:"message"`
	Edits   []analysisTextEdit `json:"edits"`
}

// analysisDiagnostic is one finding, positioned as "file:line:column".
type analysisDiagnostic struct {
	Posn           string                 `json:"posn"`
	Message        string                 `json:"message"`
	SuggestedFixes []analysisSuggestedFix `json:"suggested_fixes"`
}

// analysisResult decodes the two shapes one analyzer's result can take. An
// analyzer that could not run prints an error object where the diagnostics
// would be; a decoder that expected only diagnostics reads that as malformed
// output and blames the tool for the wrong reason.
type analysisResult struct {
	diagnostics []analysisDiagnostic
	failure     string
}

// UnmarshalJSON decodes either the diagnostic list or the analyzer error.
func (r *analysisResult) UnmarshalJSON(data []byte) error {
	var failed struct {
		Err string `json:"error"`
	}
	if err := json.Unmarshal(data, &failed); err == nil && failed.Err != "" {
		r.failure = failed.Err
		return nil
	}
	return json.Unmarshal(data, &r.diagnostics)
}

// analysisEntry is one analyzer's result for one package.
type analysisEntry struct {
	Package     string
	Analyzer    string
	Diagnostics []analysisDiagnostic
	Failure     string
}

// decodeAnalysisJSON reads the stream of JSON trees into entries ordered by
// package and analyzer. The order is imposed here because the wire form is a
// map, and a report whose evidence order came from map iteration would differ
// between two runs over an unchanged tree.
func decodeAnalysisJSON(stream string) ([]analysisEntry, error) {
	dec := json.NewDecoder(strings.NewReader(stream))
	var out []analysisEntry
	for {
		var tree map[string]map[string]analysisResult
		if err := dec.Decode(&tree); err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, fmt.Errorf("decoding analysis JSON: %w", err)
		}
		for _, pkg := range slices.Sorted(maps.Keys(tree)) {
			results := tree[pkg]
			for _, analyzer := range slices.Sorted(maps.Keys(results)) {
				out = append(out, analysisEntry{
					Package:     pkg,
					Analyzer:    analyzer,
					Diagnostics: results[analyzer].diagnostics,
					Failure:     results[analyzer].failure,
				})
			}
		}
	}
}
