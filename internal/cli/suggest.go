package cli

import (
	"slices"
	"strings"
)

// maxSuggestionDistance keeps suggestions plausible: beyond a third of the
// word, a "did you mean" is noise rather than help.
const maxSuggestionDistance = 3

// nearest returns the candidates closest to the input by edit distance, best
// first, so a misuse error can say what to type rather than only what failed.
func nearest(input string, candidates []string, limit int) []string {
	type scored struct {
		name     string
		distance int
	}
	var matches []scored
	lower := strings.ToLower(input)
	for _, candidate := range candidates {
		distance := editDistance(lower, strings.ToLower(candidate))
		if distance <= maxSuggestionDistance {
			matches = append(matches, scored{candidate, distance})
		}
	}
	slices.SortStableFunc(matches, func(a, b scored) int {
		if a.distance != b.distance {
			return a.distance - b.distance
		}
		return strings.Compare(a.name, b.name)
	})
	out := make([]string, 0, limit)
	for _, m := range matches {
		if len(out) == limit {
			break
		}
		out = append(out, m.name)
	}
	return out
}

// editDistance is Levenshtein distance over runes, computed with two rows
// because only the previous row is ever needed.
func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	previous := make([]int, len(br)+1)
	current := make([]int, len(br)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		current[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			current[j] = min(current[j-1]+1, previous[j]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(br)]
}
