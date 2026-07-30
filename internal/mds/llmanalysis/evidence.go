package llmanalysis

import (
	"regexp"
	"strconv"
)

var (
	eventRangeReference = regexp.MustCompile(
		`(?i)\bE\d+\s*(?:-|through|to)\s*E?\d+\b`,
	)
	eventReference = regexp.MustCompile(`\bE([1-9]\d*)\b`)
)

// ReferencedEventIDs excludes ranges and preserves first-seen order.
func ReferencedEventIDs(reply string, groupCount int) []int {
	if groupCount <= 0 {
		return nil
	}

	withoutRanges := eventRangeReference.ReplaceAllString(reply, " ")
	matches := eventReference.FindAllStringSubmatch(withoutRanges, -1)

	seen := make(map[int]struct{}, len(matches))
	ids := make([]int, 0, len(matches))

	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil || id > groupCount {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}

		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	return ids
}
