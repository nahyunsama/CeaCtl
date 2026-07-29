package logcompressor

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	reTimestamp = regexp.MustCompile(`^(\d{4}\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2})`)
	reMnemonic  = regexp.MustCompile(`%([A-Z0-9_-]+)-(\d)-([A-Z0-9_]+)\s*:`)
	reInterface = regexp.MustCompile(`(?i)\bInterface\s+([^\s,]+)`)
	reVsan      = regexp.MustCompile(`(?i)VSAN\s*(\d+)`)
)

type groupKey struct {
	facility string
	severity string
	mnemonic string
	iface    string
	vsan     string
}

type MessageVariant struct {
	Message string
	Count   int
	First   time.Time
	Last    time.Time
}

type Group struct {
	Facility string
	Mnemonic string
	Iface    string
	Vsan     string
	Severity string
	Sample   string
	Count    int
	First    time.Time
	Last     time.Time
	Variants []MessageVariant
}

type groupAccumulator struct {
	group        Group
	variantIndex map[string]int
}

type Result struct {
	Groups    []Group
	Events    []Event
	Sequences []TargetSequence
	Context   string
	Unparsed  []string
}

func parseTS(line string) (time.Time, bool) {
	m := reTimestamp.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, false
	}
	normalized := strings.Join(strings.Fields(m[1]), " ")
	t, err := time.Parse("2006 Jan 2 15:04:05", normalized)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func parseMnemonic(line string) (facility, severity, mnemonic string, ok bool) {
	m := reMnemonic.FindStringSubmatch(line)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

func parseInterface(line string) string {
	m := reInterface.FindStringSubmatch(line)
	if m == nil {
		return "-"
	}
	return m[1]
}

func parseVsan(line string) string {
	m := reVsan.FindStringSubmatch(line)
	if m == nil {
		return "-"
	}
	return m[1]
}

func parseMessageDetail(line string) string {
	location := reMnemonic.FindStringIndex(line)
	if location == nil {
		return ""
	}

	detail := strings.TrimSpace(line[location[1]:])
	return strings.Join(strings.Fields(detail), " ")
}

func Analyze(r io.Reader, from, to time.Time) (*Result, error) {
	groups := make(map[groupKey]*groupAccumulator)
	var order []groupKey
	var occurrences []rawOccurrence
	var unparsed []string

	scanner := bufio.NewScanner(r)

	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		ts, tsOK := parseTS(line)
		if !tsOK {
			unparsed = append(unparsed, line)
			continue
		}
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && ts.After(to) {
			continue
		}

		facility, severity, mnemonic, mnemonicOK := parseMnemonic(line)
		if !mnemonicOK {
			unparsed = append(unparsed, line)
			continue
		}

		iface := parseInterface(line)
		vsan := parseVsan(line)

		key := groupKey{
			facility: facility,
			severity: severity,
			mnemonic: mnemonic,
			iface:    iface,
			vsan:     vsan,
		}

		accumulator, exists := groups[key]
		if !exists {
			accumulator = &groupAccumulator{
				group: Group{
					Facility: facility,
					Mnemonic: mnemonic,
					Iface:    iface,
					Vsan:     vsan,
					Severity: severity,
					Sample:   strings.TrimSpace(line),
					First:    ts,
					Last:     ts,
				},
				variantIndex: make(map[string]int),
			}
			groups[key] = accumulator
			order = append(order, key)
		}

		group := &accumulator.group
		group.Count++

		if ts.Before(group.First) {
			group.First = ts
		}
		if ts.After(group.Last) {
			group.Last = ts
		}

		detail := parseMessageDetail(line)
		if detail == "" {
			continue
		}

		occurrences = append(occurrences, rawOccurrence{
			GroupKey:  key,
			Timestamp: ts,
			Order:     len(occurrences),
			Message:   detail,
		})

		variantPosition, variantExists := accumulator.variantIndex[detail]
		if !variantExists {
			variantPosition = len(group.Variants)
			accumulator.variantIndex[detail] = variantPosition

			group.Variants = append(group.Variants, MessageVariant{
				Message: detail,
				First:   ts,
				Last:    ts,
			})
		}

		variant := &group.Variants[variantPosition]
		variant.Count++

		if ts.Before(variant.First) {
			variant.First = ts
		}
		if ts.After(variant.Last) {
			variant.Last = ts
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.SliceStable(order, func(i, j int) bool {
		return groups[order[i]].group.First.Before(
			groups[order[j]].group.First,
		)
	})

	result := &Result{
		Unparsed: unparsed,
	}
	groupIDs := make(map[groupKey]int, len(order))

	for _, key := range order {
		group := groups[key].group

		sort.SliceStable(group.Variants, func(i, j int) bool {
			return group.Variants[i].First.Before(
				group.Variants[j].First,
			)
		})

		result.Groups = append(result.Groups, group)
		groupIDs[key] = len(result.Groups)
	}

	result.Context = detectContext(occurrences)
	result.Events, result.Sequences = buildStructuredEvents(
		occurrences,
		groupIDs,
		result.Context,
	)
	return result, nil
}
