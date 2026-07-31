package logcompressor

import (
	"fmt"
	"io"
	"strings"
	"time"
)

const maxDisplayedTargets = 5

type compactSequence struct {
	Targets    []string
	Transition string
	Final      string
	Count      int
	First      time.Time
	Last       time.Time
}

func (r *Result) WriteReport(w io.Writer, maxUnparsed int) error {
	events := r.StructuredEvents()
	sequences := compactTargetSequences(r.Sequences)
	unknownCount := 0
	for _, event := range events {
		if event.Type == "unknown" {
			unknownCount++
		}
	}

	if _, err := fmt.Fprintf(
		w,
		"=== Structured log compression: events=%d sequences=%d "+
			"unknown=%d unparsed=%d ===\n\n",
		len(events),
		len(sequences),
		unknownCount,
		len(r.Unparsed),
	); err != nil {
		return err
	}

	if err := r.WriteCompact(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		w,
		"\n=== Unparsed lines (%d) ===\n",
		len(r.Unparsed),
	); err != nil {
		return err
	}

	limit := maxUnparsed
	if limit < 0 {
		limit = 0
	}
	if len(r.Unparsed) < limit {
		limit = len(r.Unparsed)
	}
	for _, line := range r.Unparsed[:limit] {
		if _, err := fmt.Fprintf(w, "  %s\n", strings.TrimSpace(line)); err != nil {
			return err
		}
	}
	if omitted := len(r.Unparsed) - limit; omitted > 0 {
		_, err := fmt.Fprintf(w, "  ... %d additional lines omitted\n", omitted)
		return err
	}
	return nil
}

// WriteGroupTable preserves the former report API.
func (r *Result) WriteGroupTable(w io.Writer) error {
	return r.WriteCompact(w)
}

func (r *Result) WriteCompact(w io.Writer) error {
	context := r.Context
	if context == "" {
		context = "unknown"
	}
	if _, err := fmt.Fprintf(w, "context|%s\n", compactValue(context)); err != nil {
		return err
	}

	sequences := compactTargetSequences(r.Sequences)
	if len(sequences) > 0 {
		if _, err := fmt.Fprintln(
			w,
			"sequence_schema|id|time|count|target|transition|final",
		); err != nil {
			return err
		}
		for index, sequence := range sequences {
			if _, err := fmt.Fprintf(
				w,
				"S%d|%s|%d|%s|%s|%s\n",
				index+1,
				compactSpan(sequence.First, sequence.Last),
				sequence.Count,
				formatTargets(sequence.Targets),
				compactValue(sequence.Transition),
				compactValue(sequence.Final),
			); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(
		w,
		"event_schema|id|time|count|target|type|role|transition|reason|final|detail",
	); err != nil {
		return err
	}

	for index, event := range r.StructuredEvents() {
		if err := writeCompactEvent(w, index+1, event); err != nil {
			return err
		}
	}
	return nil
}

// WriteCitedEventSummary writes nothing for an empty or invalid ID set.
func (r *Result) WriteCitedEventSummary(
	w io.Writer,
	eventIDs []int,
) error {
	validIDs := r.validUniqueEventIDs(eventIDs)
	if len(validIDs) == 0 {
		return nil
	}

	if _, err := fmt.Fprintln(w, "\n=== Cited Event Summary ==="); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(
		w,
		"event_schema|id|time|count|target|type|role|transition|reason|final|detail",
	); err != nil {
		return err
	}

	events := r.StructuredEvents()
	for _, id := range validIDs {
		if err := writeCompactEvent(w, id, events[id-1]); err != nil {
			return err
		}
	}
	return nil
}

func writeCompactEvent(w io.Writer, id int, event Event) error {
	detail := event.Detail
	if detail == "" {
		detail = "-"
	}
	_, err := fmt.Fprintf(
		w,
		"E%d|%s|%d|%s|%s|%s|%s|%s|%s|%s\n",
		id,
		compactSpan(event.First, event.Last),
		event.Count,
		formatTargets(event.Targets),
		compactValue(event.Type),
		compactValue(event.Role),
		compactValue(event.Transition),
		compactValue(event.Reason),
		compactValue(event.Final),
		compactValue(detail),
	)
	return err
}

func compactTargetSequences(
	sequences []TargetSequence,
) []compactSequence {
	var result []compactSequence
	currentByPattern := make(map[string]int)

	for _, sequence := range sequences {
		pattern := sequence.Transition + "|" + sequence.Final
		if index, exists := currentByPattern[pattern]; exists {
			current := &result[index]
			if sequence.First.Sub(current.Last) <=
				semanticAggregationGap {
				current.Targets = append(
					current.Targets,
					sequence.Target,
				)
				current.Count += sequence.Count
				if sequence.First.Before(current.First) {
					current.First = sequence.First
				}
				if sequence.Last.After(current.Last) {
					current.Last = sequence.Last
				}
				continue
			}
		}

		result = append(result, compactSequence{
			Targets:    []string{sequence.Target},
			Transition: sequence.Transition,
			Final:      sequence.Final,
			Count:      sequence.Count,
			First:      sequence.First,
			Last:       sequence.Last,
		})
		currentByPattern[pattern] = len(result) - 1
	}
	return result
}

func compactSpan(first, last time.Time) string {
	const layout = "2006-01-02T15:04:05"
	if first.IsZero() {
		return "-"
	}
	if first.Equal(last) || last.IsZero() {
		return first.Format(layout)
	}
	return first.Format(layout) + "~" + last.Format(layout)
}

func formatTargets(targets []string) string {
	if len(targets) == 0 {
		return "-"
	}
	limit := len(targets)
	if limit > maxDisplayedTargets {
		limit = maxDisplayedTargets
	}

	values := make([]string, 0, limit)
	for _, target := range targets[:limit] {
		values = append(values, compactValue(target))
	}
	joined := strings.Join(values, ",")
	if omitted := len(targets) - limit; omitted > 0 {
		joined += fmt.Sprintf(",+%dmore", omitted)
	}
	if len(targets) == 1 {
		return joined
	}
	return fmt.Sprintf("%d[%s]", len(targets), joined)
}

func compactValue(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	value = strings.ReplaceAll(value, "|", "/")
	if value == "" {
		return "-"
	}
	return value
}
