package logcompressor

import (
	"fmt"
	"io"
	"time"
)

const (
	maxEvidenceEvents           = 20
	maxEvidenceVariantsPerEvent = 10
)

func (r *Result) WriteEvidenceDetails(
	w io.Writer,
	eventIDs []int,
) error {
	if _, err := fmt.Fprintln(
		w,
		"\n=== Source evidence for LLM-cited events ===",
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(
		w,
		"The following messages are exact source-log evidence "+
			"behind the cited compact Event IDs.",
	); err != nil {
		return err
	}

	validIDs := r.validUniqueEventIDs(eventIDs)
	if len(validIDs) == 0 {
		_, err := fmt.Fprintln(
			w,
			"\nNo valid individual Event IDs were cited by the LLM.",
		)
		return err
	}

	limit := len(validIDs)
	if limit > maxEvidenceEvents {
		limit = maxEvidenceEvents
	}
	for _, id := range validIDs[:limit] {
		if err := r.writeStructuredEvidenceEvent(w, id); err != nil {
			return err
		}
	}
	if omitted := len(validIDs) - limit; omitted > 0 {
		_, err := fmt.Fprintf(
			w,
			"\n... %d additional individually cited events omitted\n",
			omitted,
		)
		return err
	}
	return nil
}

func (r *Result) validUniqueEventIDs(eventIDs []int) []int {
	eventCount := r.EventCount()
	seen := make(map[int]struct{}, len(eventIDs))
	valid := make([]int, 0, len(eventIDs))

	for _, id := range eventIDs {
		if id < 1 || id > eventCount {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		valid = append(valid, id)
	}
	return valid
}

func (r *Result) writeStructuredEvidenceEvent(
	w io.Writer,
	id int,
) error {
	event := r.StructuredEvents()[id-1]
	if _, err := fmt.Fprintf(
		w,
		"\n[E%d] target=%s type=%s role=%s transition=%s "+
			"reason=%s observed_count=%d\n",
		id,
		formatTargets(event.Targets),
		event.Type,
		event.Role,
		event.Transition,
		event.Reason,
		event.Count,
	); err != nil {
		return err
	}

	writtenVariants := 0
	for _, groupID := range event.SourceGroupIDs {
		if groupID < 1 || groupID > len(r.Groups) {
			continue
		}
		group := r.Groups[groupID-1]
		if _, err := fmt.Fprintf(
			w,
			"  source=%s-%s interface=%s vsan=%s\n",
			group.Facility,
			group.Mnemonic,
			group.Iface,
			group.Vsan,
		); err != nil {
			return err
		}

		if len(group.Variants) == 0 {
			if group.Sample != "" {
				if _, err := fmt.Fprintf(w, "    %s\n", group.Sample); err != nil {
					return err
				}
			}
			continue
		}

		for _, variant := range group.Variants {
			if writtenVariants >= maxEvidenceVariantsPerEvent {
				break
			}
			if _, err := fmt.Fprintf(
				w,
				"    - observed_count=%d time=%s\n      %s\n",
				variant.Count,
				formatEvidenceSpan(variant.First, variant.Last),
				variant.Message,
			); err != nil {
				return err
			}
			writtenVariants++
		}
		if writtenVariants >= maxEvidenceVariantsPerEvent {
			break
		}
	}

	if writtenVariants >= maxEvidenceVariantsPerEvent {
		_, err := fmt.Fprintf(
			w,
			"    - additional source variants omitted after %d entries\n",
			maxEvidenceVariantsPerEvent,
		)
		return err
	}
	return nil
}

func formatEvidenceSpan(first, last time.Time) string {
	const layout = "2006-01-02 15:04:05"
	if first.Equal(last) {
		return first.Format(layout)
	}
	return fmt.Sprintf(
		"%s ~ %s",
		first.Format(layout),
		last.Format(layout),
	)
}
