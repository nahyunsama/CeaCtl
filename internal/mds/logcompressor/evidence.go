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

// WriteEvidenceDetails treats event IDs as one-based indexes into Groups.
func (r *Result) WriteEvidenceDetails(w io.Writer, eventIDs []int) error {
	if _, err := fmt.Fprintln(
		w,
		"\n=== LLM이 인용한 이벤트 원문 (프로그램 자동 추출) ===",
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(
		w,
		"※ 아래 내용은 LLM의 분석이 아니라, 인용된 Event ID의 실제 로그 메시지입니다.",
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
		if err := r.writeEvidenceEvent(w, id); err != nil {
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
	seen := make(map[int]struct{}, len(eventIDs))
	valid := make([]int, 0, len(eventIDs))

	for _, id := range eventIDs {
		if id < 1 || id > len(r.Groups) {
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

func (r *Result) writeEvidenceEvent(w io.Writer, id int) error {
	group := r.Groups[id-1]

	if _, err := fmt.Fprintf(
		w,
		"\n[E%d] %s-%s iface=%s vsan=%s observed_count=%d\n",
		id,
		group.Facility,
		group.Mnemonic,
		group.Iface,
		group.Vsan,
		group.Count,
	); err != nil {
		return err
	}

	if len(group.Variants) == 0 {
		_, err := fmt.Fprintln(w, "  No parsed message detail available.")
		return err
	}

	limit := len(group.Variants)
	if limit > maxEvidenceVariantsPerEvent {
		limit = maxEvidenceVariantsPerEvent
	}

	for _, variant := range group.Variants[:limit] {
		if _, err := fmt.Fprintf(
			w,
			"  - observed_count=%d time=%s\n    %s\n",
			variant.Count,
			formatEvidenceSpan(variant.First, variant.Last),
			variant.Message,
		); err != nil {
			return err
		}
	}

	if omitted := len(group.Variants) - limit; omitted > 0 {
		_, err := fmt.Fprintf(
			w,
			"  - ... %d additional variants omitted\n",
			omitted,
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
