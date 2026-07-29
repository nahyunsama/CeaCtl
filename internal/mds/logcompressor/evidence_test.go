package logcompressor

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteEvidenceDetails_WritesExactVariantsForValidIDs(t *testing.T) {
	first := time.Date(2026, time.June, 1, 13, 57, 25, 0, time.UTC)
	last := time.Date(2026, time.June, 1, 14, 7, 26, 0, time.UTC)

	result := &Result{
		Groups: []Group{
			{
				Facility: "PORT",
				Mnemonic: "IF_DOWN",
				Iface:    "fc1/1",
				Vsan:     "1",
				Count:    1,
			},
			{
				Facility: "ETHPORT",
				Mnemonic: "IF_SFP_WARNING",
				Iface:    "IPStorage1/6",
				Vsan:     "-",
				Count:    2,
				Variants: []MessageVariant{
					{
						Message: "Interface IPStorage1/6, Low Rx Power Warning",
						Count:   1,
						First:   first,
						Last:    first,
					},
					{
						Message: "Interface IPStorage1/6, Low Rx Power Warning cleared",
						Count:   1,
						First:   last,
						Last:    last,
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := result.WriteEvidenceDetails(&buf, []int{2, 2, 0, 3}); err != nil {
		t.Fatalf("WriteEvidenceDetails returned an error: %v", err)
	}

	output := buf.String()
	expected := []string{
		"=== Source evidence for LLM-cited events ===",
		"[E2] target=IPStorage1/6 type=measurement",
		"transition=asserted>cleared",
		"reason=low_rx_power_warning observed_count=2",
		"source=ETHPORT-IF_SFP_WARNING interface=IPStorage1/6 vsan=-",
		"observed_count=1 time=2026-06-01 13:57:25",
		"Interface IPStorage1/6, Low Rx Power Warning",
		"observed_count=1 time=2026-06-01 14:07:26",
		"Interface IPStorage1/6, Low Rx Power Warning cleared",
	}

	for _, value := range expected {
		if !strings.Contains(output, value) {
			t.Errorf("output does not contain %q:\n%s", value, output)
		}
	}

	if strings.Contains(output, "[E1]") || strings.Contains(output, "[E3]") {
		t.Errorf("output contains an unrequested or invalid Event ID:\n%s", output)
	}
}

func TestWriteEvidenceDetails_ReportsNoValidIndividualIDs(t *testing.T) {
	result := &Result{Groups: []Group{{Facility: "PORT"}}}

	var buf bytes.Buffer
	if err := result.WriteEvidenceDetails(&buf, nil); err != nil {
		t.Fatalf("WriteEvidenceDetails returned an error: %v", err)
	}

	if !strings.Contains(
		buf.String(),
		"No valid individual Event IDs were cited by the LLM.",
	) {
		t.Fatalf("unexpected output:\n%s", buf.String())
	}
}
