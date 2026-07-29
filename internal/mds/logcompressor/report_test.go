package logcompressor

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteReport_WritesStructuredCompression(t *testing.T) {
	result := &Result{
		Groups: []Group{
			{
				Facility: "PORT",
				Mnemonic: "IF_DOWN",
				Iface:    "fc1/1",
				Vsan:     "100",
				Severity: "5",
				Count:    3,
				First:    time.Date(2024, time.January, 15, 10, 23, 45, 0, time.UTC),
				Last:     time.Date(2024, time.January, 15, 10, 25, 0, 0, time.UTC),
			},
		},
		Unparsed: []string{"unparsed line 1", "unparsed line 2"},
	}

	var buf bytes.Buffer
	if err := result.WriteReport(&buf, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	expected := []string{
		"Structured log compression: events=1",
		"unknown=0 unparsed=2",
		"event_schema|id|time|count|target|type|role|transition|reason|final|detail",
		"E1|2024-01-15T10:23:45~2024-01-15T10:25:00|3|fc1/1@vsan100",
		"|state|effect|downx3|unspecified|down|-",
		"=== Unparsed lines (2) ===",
		"unparsed line 1",
		"unparsed line 2",
	}
	for _, value := range expected {
		if !strings.Contains(output, value) {
			t.Errorf("output does not contain %q:\n%s", value, output)
		}
	}
}

func TestWriteReport_SingleTimestampHasNoRangeSeparator(t *testing.T) {
	observed := time.Date(2024, time.January, 15, 10, 23, 45, 0, time.UTC)
	result := &Result{
		Groups: []Group{{
			Facility: "PORT",
			Mnemonic: "IF_DOWN",
			Iface:    "fc1/1",
			Vsan:     "100",
			Count:    1,
			First:    observed,
			Last:     observed,
		}},
	}

	var buf bytes.Buffer
	if err := result.WriteReport(&buf, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	eventLine := findLineWithPrefix(buf.String(), "E1|")
	if strings.Contains(strings.Split(eventLine, "|")[1], "~") {
		t.Errorf("single timestamp unexpectedly contains a range: %s", eventLine)
	}
}

func TestWriteReport_LimitsAndTrimsUnparsedLines(t *testing.T) {
	result := &Result{
		Unparsed: []string{"  line 1  ", "line 2", "line 3"},
	}

	var buf bytes.Buffer
	if err := result.WriteReport(&buf, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "  line 1\n") {
		t.Errorf("output should contain the trimmed first line:\n%s", output)
	}
	if strings.Contains(output, "line 2") || strings.Contains(output, "line 3") {
		t.Errorf("output contains lines beyond the limit:\n%s", output)
	}
	if !strings.Contains(output, "2 additional lines omitted") {
		t.Errorf("output missing omitted count:\n%s", output)
	}
}

func TestWriteReport_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	if err := (&Result{}).WriteReport(&buf, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "events=0 sequences=0 unknown=0 unparsed=0") {
		t.Errorf("output missing zero counts:\n%s", output)
	}
	if !strings.Contains(output, "=== Unparsed lines (0) ===") {
		t.Errorf("output missing empty unparsed section:\n%s", output)
	}
}

func TestWriteGroupTable_IncludesSequentialEventIDs(t *testing.T) {
	observed := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	result := &Result{
		Groups: []Group{
			{
				Facility: "ETHPORT",
				Mnemonic: "IF_DOWN_LINK_FAILURE",
				Iface:    "IPStorage1/6",
				Vsan:     "-",
				Count:    1,
				First:    observed,
				Last:     observed,
			},
			{
				Facility: "ETHPORT",
				Mnemonic: "IF_SFP_WARNING",
				Iface:    "IPStorage1/6",
				Vsan:     "-",
				Count:    1,
				First:    observed,
				Last:     observed,
			},
		},
	}

	var buf bytes.Buffer
	if err := result.WriteGroupTable(&buf); err != nil {
		t.Fatalf("WriteGroupTable returned an error: %v", err)
	}
	output := buf.String()
	for _, value := range []string{"E1|", "E2|", "|state|effect|down|", "|measurement|cause_candidate|asserted|"} {
		if !strings.Contains(output, value) {
			t.Errorf("output does not contain %q:\n%s", value, output)
		}
	}
}

func TestCompactTargetSequences_AggregatesSharedPatternWithinIncident(t *testing.T) {
	start := time.Date(2026, time.July, 1, 7, 36, 0, 0, time.UTC)
	sequences := []TargetSequence{
		{
			Target: "fc1/7", Transition: "down>blocked", Final: "blocked",
			Count: 2, First: start, Last: start.Add(time.Minute),
		},
		{
			Target: "fc1/8", Transition: "down>blocked", Final: "blocked",
			Count: 2, First: start.Add(time.Second), Last: start.Add(time.Minute),
		},
		{
			Target: "fc1/9", Transition: "down>blocked", Final: "blocked",
			Count: 2, First: start.Add(time.Hour), Last: start.Add(time.Hour),
		},
	}

	got := compactTargetSequences(sequences)
	if len(got) != 2 {
		t.Fatalf("got %d compact sequences, want 2", len(got))
	}
	if len(got[0].Targets) != 2 || got[0].Count != 4 {
		t.Errorf("nearby shared patterns were not aggregated: %+v", got[0])
	}
}

func TestWriteCitedEventSummary_WritesOnlyValidSelectedEvents(t *testing.T) {
	observed := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	result := &Result{Events: []Event{
		{
			Targets: []string{"fc1/1"}, Type: "state",
			Role: "effect", Transition: "down",
			Reason: "link_failure", Final: "down",
			Count: 1, First: observed, Last: observed,
		},
		{
			Targets: []string{"fc1/2"}, Type: "state",
			Role: "recovery", Transition: "up",
			Reason: "none", Final: "up",
			Count: 1, First: observed, Last: observed,
		},
	}}

	var output bytes.Buffer
	if err := result.WriteCitedEventSummary(
		&output,
		[]int{2, 2, 0, 3},
	); err != nil {
		t.Fatalf("WriteCitedEventSummary returned an error: %v", err)
	}
	got := output.String()
	if !strings.Contains(got, "E2|") || strings.Contains(got, "E1|") {
		t.Errorf("unexpected cited event selection:\n%s", got)
	}

	output.Reset()
	if err := result.WriteCitedEventSummary(&output, nil); err != nil {
		t.Fatalf("empty summary returned an error: %v", err)
	}
	if output.Len() != 0 {
		t.Errorf("empty ID set produced output:\n%s", output.String())
	}
}

func findLineWithPrefix(value, prefix string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}
