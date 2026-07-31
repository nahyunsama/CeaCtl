package mds

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nahyunsama/ceactl/internal/mds/logcompressor"
)

func TestParseDayStart(t *testing.T) {
	t.Run("empty string returns zero time with no error", func(t *testing.T) {
		got, err := parseDayStart("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.IsZero() {
			t.Errorf("got %v, want zero time", got)
		}
	})

	t.Run("valid date returns midnight of that day", func(t *testing.T) {
		got, err := parseDayStart("20240115")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2024, time.January, 15, 0, 0, 0, 0, time.UTC)
		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("invalid format returns an error", func(t *testing.T) {
		_, err := parseDayStart("2024-01-15")
		if err == nil {
			t.Fatal("expected an error for malformed date, got nil")
		}
	})
}

func TestParseDayEnd(t *testing.T) {
	t.Run("empty string returns zero time with no error", func(t *testing.T) {
		got, err := parseDayEnd("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.IsZero() {
			t.Errorf("got %v, want zero time", got)
		}
	})

	t.Run("valid date returns the last second of that day", func(t *testing.T) {
		got, err := parseDayEnd("20240115")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2024, time.January, 15, 23, 59, 59, 0, time.UTC)
		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("invalid format returns an error", func(t *testing.T) {
		_, err := parseDayEnd("2024-01-15")
		if err == nil {
			t.Fatal("expected an error for malformed date, got nil")
		}
	})
}

func TestShouldWriteFullLogReport(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		backend string
		want    bool
	}{
		{
			name:    "default ollama output hides full report",
			backend: "ollama",
		},
		{
			name:    "verbose ollama output includes full report",
			verbose: true,
			backend: "ollama",
			want:    true,
		},
		{
			name:    "non ollama backend still has useful output",
			backend: "console-only",
			want:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shouldWriteFullLogReport(
				test.verbose,
				test.backend,
			)
			if got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestWriteReferencedEventOutput_SelectsDetailByMode(t *testing.T) {
	observed := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	result := &logcompressor.Result{
		Events: []logcompressor.Event{
			{
				Targets: []string{"fc1/1"}, Type: "state",
				Role: "effect", Transition: "down",
				Reason: "link_failure", Final: "down",
				Count: 1, First: observed, Last: observed,
				SourceGroupIDs: []int{1},
			},
			{
				Targets: []string{"IPStorage1/6"}, Type: "measurement",
				Role: "cause_candidate", Transition: "asserted",
				Reason: "low_rx_power_alarm", Final: "asserted",
				Count: 1, First: observed, Last: observed,
				SourceGroupIDs: []int{2},
			},
		},
		Groups: []logcompressor.Group{
			{
				Facility: "PORT", Mnemonic: "IF_DOWN_LINK_FAILURE",
				Iface: "fc1/1", Vsan: "-", Count: 1,
			},
			{
				Facility: "ETHPORT", Mnemonic: "IF_SFP_ALARM",
				Iface: "IPStorage1/6", Vsan: "-", Count: 1,
				Variants: []logcompressor.MessageVariant{{
					Message: "Interface IPStorage1/6, Low Rx Power Alarm",
					Count:   1,
					First:   observed,
					Last:    observed,
				}},
			},
		},
	}

	t.Run("default writes only cited compact summary", func(t *testing.T) {
		var output bytes.Buffer
		if err := writeReferencedEventOutput(
			&output,
			result,
			[]int{2},
			false,
		); err != nil {
			t.Fatalf("writeReferencedEventOutput returned an error: %v", err)
		}

		got := output.String()
		if !strings.Contains(got, "=== Cited Event Summary ===") ||
			!strings.Contains(got, "E2|") ||
			!strings.Contains(got, "low_rx_power_alarm") {
			t.Errorf("default output is missing cited summary:\n%s", got)
		}
		if strings.Contains(got, "Source evidence") ||
			strings.Contains(got, "E1|") {
			t.Errorf("default output contains verbose detail:\n%s", got)
		}
	})

	t.Run("verbose writes exact source evidence", func(t *testing.T) {
		var output bytes.Buffer
		if err := writeReferencedEventOutput(
			&output,
			result,
			[]int{2},
			true,
		); err != nil {
			t.Fatalf("writeReferencedEventOutput returned an error: %v", err)
		}

		got := output.String()
		if !strings.Contains(got, "=== Source evidence") ||
			!strings.Contains(
				got,
				"Interface IPStorage1/6, Low Rx Power Alarm",
			) {
			t.Errorf("verbose output is missing source evidence:\n%s", got)
		}
		if strings.Contains(got, "=== Cited Event Summary ===") {
			t.Errorf("verbose output contains default summary:\n%s", got)
		}
	})
}

func TestWriteLLMOutput_AppendsTranslationAfterCitedEvents(t *testing.T) {
	observed := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	result := &logcompressor.Result{
		Events: []logcompressor.Event{{
			Targets: []string{"fc1/1"},
			Type:    "state", Role: "effect", Transition: "down",
			Reason: "link_failure", Final: "down", Count: 1,
			First: observed, Last: observed,
		}},
	}

	var output bytes.Buffer
	if err := writeLLMOutput(
		&output,
		result,
		[]int{1},
		"gemma4:e2b",
		"English analysis citing E1.",
		"ko_KR",
		"E1을 인용한 한국어 분석입니다.",
		false,
	); err != nil {
		t.Fatalf("writeLLMOutput returned an error: %v", err)
	}

	got := output.String()
	analysisIndex := strings.Index(got, "English analysis citing E1.")
	eventIndex := strings.Index(got, "=== Cited Event Summary ===")
	translationIndex := strings.Index(got, "=== Translation (ko_KR) ===")
	if analysisIndex < 0 || eventIndex < 0 || translationIndex < 0 {
		t.Fatalf("output is missing a required section:\n%s", got)
	}
	if !(analysisIndex < eventIndex && eventIndex < translationIndex) {
		t.Fatalf(
			"output order is not analysis, cited events, translation:\n%s",
			got,
		)
	}
	if !strings.Contains(got, "E1을 인용한 한국어 분석입니다.") {
		t.Errorf("output is missing translated analysis:\n%s", got)
	}
}

func TestWriteLLMOutput_OmitsTranslationWhenDisabled(t *testing.T) {
	var output bytes.Buffer
	if err := writeLLMOutput(
		&output,
		&logcompressor.Result{},
		nil,
		"gemma4:e2b",
		"English analysis.",
		"",
		"",
		false,
	); err != nil {
		t.Fatalf("writeLLMOutput returned an error: %v", err)
	}

	got := output.String()
	if !strings.Contains(got, "English analysis.") {
		t.Errorf("output is missing original analysis:\n%s", got)
	}
	if strings.Contains(got, "=== Translation") {
		t.Errorf("output contains a translation section:\n%s", got)
	}
}
