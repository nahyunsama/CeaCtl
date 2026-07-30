package llmtranslation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildUserPrompt_ContainsOnlyTargetLanguageAndAnalysis(t *testing.T) {
	t.Parallel()

	const analysis = "## Key findings\n\n* Interface fc1/1 is down. (E2)\n"
	got, err := BuildUserPrompt(PromptInput{
		TargetLang: "  ko_KR  ",
		Analysis:   analysis,
	})
	if err != nil {
		t.Fatalf("BuildUserPrompt returned an error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("prompt is not valid JSON: %v", err)
	}
	if len(payload) != 2 {
		t.Fatalf("got fields %v, want only target_lang and analysis", payload)
	}
	if payload["target_lang"] != "ko_KR" {
		t.Errorf("got target_lang %#v, want %q", payload["target_lang"], "ko_KR")
	}
	if payload["analysis"] != analysis {
		t.Errorf("got analysis %#v, want exact source analysis", payload["analysis"])
	}
}

func TestBuildUserPrompt_PreservesMarkupWithoutIncludingMetadata(t *testing.T) {
	t.Parallel()

	const analysis = "## Context\n\n* A > B on fc1/1 (E1)"
	got, err := BuildUserPrompt(PromptInput{
		TargetLang: "ko_KR",
		Analysis:   analysis,
	})
	if err != nil {
		t.Fatalf("BuildUserPrompt returned an error: %v", err)
	}

	if !strings.Contains(got, "A > B") {
		t.Errorf("prompt did not preserve analysis markup: %s", got)
	}
	for _, excluded := range []string{
		"RawResponse",
		"StatusCode",
		"eval_count",
		"compressed_log",
	} {
		if strings.Contains(got, excluded) {
			t.Errorf("prompt contains excluded data %q: %s", excluded, got)
		}
	}
}

func TestBuildUserPrompt_RejectsMissingRequiredInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input PromptInput
		want  string
	}{
		{
			name:  "missing target language",
			input: PromptInput{Analysis: "analysis"},
			want:  "target language is empty",
		},
		{
			name:  "missing analysis",
			input: PromptInput{TargetLang: "ko_KR"},
			want:  "analysis is empty",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := BuildUserPrompt(test.input)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not contain %q", err, test.want)
			}
		})
	}
}
