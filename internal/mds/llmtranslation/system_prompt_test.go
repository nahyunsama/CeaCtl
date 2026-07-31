package llmtranslation

import (
	"strings"
	"testing"
)

func TestSystemPromptDefinesTranslationOnlyContract(t *testing.T) {
	t.Parallel()

	expected := []string{
		"only task is to translate the supplied source analysis",
		"locale code such as ko_KR",
		"Translate all human-readable prose into the target language",
		"response that leaves all human-readable prose in the source language is",
		"Repeating an existing protected term",
		"Natural line wrapping and paragraph spacing may change",
		"source_analysis: the completed LLM analysis to translate",
		"Return only the translated Markdown analysis",
	}

	for _, value := range expected {
		if !strings.Contains(SystemPrompt, value) {
			t.Errorf("system prompt does not contain %q", value)
		}
	}
}

func TestSystemPromptIsEmbedded(t *testing.T) {
	t.Parallel()

	if strings.TrimSpace(SystemPrompt) == "" {
		t.Fatal("embedded system prompt is empty")
	}
}
