package llmtranslation

import (
	"strings"
	"testing"
)

func TestSystemPromptDefinesTranslationOnlyContract(t *testing.T) {
	t.Parallel()

	expected := []string{
		"single task is to translate the supplied LLM analysis",
		"locale configured for translated output",
		"Preserve the original meaning, confidence, scope, and level of certainty",
		"Preserve the Markdown structure",
		"Event IDs such as E1 and E2",
		"configuration keys",
		"adds no diagnosis",
		"Return only the translated analysis",
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
