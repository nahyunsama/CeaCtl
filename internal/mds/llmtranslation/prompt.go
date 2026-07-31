// Package llmtranslation translates and validates LLM analysis output.
package llmtranslation

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed prompts/system_prompt.txt
var SystemPrompt string

// PromptInput excludes raw logs, evidence, and transport metadata by design.
type PromptInput struct {
	TargetLang string
	Analysis   string
}

const userPromptTemplate = `Translate the source analysis into the language specified by target_lang.

Interpret target_lang as either a locale code, language code, or language name.
All human-readable prose must be written in that target language.
Keep protected technical values unchanged.

target_lang: %s

<source_analysis>
%s
</source_analysis>

Return only the translated Markdown analysis.
`

func BuildUserPrompt(input PromptInput) (string, error) {
	targetLang := strings.TrimSpace(input.TargetLang)
	if targetLang == "" {
		return "", fmt.Errorf("BuildUserPrompt: target language is empty")
	}
	if strings.ContainsAny(targetLang, "\r\n") {
		return "", fmt.Errorf(
			"BuildUserPrompt: target language contains a line break",
		)
	}
	if strings.TrimSpace(input.Analysis) == "" {
		return "", fmt.Errorf("BuildUserPrompt: analysis is empty")
	}

	return fmt.Sprintf(
		userPromptTemplate,
		targetLang,
		input.Analysis,
	), nil
}
