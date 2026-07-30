// Package llmtranslation contains prompts and helpers for translating an LLM
// analysis without changing its technical meaning.
package llmtranslation

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// SystemPrompt defines the translation-only behavior used for a second LLM
// request after log analysis.
//
//go:embed prompts/system_prompt.txt
var SystemPrompt string

// PromptInput is deliberately limited to the configured language and the
// assistant's completed analysis. Raw logs, source evidence, and Ollama
// response metadata belong to other stages and are not translation input.
type PromptInput struct {
	TargetLang string
	Analysis   string
}

type promptPayload struct {
	TargetLang string `json:"target_lang"`
	Analysis   string `json:"analysis"`
}

// BuildUserPrompt creates the data-only translation request.
func BuildUserPrompt(input PromptInput) (string, error) {
	targetLang := strings.TrimSpace(input.TargetLang)
	if targetLang == "" {
		return "", fmt.Errorf("BuildUserPrompt: target language is empty")
	}
	if strings.TrimSpace(input.Analysis) == "" {
		return "", fmt.Errorf("BuildUserPrompt: analysis is empty")
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(promptPayload{
		TargetLang: targetLang,
		Analysis:   input.Analysis,
	}); err != nil {
		return "", fmt.Errorf("BuildUserPrompt: encode payload: %w", err)
	}

	return buf.String(), nil
}
