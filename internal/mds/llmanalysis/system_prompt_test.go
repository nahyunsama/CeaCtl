package llmanalysis

import (
	"regexp"
	"strings"
	"testing"
)

func TestSystemPrompt_UsesPositiveGuidanceForCriticalRules(t *testing.T) {
	expected := []string{
		"Use up to eight unique Event IDs",
		"reason=unspecified or reason=admin_down",
		"Apply reason=license_unavailable to the targets listed",
		"distinct target families",
		"Place type=unknown startup events in Separate observations first",
		"Connect a possible cause to an effect when they share a target",
	}

	for _, value := range expected {
		if !strings.Contains(SystemPrompt, value) {
			t.Errorf("system prompt does not contain %q", value)
		}
	}

	negativeDirective := regexp.MustCompile(
		`(?i)\b(do not|never|must not|should not|cannot|can't|unless)\b`,
	)
	if match := negativeDirective.FindString(SystemPrompt); match != "" {
		t.Errorf(
			"system prompt contains negative directive %q",
			match,
		)
	}
}
