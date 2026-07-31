package llmanalysis

import (
	"regexp"
	"strings"
	"testing"
)

func TestSystemPrompt_UsesPositiveGuidanceForCriticalRules(t *testing.T) {
	expected := []string{
		"Use no more than eight unique Event IDs",
		"reason=none, unspecified, or admin_down",
		"Apply reasons such as members_down, license_unavailable",
		"Treat physical Ethernet interfaces, FC interfaces, port-channels",
		"independent fault evidence, including during startup",
		"Connect a possible cause to an effect when they:",
		"share the same target",
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
