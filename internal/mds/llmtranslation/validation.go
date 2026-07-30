package llmtranslation

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	eventIDPattern = regexp.MustCompile(`\bE[1-9][0-9]*\b`)
	numberPattern  = regexp.MustCompile(`\b[0-9]+(?:\.[0-9]+)?\b`)
	inlineCodePattern = regexp.MustCompile(
		"`([^`\\r\\n]+)`",
	)

	protectedTokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`),
		regexp.MustCompile(`\b[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}:[0-9]{2})?\b`),
		regexp.MustCompile(`\b[0-9]{2}:[0-9]{2}:[0-9]{2}\b`),
		regexp.MustCompile(`(?i)\b(?:fc|fcip|ethernet|eth|mgmt|port-channel|portchannel|po|ipstorage|vlan)[0-9]+(?:[/.:_-][0-9]+)*(?:@vsan[0-9]+)?\b`),
		regexp.MustCompile(`(?i)\bVSAN(?:\s+|@)?[0-9]+\b`),
		regexp.MustCompile(`\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?:/[a-z][a-z0-9_]*)*\b`),
		regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-[A-Za-z0-9]*[0-9][A-Za-z0-9-]*\b`),
		regexp.MustCompile(`\bv?[0-9]+(?:\.[0-9]+){1,}(?:\([^)]+\)|[A-Za-z0-9.-]*)?\b`),
		regexp.MustCompile(`[-+]?[0-9]+(?:\.[0-9]+)?\s?(?:dBm|dB|ms|sec|seconds?|minutes?|hours?|%|V|A|W|°C)\b`),
		regexp.MustCompile(`\b(?:show|clear|ping|traceroute|debug|undebug)\s+(?:interface|logging|module|environment|version|inventory|port-channel|fcns|flogi|zoneset|zone|vsan|processes|tech-support)\b`),
		regexp.MustCompile(`[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+`),
		regexp.MustCompile(`(?:\./|\.\./|/(?:etc|var|tmp|home|opt|usr)/)[A-Za-z0-9_./-]+`),
	}

	headingPattern  = regexp.MustCompile(`^(#{1,6})[ \t]+`)
	bulletPattern   = regexp.MustCompile(`^([ \t]*)[-+*][ \t]+`)
	numberedPattern = regexp.MustCompile(
		`^([ \t]*)[0-9]+[.)][ \t]+`,
	)
	quotePattern = regexp.MustCompile(`^([ \t]*)>[ \t]?`)
	fencePattern = regexp.MustCompile(`^([ \t]*)(?:` + "```" + `|~~~)`)
)

// ValidationInput contains the source and translated analysis to compare
// before either is written as final LLM output.
type ValidationInput struct {
	TargetLang  string
	Original    string
	Translation string
}

// ValidationError reports deterministic translation contract violations.
type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return "LLM translation validation failed: " +
		strings.Join(e.Issues, "; ")
}

// Validate checks structural and technical invariants that a translation must
// preserve. It does not attempt to judge semantic translation quality.
func Validate(input ValidationInput) error {
	var issues []string

	if strings.TrimSpace(input.Original) == "" {
		issues = append(issues, "original analysis is empty")
	}
	if strings.TrimSpace(input.Translation) == "" {
		issues = append(issues, "translated analysis is empty")
	}
	if strings.TrimSpace(input.TargetLang) == "" {
		issues = append(issues, "target language is empty")
	}

	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}

	if missing, unexpected := setDifferences(
		tokenCounts(eventIDPattern, input.Original),
		tokenCounts(eventIDPattern, input.Translation),
	); len(missing) > 0 || len(unexpected) > 0 {
		issues = append(
			issues,
			"Event IDs differ ("+
				formatSetDifferences(missing, unexpected)+")",
		)
	}

	if missing, unexpected := setDifferences(
		protectedTokenCounts(input.Original),
		protectedTokenCounts(input.Translation),
	); len(missing) > 0 || len(unexpected) > 0 {
		issues = append(
			issues,
			"protected technical tokens differ ("+
				formatSetDifferences(missing, unexpected)+")",
		)
	}

	if missing, _ := setDifferences(
		tokenCounts(numberPattern, input.Original),
		tokenCounts(numberPattern, input.Translation),
	); len(missing) > 0 {
		issues = append(
			issues,
			"numeric literals are missing ("+
				strings.Join(missing, ", ")+")",
		)
	}

	if !reflect.DeepEqual(
		markdownSignature(input.Original),
		markdownSignature(input.Translation),
	) {
		issues = append(issues, "Markdown heading/list structure changed")
	}

	if !containsTargetScript(input.TargetLang, input.Translation) {
		issues = append(
			issues,
			fmt.Sprintf(
				"target language script was not detected for %s",
				strings.TrimSpace(input.TargetLang),
			),
		)
	}

	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}
	return nil
}

func tokenCounts(pattern *regexp.Regexp, text string) map[string]int {
	counts := make(map[string]int)
	for _, token := range pattern.FindAllString(text, -1) {
		counts[token]++
	}
	return counts
}

func protectedTokenCounts(text string) map[string]int {
	counts := make(map[string]int)

	for _, match := range inlineCodePattern.FindAllStringSubmatch(text, -1) {
		token := strings.TrimSpace(match[1])
		if token != "" {
			counts[token]++
		}
	}

	for _, pattern := range protectedTokenPatterns {
		patternCounts := tokenCounts(pattern, text)
		for token, count := range patternCounts {
			if count > counts[token] {
				counts[token] = count
			}
		}
	}
	return counts
}

func setDifferences(
	original map[string]int,
	translation map[string]int,
) (missing []string, unexpected []string) {
	for token := range original {
		if _, exists := translation[token]; !exists {
			missing = append(missing, token)
		}
	}
	for token := range translation {
		if _, exists := original[token]; !exists {
			unexpected = append(unexpected, token)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	return missing, unexpected
}

func formatSetDifferences(missing, unexpected []string) string {
	var values []string
	if len(missing) > 0 {
		values = append(values, "missing="+strings.Join(missing, ", "))
	}
	if len(unexpected) > 0 {
		values = append(
			values,
			"unexpected="+strings.Join(unexpected, ", "),
		)
	}
	return strings.Join(values, "; ")
}

func markdownSignature(text string) []string {
	var signature []string
	for _, line := range strings.Split(
		strings.ReplaceAll(text, "\r\n", "\n"),
		"\n",
	) {
		switch {
		case headingPattern.MatchString(line):
			match := headingPattern.FindStringSubmatch(line)
			signature = append(signature, "heading:"+match[1])
		case bulletPattern.MatchString(line):
			match := bulletPattern.FindStringSubmatch(line)
			signature = append(signature, "bullet:"+match[1])
		case numberedPattern.MatchString(line):
			match := numberedPattern.FindStringSubmatch(line)
			signature = append(signature, "numbered:"+match[1])
		case quotePattern.MatchString(line):
			match := quotePattern.FindStringSubmatch(line)
			signature = append(signature, "quote:"+match[1])
		case fencePattern.MatchString(line):
			match := fencePattern.FindStringSubmatch(line)
			signature = append(signature, "fence:"+match[1])
		}
	}
	return signature
}

func containsTargetScript(targetLang string, text string) bool {
	language := strings.ToLower(strings.TrimSpace(targetLang))
	if separator := strings.IndexAny(language, "_-"); separator >= 0 {
		language = language[:separator]
	}

	var tables []*unicode.RangeTable
	switch language {
	case "ko":
		tables = []*unicode.RangeTable{unicode.Hangul}
	case "ja":
		tables = []*unicode.RangeTable{
			unicode.Hiragana,
			unicode.Katakana,
			unicode.Han,
		}
	case "zh":
		tables = []*unicode.RangeTable{unicode.Han}
	case "ru", "uk", "bg":
		tables = []*unicode.RangeTable{unicode.Cyrillic}
	case "ar":
		tables = []*unicode.RangeTable{unicode.Arabic}
	case "he":
		tables = []*unicode.RangeTable{unicode.Hebrew}
	case "th":
		tables = []*unicode.RangeTable{unicode.Thai}
	default:
		return true
	}

	for _, value := range text {
		if unicode.IsOneOf(tables, value) {
			return true
		}
	}
	return false
}
