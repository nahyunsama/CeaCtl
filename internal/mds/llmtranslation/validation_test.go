package llmtranslation

import (
	"strings"
	"testing"
)

const validationOriginal = `## Operational context

* Pattern: operational incident on MDS-1
* Evidence: E1

## Key findings

1. Interface fc1/1 on VSAN 22 is DOWN due to link_failure at 2026-06-01 12:00:00. (E1)
2. Run ` + "`show interface fc1/1`" + ` and confirm 3 dBm.`

const validKoreanTranslation = `## 운영 컨텍스트

* 패턴: MDS-1의 운영 장애
* 증거: E1

## 주요 발견 사항

1. VSAN 22의 인터페이스 fc1/1은 2026-06-01 12:00:00에 link_failure로 인해 DOWN 상태입니다. (E1)
2. ` + "`show interface fc1/1`" + ` 명령을 실행하여 3 dBm을 확인하십시오.`

func TestValidate_AcceptsPreservedTranslation(t *testing.T) {
	t.Parallel()

	err := Validate(ValidationInput{
		TargetLang:  "ko_KR",
		Original:    validationOriginal,
		Translation: validKoreanTranslation,
	})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
}

func TestValidate_RejectsContractViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		translation string
		want        string
	}{
		{
			name:        "empty translation",
			translation: " ",
			want:        "translated analysis is empty",
		},
		{
			name: "event ID changed",
			translation: strings.ReplaceAll(
				validKoreanTranslation,
				"E1",
				"E2",
			),
			want: "Event IDs differ",
		},
		{
			name: "technical token changed",
			translation: strings.ReplaceAll(
				validKoreanTranslation,
				"fc1/1",
				"fc1/2",
			),
			want: "protected technical tokens differ",
		},
		{
			name: "numeric literal changed",
			translation: strings.Replace(
				validKoreanTranslation,
				"3 dBm",
				"4 dBm",
				1,
			),
			want: "numeric literals are missing",
		},
		{
			name: "Markdown list changed",
			translation: strings.Replace(
				validKoreanTranslation,
				"* 패턴:",
				"패턴:",
				1,
			),
			want: "Markdown heading/list structure changed",
		},
		{
			name:        "target script missing",
			translation: validationOriginal,
			want:        "target language script was not detected",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := Validate(ValidationInput{
				TargetLang:  "ko_KR",
				Original:    validationOriginal,
				Translation: test.translation,
			})
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !strings.HasPrefix(
				err.Error(),
				"LLM translation validation failed:",
			) {
				t.Fatalf("unexpected error prefix: %v", err)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"error %q does not contain %q",
					err,
					test.want,
				)
			}
		})
	}
}

func TestValidate_AllowsRepeatedTermsAndParagraphChanges(t *testing.T) {
	t.Parallel()

	translation := strings.Replace(
		validKoreanTranslation,
		"* 패턴: MDS-1의 운영 장애",
		"* 패턴: MDS-1의 SAN 및 VSAN 22 운영 장애\n\n  VSAN 22를 확인했습니다.",
		1,
	)

	err := Validate(ValidationInput{
		TargetLang:  "ko_KR",
		Original:    validationOriginal,
		Translation: translation,
	})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
}

func TestValidate_AllowsBackticksAddedAroundExistingReasonValues(t *testing.T) {
	t.Parallel()

	original := `## Findings

* Authentication failed with authentication_failed and low_rx_power_warning/alarm. (E1)`
	translation := `## 발견 사항

* 인증이 ` + "`authentication_failed`" + ` 및 ` +
		"`low_rx_power_warning/alarm`" + ` 상태로 실패했습니다. (E1)`

	err := Validate(ValidationInput{
		TargetLang:  "ko_KR",
		Original:    original,
		Translation: translation,
	})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
}

func TestValidate_AllowsLocalesWithoutDistinctScriptCheck(t *testing.T) {
	t.Parallel()

	err := Validate(ValidationInput{
		TargetLang:  "fr_FR",
		Original:    "## Status\n\n* Evidence: E1",
		Translation: "## État\n\n* Preuve : E1",
	})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
}
