package logcompressor

import (
	"strings"
	"testing"
	"time"
)

func TestAnalyze_CompressesOrderedTargetStateRuns(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jun 1 10:00:00 sw %PORT-5-IF_DOWN_LINK_FAILURE: Interface fc1/1 is down (Link failure)",
		"2026 Jun 1 10:00:01 sw %PORT-5-IF_DOWN_LINK_FAILURE: Interface fc1/1 is down (Link failure)",
		"2026 Jun 1 10:00:02 sw %PORT-5-IF_UP: Interface fc1/1 is up",
		"2026 Jun 1 10:00:03 sw %PORT-5-IF_UP: Interface fc1/1 is up",
		"2026 Jun 1 10:00:04 sw %PORT-5-IF_DOWN_LINK_FAILURE: Interface fc1/1 is down (Link failure)",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Sequences) != 1 {
		t.Fatalf("got %d sequences, want 1", len(result.Sequences))
	}

	sequence := result.Sequences[0]
	if sequence.Transition != "downx2>upx2>down" {
		t.Errorf("transition = %q, want downx2>upx2>down", sequence.Transition)
	}
	if sequence.Final != "down" {
		t.Errorf("final = %q, want down", sequence.Final)
	}
}

func TestAnalyze_PairsAlarmAndCleared(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jun 1 13:57:25 sw %ETHPORT-3-IF_SFP_ALARM: Interface IPStorage1/6, Low Rx Power Alarm",
		"2026 Jun 1 14:07:26 sw %ETHPORT-3-IF_SFP_ALARM: Interface IPStorage1/6, Low Rx Power Alarm cleared",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(result.Events))
	}

	event := result.Events[0]
	if event.Transition != "asserted>cleared" {
		t.Errorf("transition = %q, want asserted>cleared", event.Transition)
	}
	if event.Role != "cause_candidate>recovery" {
		t.Errorf("role = %q, want cause_candidate>recovery", event.Role)
	}
	if event.Detail != "episodes=1,duration=10m1s" {
		t.Errorf("detail = %q, want paired duration", event.Detail)
	}
}

func TestAnalyze_AggregatesSameSemanticEventAcrossTargets(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jul 1 07:36:29 sw %PORT-5-IF_DOWN_ADMIN_DOWN: %$VSAN 1%$ Interface fc1/3 is down (Administratively down)",
		"2026 Jul 1 07:36:30 sw %PORT-5-IF_DOWN_ADMIN_DOWN: %$VSAN 1%$ Interface fc1/4 is down (Administratively down)",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(result.Events))
	}

	event := result.Events[0]
	if event.Count != 2 || len(event.Targets) != 2 {
		t.Errorf("event was not aggregated: %+v", event)
	}
	if event.Type != "configuration" ||
		event.Role != "context" ||
		event.Reason != "admin_down" {
		t.Errorf("unexpected semantic classification: %+v", event)
	}
}

func TestAnalyze_PreservesUnclassifiedMessageAsUnknownDetail(t *testing.T) {
	log := "2026 Jul 1 07:35:24 sw %KERN-3-SYSTEM_MSG: unusual diagnostic payload"

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(result.Events))
	}
	event := result.Events[0]
	if event.Type != "unknown" ||
		event.Detail != "unusual diagnostic payload" {
		t.Errorf("unexpected unknown event: %+v", event)
	}
}

func TestAnalyze_SplitsSameSemanticEventAcrossLongGap(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jun 1 10:00:00 sw %PORT-5-IF_DOWN_LINK_FAILURE: Interface fc1/1 is down (Link failure)",
		"2026 Jun 1 22:00:00 sw %PORT-5-IF_DOWN_LINK_FAILURE: Interface fc1/2 is down (Link failure)",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("got %d events, want 2 incidents", len(result.Events))
	}
}

func TestAnalyze_ClassifiesSpecificReasonsBeforeGenericDown(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jun 1 10:00:00 sw %PORT-5-IF_TRUNK_DOWN: %$VSAN 12%$ Interface fcip303 is down (Isolation due to vsan not configured on peer)",
		"2026 Jun 1 10:00:01 sw %PORT-5-IF_PORT_QUIESCE_FAILED: Interface fcip303 port quiesce failed due to failure reason: Force Abort Due to Link Failure (0xa2)",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(result.Events))
	}
	if result.Events[0].Reason != "vsan_not_configured_on_peer" ||
		result.Events[0].Type != "configuration" {
		t.Errorf("unexpected VSAN classification: %+v", result.Events[0])
	}
	if result.Events[1].Reason != "port_quiesce_failed_link_failure" ||
		result.Events[1].Type != "state" {
		t.Errorf("unexpected quiesce classification: %+v", result.Events[1])
	}
}

func TestClassifyOccurrence_DoesNotTreatNotFoundAsDetection(t *testing.T) {
	occurrence := rawOccurrence{
		GroupKey: groupKey{
			facility: "KERN",
			severity: "3",
			mnemonic: "SYSTEM_MSG",
			iface:    "-",
			vsan:     "-",
		},
		Message: "libphy: PHY fixed-0:ff not found - kernel",
	}

	got := classifyOccurrence(occurrence, "startup", "")
	if got.known || got.eventType != "unknown" {
		t.Errorf("not-found diagnostic was misclassified: %+v", got)
	}
}

func TestAnalyze_GroupsUnknownKernelMessagesIgnoringElapsedPrefix(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jul 1 07:35:24 sw %KERN-3-SYSTEM_MSG: [ 16.060438] libphy: PHY fixed-0:ff not found - kernel",
		"2026 Jul 1 07:35:24 sw %KERN-3-SYSTEM_MSG: [ 135.878006] libphy: PHY fixed-0:ff not found - kernel",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].Count != 2 {
		t.Errorf("elapsed prefixes prevented unknown grouping: %+v", result.Events)
	}
}
