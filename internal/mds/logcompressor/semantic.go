package logcompressor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	reSupervisorTarget  = regexp.MustCompile(`(?i)\bSupervisor\s+\d+\b`)
	reModuleTarget      = regexp.MustCompile(`(?i)\bModule\s+\d+\b`)
	rePowerSupplyTarget = regexp.MustCompile(`(?i)\bPower\s*supply\s+\d+\b`)
	reFanModuleTarget   = regexp.MustCompile(`(?i)\bFan module\s+\d+\b`)
	reEthernetTarget    = regexp.MustCompile(`(?i)\beth\d+\b`)
	reKernelElapsed     = regexp.MustCompile(`^\[\s*\d+(?:\.\d+)?\]\s*`)
)

// Event is the compact semantic unit printed to the console and sent to the
// LLM. SourceGroupIDs retain the mechanically grouped evidence behind it.
type Event struct {
	Targets        []string
	Type           string
	Role           string
	Transition     string
	Reason         string
	Final          string
	Detail         string
	Count          int
	First          time.Time
	Last           time.Time
	SourceGroupIDs []int
	firstOrder     int
}

// TargetSequence keeps only actual state changes for one target. Repeated
// identical states are represented as a run count, for example downx3>upx2.
type TargetSequence struct {
	Target     string
	Transition string
	Final      string
	Count      int
	First      time.Time
	Last       time.Time
	firstOrder int
}

type rawOccurrence struct {
	GroupKey  groupKey
	Timestamp time.Time
	Order     int
	Message   string
}

type semanticOccurrence struct {
	target     string
	eventType  string
	role       string
	transition string
	reason     string
	known      bool
}

type transitionRun struct {
	value string
	count int
}

type eventAccumulator struct {
	event            Event
	targetSeen       map[string]struct{}
	sourceGroupSeen  map[int]struct{}
	roles            []string
	roleSeen         map[string]struct{}
	transitions      []transitionRun
	alarm            bool
	alarmActive      bool
	alarmStarted     time.Time
	alarmDurations   []time.Duration
	preexistingClear int
}

type sequenceAccumulator struct {
	sequence TargetSequence
	runs     []transitionRun
}

const semanticAggregationGap = 15 * time.Minute

// StructuredEvents returns the semantic events produced by Analyze. The
// fallback keeps manually constructed Results useful in tests and callers.
func (r *Result) StructuredEvents() []Event {
	if len(r.Events) > 0 || len(r.Groups) == 0 {
		return r.Events
	}

	var occurrences []rawOccurrence
	groupIDs := make(map[groupKey]int, len(r.Groups))
	order := 0

	for index, group := range r.Groups {
		key := groupKey{
			facility: group.Facility,
			severity: group.Severity,
			mnemonic: group.Mnemonic,
			iface:    group.Iface,
			vsan:     group.Vsan,
		}
		groupIDs[key] = index + 1

		if len(group.Variants) == 0 {
			message := parseMessageDetail(group.Sample)
			if message == "" {
				message = group.Sample
			}
			if message == "" {
				message = group.Mnemonic
			}
			count := group.Count
			if count < 1 {
				count = 1
			}
			for occurrenceIndex := 0; occurrenceIndex < count; occurrenceIndex++ {
				timestamp := group.First
				if occurrenceIndex == count-1 && !group.Last.IsZero() {
					timestamp = group.Last
				}
				occurrences = append(occurrences, rawOccurrence{
					GroupKey:  key,
					Timestamp: timestamp,
					Order:     order,
					Message:   message,
				})
				order++
			}
			continue
		}

		for _, variant := range group.Variants {
			count := variant.Count
			if count < 1 {
				count = 1
			}
			for occurrenceIndex := 0; occurrenceIndex < count; occurrenceIndex++ {
				timestamp := variant.First
				if occurrenceIndex == count-1 && !variant.Last.IsZero() {
					timestamp = variant.Last
				}
				occurrences = append(occurrences, rawOccurrence{
					GroupKey:  key,
					Timestamp: timestamp,
					Order:     order,
					Message:   variant.Message,
				})
				order++
			}
		}
	}

	context := r.Context
	if context == "" {
		context = detectContext(occurrences)
		r.Context = context
	}
	r.Events, r.Sequences = buildStructuredEvents(
		occurrences,
		groupIDs,
		context,
	)
	return r.Events
}

func (r *Result) EventCount() int {
	return len(r.StructuredEvents())
}

func detectContext(occurrences []rawOccurrence) string {
	if len(occurrences) == 0 {
		return "unknown"
	}

	start := occurrences[0].Timestamp
	kernelCount := 0
	supervisorOrModuleOnline := false

	for _, occurrence := range occurrences {
		if occurrence.Timestamp.Sub(start) > 10*time.Minute {
			break
		}

		mnemonic := occurrence.GroupKey.mnemonic
		message := strings.ToLower(occurrence.Message)

		if occurrence.GroupKey.facility == "KERN" &&
			mnemonic == "SYSTEM_MSG" {
			kernelCount++
		}
		if mnemonic == "ACTIVE_SUP_OK" ||
			mnemonic == "MOD_OK" ||
			strings.Contains(message, "supervisor") &&
				strings.Contains(message, " is active") ||
			strings.Contains(message, "module") &&
				strings.Contains(message, " is online") {
			supervisorOrModuleOnline = true
		}
	}

	if supervisorOrModuleOnline && kernelCount >= 2 {
		return "startup"
	}
	return "operational_or_unknown"
}

func buildStructuredEvents(
	occurrences []rawOccurrence,
	groupIDs map[groupKey]int,
	context string,
) ([]Event, []TargetSequence) {
	eventByKey := make(map[string]*eventAccumulator)
	var eventKeys []string
	currentEventKey := make(map[string]string)
	eventKeyVersion := make(map[string]int)
	sequenceByTarget := make(map[string]*sequenceAccumulator)
	var sequenceTargets []string
	targetState := make(map[string]string)

	for _, occurrence := range occurrences {
		semantic := classifyOccurrence(
			occurrence,
			context,
			targetState[semanticTarget(occurrence)],
		)
		if isStateTransition(semantic.transition) {
			targetState[semantic.target] = semantic.transition
			accumulateTargetSequence(
				sequenceByTarget,
				&sequenceTargets,
				occurrence,
				semantic,
			)
		}

		baseKey := semanticEventKey(occurrence, semantic)
		key := baseKey
		if currentKey, exists := currentEventKey[baseKey]; exists {
			key = currentKey
			current := eventByKey[key]
			if occurrence.Timestamp.Sub(current.event.Last) >
				semanticAggregationGap {
				eventKeyVersion[baseKey]++
				key = fmt.Sprintf(
					"%s#%d",
					baseKey,
					eventKeyVersion[baseKey],
				)
				currentEventKey[baseKey] = key
			}
		} else {
			currentEventKey[baseKey] = key
		}
		accumulator, exists := eventByKey[key]
		if !exists {
			accumulator = &eventAccumulator{
				event: Event{
					Type:       semantic.eventType,
					Reason:     semantic.reason,
					First:      occurrence.Timestamp,
					Last:       occurrence.Timestamp,
					firstOrder: occurrence.Order,
				},
				targetSeen:      make(map[string]struct{}),
				sourceGroupSeen: make(map[int]struct{}),
				roleSeen:        make(map[string]struct{}),
				alarm:           isAlarmTransition(semantic.transition),
			}
			if !semantic.known {
				accumulator.event.Detail = occurrence.Message
			}
			eventByKey[key] = accumulator
			eventKeys = append(eventKeys, key)
		}

		accumulateEvent(
			accumulator,
			occurrence,
			semantic,
			groupIDs[occurrence.GroupKey],
		)
	}

	sort.SliceStable(eventKeys, func(i, j int) bool {
		left := eventByKey[eventKeys[i]].event
		right := eventByKey[eventKeys[j]].event
		if left.First.Equal(right.First) {
			return left.firstOrder < right.firstOrder
		}
		return left.First.Before(right.First)
	})

	events := make([]Event, 0, len(eventKeys))
	for _, key := range eventKeys {
		accumulator := eventByKey[key]
		finalizeEvent(accumulator)
		events = append(events, accumulator.event)
	}

	sequences := finalizeSequences(sequenceByTarget, sequenceTargets)
	return events, sequences
}

func classifyOccurrence(
	occurrence rawOccurrence,
	context string,
	previousState string,
) semanticOccurrence {
	message := strings.ToLower(occurrence.Message)
	mnemonic := strings.ToUpper(occurrence.GroupKey.mnemonic)
	target := semanticTarget(occurrence)

	if isMeasurementMessage(mnemonic, message) {
		reason := measurementReason(mnemonic, message)
		if strings.Contains(message, "clear") {
			return semanticOccurrence{
				target: target, eventType: "measurement",
				role: "recovery", transition: "cleared",
				reason: reason, known: true,
			}
		}
		return semanticOccurrence{
			target: target, eventType: "measurement",
			role: "cause_candidate", transition: "asserted",
			reason: reason, known: true,
		}
	}

	if strings.Contains(mnemonic, "ADMIN_DOWN") ||
		strings.Contains(message, "administratively down") {
		return semanticOccurrence{
			target: target, eventType: "configuration",
			role: "context", transition: "down",
			reason: "admin_down", known: true,
		}
	}

	if strings.Contains(mnemonic, "LICENSE_NOT_AVAILABLE") ||
		strings.Contains(message, "license not available") {
		return semanticOccurrence{
			target: target, eventType: "configuration",
			role: "cause_candidate", transition: "blocked",
			reason: "license_unavailable", known: true,
		}
	}

	if strings.Contains(message, "authentication failed") {
		return semanticOccurrence{
			target: "authentication", eventType: "security",
			role: "cause_candidate", transition: "failed",
			reason: "authentication_failed", known: true,
		}
	}

	if strings.Contains(message, "authentication failure") {
		return semanticOccurrence{
			target: "authentication", eventType: "security",
			role: "cause_candidate", transition: "failed",
			reason: "authentication_failed", known: true,
		}
	}

	if strings.Contains(message, "vsan not configured on peer") {
		return semanticOccurrence{
			target: target, eventType: "configuration",
			role: "cause_candidate", transition: "down",
			reason: "vsan_not_configured_on_peer", known: true,
		}
	}

	if strings.Contains(message, "port quiesce failed") {
		reason := "port_quiesce_failed"
		if strings.Contains(message, "link failure") {
			reason = "port_quiesce_failed_link_failure"
		}
		return semanticOccurrence{
			target: target, eventType: "state",
			role: "effect", transition: "failed",
			reason: reason, known: true,
		}
	}

	if mnemonicIndicatesDown(mnemonic) || containsState(message, "down") {
		return semanticOccurrence{
			target: target, eventType: "state",
			role: "effect", transition: "down",
			reason: downReason(mnemonic, message), known: true,
		}
	}

	if mnemonicIndicatesUp(mnemonic) || containsState(message, "up") {
		role := transitionRole(context, previousState)
		return semanticOccurrence{
			target: target, eventType: "state",
			role: role, transition: "up",
			reason: "none", known: true,
		}
	}

	if strings.Contains(message, " is online") ||
		strings.Contains(message, "status_online") {
		role := transitionRole(context, previousState)
		return semanticOccurrence{
			target: target, eventType: "state",
			role: role, transition: "online",
			reason: "none", known: true,
		}
	}

	if mnemonicIndicatesOK(mnemonic, message) {
		role := "status"
		if context == "startup" {
			role = "initialization"
		}
		return semanticOccurrence{
			target: target, eventType: "state",
			role: role, transition: "ok",
			reason: "none", known: true,
		}
	}

	found := strings.Contains(message, " found") &&
		!strings.Contains(message, " not found")
	detected := strings.Contains(message, " detected") &&
		!strings.Contains(message, " not detected")
	if context == "startup" && (found || detected) {
		return semanticOccurrence{
			target: target, eventType: "state",
			role: "initialization", transition: "detected",
			reason: "none", known: true,
		}
	}

	if strings.Contains(mnemonic, "CREATED") {
		return semanticOccurrence{
			target: target, eventType: "configuration",
			role: "context", transition: "created",
			reason: "configuration_created", known: true,
		}
	}

	if strings.Contains(mnemonic, "CONFIG") ||
		strings.Contains(message, "configured from") ||
		strings.Contains(message, "config download success") {
		return semanticOccurrence{
			target: target, eventType: "configuration",
			role: "context", transition: "changed",
			reason: "configuration_change", known: true,
		}
	}

	return semanticOccurrence{
		target: target, eventType: "unknown",
		role: "unknown", transition: "unknown",
		reason: "unknown", known: false,
	}
}

func semanticTarget(occurrence rawOccurrence) string {
	if occurrence.GroupKey.iface != "" &&
		occurrence.GroupKey.iface != "-" {
		target := occurrence.GroupKey.iface
		if occurrence.GroupKey.vsan != "" &&
			occurrence.GroupKey.vsan != "-" {
			target += "@vsan" + occurrence.GroupKey.vsan
		}
		return target
	}

	for _, expression := range []*regexp.Regexp{
		reSupervisorTarget,
		rePowerSupplyTarget,
		reFanModuleTarget,
		reModuleTarget,
		reEthernetTarget,
	} {
		if target := expression.FindString(occurrence.Message); target != "" {
			target = strings.ToLower(
				strings.Join(strings.Fields(target), "_"),
			)
			target = strings.ReplaceAll(
				target,
				"powersupply",
				"power_supply",
			)
			return target
		}
	}

	if occurrence.GroupKey.facility == "AUTHPRIV" {
		return "authentication"
	}
	return strings.ToLower(occurrence.GroupKey.facility)
}

func semanticEventKey(
	occurrence rawOccurrence,
	semantic semanticOccurrence,
) string {
	base := strings.Join([]string{
		occurrence.GroupKey.facility,
		occurrence.GroupKey.mnemonic,
		semantic.eventType,
		semantic.reason,
	}, "|")

	if isAlarmTransition(semantic.transition) {
		return "alarm|" + base + "|" + semantic.target
	}
	if !semantic.known {
		return "unknown|" + base + "|" +
			reKernelElapsed.ReplaceAllString(occurrence.Message, "")
	}
	return base + "|" + semantic.role + "|" + semantic.transition
}

func accumulateEvent(
	accumulator *eventAccumulator,
	occurrence rawOccurrence,
	semantic semanticOccurrence,
	groupID int,
) {
	event := &accumulator.event
	event.Count++
	if occurrence.Timestamp.Before(event.First) {
		event.First = occurrence.Timestamp
	}
	if occurrence.Timestamp.After(event.Last) {
		event.Last = occurrence.Timestamp
	}

	if _, exists := accumulator.targetSeen[semantic.target]; !exists {
		accumulator.targetSeen[semantic.target] = struct{}{}
		event.Targets = append(event.Targets, semantic.target)
	}
	if groupID > 0 {
		if _, exists := accumulator.sourceGroupSeen[groupID]; !exists {
			accumulator.sourceGroupSeen[groupID] = struct{}{}
			event.SourceGroupIDs = append(event.SourceGroupIDs, groupID)
		}
	}
	if _, exists := accumulator.roleSeen[semantic.role]; !exists {
		accumulator.roleSeen[semantic.role] = struct{}{}
		accumulator.roles = append(accumulator.roles, semantic.role)
	}
	appendRun(&accumulator.transitions, semantic.transition, 1)

	if !accumulator.alarm {
		return
	}
	switch semantic.transition {
	case "asserted":
		if !accumulator.alarmActive {
			accumulator.alarmActive = true
			accumulator.alarmStarted = occurrence.Timestamp
		}
	case "cleared":
		if accumulator.alarmActive {
			duration := occurrence.Timestamp.Sub(accumulator.alarmStarted)
			if duration >= 0 {
				accumulator.alarmDurations = append(
					accumulator.alarmDurations,
					duration,
				)
			}
			accumulator.alarmActive = false
		} else {
			accumulator.preexistingClear++
		}
	}
}

func finalizeEvent(accumulator *eventAccumulator) {
	event := &accumulator.event
	event.Role = strings.Join(accumulator.roles, ">")
	event.Transition = formatRuns(accumulator.transitions)
	if len(accumulator.transitions) > 0 {
		event.Final = accumulator.transitions[len(accumulator.transitions)-1].value
	} else {
		event.Final = "unknown"
	}

	if !accumulator.alarm {
		return
	}

	episodeCount := len(accumulator.alarmDurations)
	if accumulator.alarmActive {
		episodeCount++
	}
	detailParts := []string{fmt.Sprintf("episodes=%d", episodeCount)}
	if len(accumulator.alarmDurations) > 0 {
		detailParts = append(
			detailParts,
			"duration="+formatDurations(accumulator.alarmDurations),
		)
	}
	if accumulator.alarmActive {
		detailParts = append(detailParts, "open=1")
	}
	if accumulator.preexistingClear > 0 {
		detailParts = append(
			detailParts,
			fmt.Sprintf(
				"preexisting_cleared=%d",
				accumulator.preexistingClear,
			),
		)
	}
	event.Detail = strings.Join(detailParts, ",")
}

func accumulateTargetSequence(
	sequences map[string]*sequenceAccumulator,
	order *[]string,
	occurrence rawOccurrence,
	semantic semanticOccurrence,
) {
	accumulator, exists := sequences[semantic.target]
	if !exists {
		accumulator = &sequenceAccumulator{
			sequence: TargetSequence{
				Target:     semantic.target,
				First:      occurrence.Timestamp,
				Last:       occurrence.Timestamp,
				firstOrder: occurrence.Order,
			},
		}
		sequences[semantic.target] = accumulator
		*order = append(*order, semantic.target)
	}

	accumulator.sequence.Count++
	if occurrence.Timestamp.Before(accumulator.sequence.First) {
		accumulator.sequence.First = occurrence.Timestamp
	}
	if occurrence.Timestamp.After(accumulator.sequence.Last) {
		accumulator.sequence.Last = occurrence.Timestamp
	}
	appendRun(&accumulator.runs, semantic.transition, 1)
}

func finalizeSequences(
	sequences map[string]*sequenceAccumulator,
	targets []string,
) []TargetSequence {
	var result []TargetSequence
	for _, target := range targets {
		accumulator := sequences[target]
		if len(accumulator.runs) < 2 {
			continue
		}

		accumulator.sequence.Transition = formatRuns(accumulator.runs)
		accumulator.sequence.Final =
			accumulator.runs[len(accumulator.runs)-1].value
		result = append(result, accumulator.sequence)
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].First.Equal(result[j].First) {
			return result[i].firstOrder < result[j].firstOrder
		}
		return result[i].First.Before(result[j].First)
	})
	return result
}

func appendRun(runs *[]transitionRun, value string, count int) {
	if len(*runs) > 0 && (*runs)[len(*runs)-1].value == value {
		(*runs)[len(*runs)-1].count += count
		return
	}
	*runs = append(*runs, transitionRun{value: value, count: count})
}

func formatRuns(runs []transitionRun) string {
	parts := make([]string, 0, len(runs))
	for _, run := range runs {
		value := run.value
		if run.count > 1 {
			value += fmt.Sprintf("x%d", run.count)
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, ">")
}

func formatDurations(durations []time.Duration) string {
	parts := make([]string, 0, len(durations))
	for _, duration := range durations {
		parts = append(parts, duration.String())
	}
	return strings.Join(parts, ",")
}

func isMeasurementMessage(mnemonic, message string) bool {
	return strings.Contains(mnemonic, "ALARM") ||
		strings.Contains(mnemonic, "WARNING") ||
		strings.Contains(message, " alarm") ||
		strings.Contains(message, " warning")
}

func measurementReason(mnemonic, message string) string {
	level := "alarm"
	if strings.Contains(mnemonic, "WARNING") ||
		strings.Contains(message, "warning") {
		level = "warning"
	}

	switch {
	case strings.Contains(message, "low rx power"):
		return "low_rx_power_" + level
	case strings.Contains(message, "high rx power"):
		return "high_rx_power_" + level
	case strings.Contains(message, "low tx power"):
		return "low_tx_power_" + level
	case strings.Contains(message, "high tx power"):
		return "high_tx_power_" + level
	case strings.Contains(message, "temperature"):
		return "temperature_" + level
	case strings.Contains(message, "voltage"):
		return "voltage_" + level
	case strings.Contains(message, "current"):
		return "current_" + level
	default:
		return level
	}
}

func downReason(mnemonic, message string) string {
	switch {
	case strings.Contains(message, "parent ethernet link down") ||
		strings.Contains(message, "src interface link down"):
		return "parent_link_down"
	case strings.Contains(message, "max retransmission") ||
		strings.Contains(mnemonic, "MAX_RETRANSMIT"):
		return "tcp_retransmission"
	case strings.Contains(message, "closed by peer") ||
		strings.Contains(mnemonic, "PEER_CLOSE"):
		return "peer_close"
	case strings.Contains(message, "peer reset") ||
		strings.Contains(mnemonic, "PEER_RESET"):
		return "peer_reset"
	case strings.Contains(message, "link reset failed"):
		return "link_reset_failed"
	case strings.Contains(message, "link failure") ||
		strings.Contains(mnemonic, "LINK_FAILURE"):
		return "link_failure"
	case strings.Contains(message, "no operational members") ||
		strings.Contains(mnemonic, "MEMBERS_DOWN"):
		return "members_down"
	case strings.Contains(message, "fcot not present") ||
		strings.Contains(mnemonic, "FCOT_NOT_PRESENT"):
		return "transceiver_not_present"
	case strings.Contains(message, "offline") ||
		strings.Contains(mnemonic, "OFFLINE"):
		return "offline"
	case strings.Contains(message, "(none)"):
		return "unspecified"
	default:
		return "unspecified"
	}
}

func transitionRole(context, previousState string) string {
	if context == "startup" {
		return "initialization"
	}
	switch previousState {
	case "down", "offline", "blocked":
		return "recovery"
	default:
		return "status"
	}
}

func mnemonicIndicatesDown(mnemonic string) bool {
	return strings.Contains(mnemonic, "IF_DOWN") ||
		strings.HasSuffix(mnemonic, "_DOWN")
}

func mnemonicIndicatesUp(mnemonic string) bool {
	return strings.Contains(mnemonic, "IF_UP") ||
		strings.HasSuffix(mnemonic, "_UP")
}

func mnemonicIndicatesOK(mnemonic, message string) bool {
	return strings.HasSuffix(mnemonic, "_OK") ||
		strings.HasSuffix(mnemonic, "FANOK") ||
		strings.Contains(mnemonic, "MOD_STATUS") &&
			strings.Contains(message, "/ok") ||
		strings.Contains(message, " current-status is ps_ok") ||
		strings.TrimSpace(message) == "ok"
}

func containsState(message, state string) bool {
	return strings.Contains(message, " is "+state) ||
		strings.Contains(message, " status is "+state)
}

func isAlarmTransition(transition string) bool {
	return transition == "asserted" || transition == "cleared"
}

func isStateTransition(transition string) bool {
	switch transition {
	case "down", "up", "online", "offline", "blocked":
		return true
	default:
		return false
	}
}
