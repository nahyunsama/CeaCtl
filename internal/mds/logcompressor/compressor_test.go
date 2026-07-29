package logcompressor

import (
	"strings"
	"testing"
	"time"
)

func mustParseDay(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse("2006 Jan 2 15:04:05", s)
	if err != nil {
		t.Fatalf("failed to parse test time %q: %v", s, err)
	}
	return tm
}

func TestAnalyze_GroupsIdenticalEvents(t *testing.T) {
	log := strings.Join([]string{
		"2024 Jan 15 10:23:45 switch1 %PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
		"2024 Jan 15 10:24:10 switch1 %PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(result.Groups))
	}

	g := result.Groups[0]
	if g.Count != 2 {
		t.Errorf("Count = %d, want 2", g.Count)
	}
	if g.Facility != "PORT" || g.Mnemonic != "IF_DOWN" || g.Iface != "fc1/1" || g.Vsan != "100" {
		t.Errorf("unexpected group fields: %+v", g)
	}

	wantFirst := mustParseDay(t, "2024 Jan 15 10:23:45")
	wantLast := mustParseDay(t, "2024 Jan 15 10:24:10")
	if !g.First.Equal(wantFirst) {
		t.Errorf("First = %v, want %v", g.First, wantFirst)
	}
	if !g.Last.Equal(wantLast) {
		t.Errorf("Last = %v, want %v", g.Last, wantLast)
	}
}

func TestAnalyze_DifferentInterfacesCreateSeparateGroups(t *testing.T) {
	log := strings.Join([]string{
		"2024 Jan 15 10:23:45 switch1 %PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
		"2024 Jan 15 10:23:46 switch1 %PORT-5-IF_DOWN: Interface fc1/2, VSAN 100 is down",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(result.Groups))
	}
}

func TestAnalyze_UnparsedLines(t *testing.T) {
	log := strings.Join([]string{
		"this line has no timestamp at all",
		"2024 Jan 15 10:23:45 switch1 no mnemonic here",
		"",
		"2024 Jan 15 10:23:46 switch1 %PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(result.Groups))
	}
	if len(result.Unparsed) != 2 {
		t.Fatalf("got %d unparsed lines, want 2 (blank line must be skipped entirely): %v", len(result.Unparsed), result.Unparsed)
	}
}

func TestAnalyze_FromToFiltersOutOfRangeLines(t *testing.T) {
	log := strings.Join([]string{
		"2024 Jan 15 09:00:00 switch1 %PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
		"2024 Jan 15 10:00:00 switch1 %PORT-5-IF_UP: Interface fc1/1, VSAN 100 is up",
		"2024 Jan 15 11:00:00 switch1 %PORT-5-IF_DOWN: Interface fc1/2, VSAN 200 is down",
	}, "\n")

	from := mustParseDay(t, "2024 Jan 15 09:30:00")
	to := mustParseDay(t, "2024 Jan 15 10:30:00")

	result, err := Analyze(strings.NewReader(log), from, to)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Groups) != 1 {
		t.Fatalf("got %d groups, want 1 (only the 10:00:00 line falls in range)", len(result.Groups))
	}
	if result.Groups[0].Mnemonic != "IF_UP" {
		t.Errorf("got mnemonic %q, want IF_UP", result.Groups[0].Mnemonic)
	}
	if len(result.Unparsed) != 0 {
		t.Errorf("got %d unparsed, want 0 (out-of-range lines are dropped, not marked unparsed)", len(result.Unparsed))
	}
}

func TestParseTS(t *testing.T) {
	tests := []struct {
		name string
		line string
		want time.Time
		ok   bool
	}{
		{
			name: "valid timestamp at line start",
			line: "2024 Jan 15 10:23:45 switch1 %PORT-5-IF_DOWN: Interface fc1/1 is down",
			want: mustParseDay(t, "2024 Jan 15 10:23:45"),
			ok:   true,
		},
		{
			name: "timestamp not at line start",
			line: "switch1 2024 Jan 15 10:23:45 %PORT-5-IF_DOWN: Interface fc1/1 is down",
			ok:   false,
		},
		{
			name: "regex matches but month name is invalid",
			line: "2024 Xxx 15 10:23:45 switch1 message",
			ok:   false,
		},
		{
			name: "empty line",
			line: "",
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseTS(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && !got.Equal(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMnemonic(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		wantFacility string
		wantSeverity string
		wantMnemonic string
		ok           bool
	}{
		{
			name:         "valid mnemonic",
			line:         "2024 Jan 15 10:23:45 switch1 %PORT-5-IF_DOWN: Interface fc1/1 is down",
			wantFacility: "PORT",
			wantSeverity: "5",
			wantMnemonic: "IF_DOWN",
			ok:           true,
		},
		{
			name:         "space before mnemonic colon",
			line:         "2024 Jan 15 10:23:45 switch1 %SYSLOG-2-SYSTEM_MSG : logflash is online",
			wantFacility: "SYSLOG",
			wantSeverity: "2",
			wantMnemonic: "SYSTEM_MSG",
			ok:           true,
		},
		{
			name: "no mnemonic present",
			line: "2024 Jan 15 10:23:45 switch1 plain log message",
			ok:   false,
		},
		{
			name: "lowercase does not match",
			line: "2024 Jan 15 10:23:45 switch1 %port-5-if_down: interface fc1/1 is down",
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facility, severity, mnemonic, ok := parseMnemonic(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if facility != tt.wantFacility || severity != tt.wantSeverity || mnemonic != tt.wantMnemonic {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)",
					facility, severity, mnemonic, tt.wantFacility, tt.wantSeverity, tt.wantMnemonic)
			}
		})
	}
}

func TestParseInterface(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "comma-terminated interface",
			line: "%PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
			want: "fc1/1",
		},
		{
			name: "is-terminated interface without comma",
			line: "%PORT-5-IF_DOWN: Interface mgmt0 is up",
			want: "mgmt0",
		},
		{
			name: "no interface mentioned",
			line: "%PORT-5-IF_DOWN: some other message",
			want: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseInterface(tt.line); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseVsan(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "vsan with space, uppercase",
			line: "Interface fc1/1, VSAN 100 is down",
			want: "100",
		},
		{
			name: "vsan without space, lowercase",
			line: "Interface fc1/1, vsan200 is down",
			want: "200",
		},
		{
			name: "no vsan mentioned",
			line: "Interface fc1/1 is down",
			want: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVsan(tt.line); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAnalyze_GroupsOrderedByFirstOccurrence(t *testing.T) {
	log := strings.Join([]string{
		"2024 Jan 15 10:00:00 switch1 %PORT-5-IF_DOWN: Interface fc1/2, VSAN 200 is down",
		"2024 Jan 15 09:00:00 switch1 %PORT-5-IF_DOWN: Interface fc1/1, VSAN 100 is down",
	}, "\n")

	result, err := Analyze(strings.NewReader(log), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(result.Groups))
	}
	if result.Groups[0].Iface != "fc1/1" {
		t.Errorf("Groups[0].Iface = %q, want fc1/1 (earlier timestamp should sort first)", result.Groups[0].Iface)
	}
	if result.Groups[1].Iface != "fc1/2" {
		t.Errorf("Groups[1].Iface = %q, want fc1/2", result.Groups[1].Iface)
	}
}

func TestAnalyze_PreservesMessageVariants(t *testing.T) {
	log := strings.Join([]string{
		"2026 Jun 1 13:57:25 switch " +
			"%ETHPORT-4-IF_SFP_WARNING: " +
			"Interface IPStorage1/6, Low Rx Power Warning",
		"2026 Jun 1 14:07:26 switch " +
			"%ETHPORT-4-IF_SFP_WARNING: " +
			"Interface IPStorage1/6, Low Rx Power Warning cleared",
	}, "\n")

	result, err := Analyze(
		strings.NewReader(log),
		time.Time{},
		time.Time{},
	)
	if err != nil {
		t.Fatalf("Analyze returned an error: %v", err)
	}

	if len(result.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(result.Groups))
	}

	group := result.Groups[0]

	if group.Count != 2 {
		t.Fatalf("got group count %d, want 2", group.Count)
	}

	if len(group.Variants) != 2 {
		t.Fatalf(
			"got %d variants, want 2",
			len(group.Variants),
		)
	}

	if group.Variants[0].Message !=
		"Interface IPStorage1/6, Low Rx Power Warning" {
		t.Errorf(
			"unexpected first variant: %q",
			group.Variants[0].Message,
		)
	}

	if group.Variants[1].Message !=
		"Interface IPStorage1/6, Low Rx Power Warning cleared" {
		t.Errorf(
			"unexpected second variant: %q",
			group.Variants[1].Message,
		)
	}
}

func TestParseInterface_PortForm(t *testing.T) {
	line := "%PORT-5-IF_PORT_QUIESCE_FAILED: " +
		"Interface fcip303 port quiesce failed"

	got := parseInterface(line)
	if got != "fcip303" {
		t.Errorf("got interface %q, want %q", got, "fcip303")
	}
}
