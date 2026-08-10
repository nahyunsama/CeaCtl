package receiver

import (
	"strings"
	"testing"
)

func TestParseVersionResponse(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": { "body": {
			"host_name": "switch1",
			"sys_ver_str": "9.3(2)",
			"kern_uptm_days": 10,
			"kern_uptm_hrs": 5,
			"kern_uptm_mins": 30,
			"kern_uptm_secs": 15
		}}}}
	}`)

	got, err := ParseVersionResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := VersionBody{
		HostName:   "switch1",
		Version:    "9.3(2)",
		UptimeDays: 10,
		UptimeHrs:  5,
		UptimeMins: 30,
		UptimeSecs: 15,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseVersionResponse_InvalidJSON(t *testing.T) {
	_, err := ParseVersionResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestParseInventoryResponse(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": { "body": {
			"TABLE_inv": { "ROW_inv": [
				{"name": "Chassis", "productid": "DS-C9148", "serialnum": "ABC123"},
				{"name": "Fan 1", "productid": "N9K-FAN", "serialnum": "DEF456"}
			]}
		}}}}
	}`)

	got, err := ParseInventoryResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	items := got.TableInv.RowInv
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}

	want := []InventoryItem{
		{Name: "Chassis", ProductID: "DS-C9148", SerialNum: "ABC123"},
		{Name: "Fan 1", ProductID: "N9K-FAN", SerialNum: "DEF456"},
	}
	for i, w := range want {
		if items[i] != w {
			t.Errorf("item %d = %+v, want %+v", i, items[i], w)
		}
	}
}

func TestParseInventoryResponse_EmptyRows(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": { "body": {
			"TABLE_inv": { "ROW_inv": [] }
		}}}}
	}`)

	got, err := ParseInventoryResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.TableInv.RowInv) != 0 {
		t.Errorf("got %d items, want 0", len(got.TableInv.RowInv))
	}
}

func TestParseInventoryResponse_InvalidJSON(t *testing.T) {
	_, err := ParseInventoryResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestParseCLIASCIIResponse(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": {
			"body": "some log file content",
			"code": "200",
			"msg": "Success",
			"input": "show logging logfile"
		}}}
	}`)

	got, err := ParseCLIASCIIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "some log file content" {
		t.Errorf("got %q, want %q", got, "some log file content")
	}
}

func TestParseCLIASCIIResponse_EmptyBody(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": {
			"body": "",
			"code": "200",
			"msg": "Success"
		}}}
	}`)

	got, err := ParseCLIASCIIResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want an empty body", got)
	}
}

func TestParseCLIASCIIResponse_CommandError(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": {
			"code": "400",
			"msg": "CLI execution error",
			"clierror": "Error: This command does not support XML output."
		}}}
	}`)

	_, err := ParseCLIASCIIResponse(input)
	if err == nil {
		t.Fatal("expected an error for a failed NX-API command, got nil")
	}
	for _, want := range []string{"400", "CLI execution error", "does not support XML output"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestParseCLIASCIIResponse_StructuredOutputUnsupported(t *testing.T) {
	input := []byte(`{
		"ins_api": { "outputs": { "output": {
			"code": "501",
			"msg": "Structured output unsupported",
			"clierror": "legacy log content"
		}}}
	}`)

	_, err := ParseCLIASCIIResponse(input)
	if err == nil {
		t.Fatal("expected an error for a failed NX-API command, got nil")
	}
	for _, want := range []string{"501", "Structured output unsupported", "legacy log content"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestParseCLIASCIIResponse_InvalidJSON(t *testing.T) {
	_, err := ParseCLIASCIIResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}
