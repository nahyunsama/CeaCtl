package config_load

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlyDeviceName_SingleMatch(t *testing.T) {
	devices := map[string]Device{
		"switch1": {Type: "mds"},
		"ucsm1":   {Type: "ucsm"},
	}

	got, err := onlyDeviceName(devices, "mds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "switch1" {
		t.Errorf("got %q, want %q", got, "switch1")
	}
}

func TestOnlyDeviceName_CaseInsensitiveType(t *testing.T) {
	devices := map[string]Device{
		"switch1": {Type: "MDS"},
	}

	got, err := onlyDeviceName(devices, "mds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "switch1" {
		t.Errorf("got %q, want %q", got, "switch1")
	}
}

func TestOnlyDeviceName_NoMatch(t *testing.T) {
	devices := map[string]Device{
		"ucsm1": {Type: "ucsm"},
	}

	_, err := onlyDeviceName(devices, "mds")
	if err == nil {
		t.Fatal("expected an error when no device matches the type, got nil")
	}
}

func TestOnlyDeviceName_MultipleMatches(t *testing.T) {
	devices := map[string]Device{
		"switch-b": {Type: "mds"},
		"switch-a": {Type: "mds"},
	}

	_, err := onlyDeviceName(devices, "mds")
	if err == nil {
		t.Fatal("expected an error when multiple devices match the type, got nil")
	}
	if !strings.Contains(err.Error(), "switch-a, switch-b") {
		t.Errorf("error %q does not contain sorted device names %q", err.Error(), "switch-a, switch-b")
	}
}

func TestValidateDevice_AllFieldsPresent(t *testing.T) {
	device := Device{
		Type:     "mds",
		Host:     "10.0.0.1",
		Port:     "443",
		Username: "admin",
		Password: "secret",
	}

	if err := validateDevice("switch1", device); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateDevice_MissingFields(t *testing.T) {
	device := Device{
		Type: "mds",
		Host: "10.0.0.1",
	}

	err := validateDevice("switch1", device)
	if err == nil {
		t.Fatal("expected an error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "port, username, password") {
		t.Errorf("error %q does not list missing fields in expected order", err.Error())
	}
}

func TestValidateDevice_MissingSingleField(t *testing.T) {
	device := Device{
		Type:     "mds",
		Host:     "10.0.0.1",
		Port:     "443",
		Username: "admin",
	}

	err := validateDevice("switch1", device)
	if err == nil {
		t.Fatal("expected an error for missing password, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error %q does not mention the missing password field", err.Error())
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	return path
}

func TestLoadFile_ValidConfig(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  switch1:
    type: mds
    host: 10.0.0.1
    port: "443"
    username: admin
    password: secret
`)

	got, err := LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	device, ok := got.Devices["switch1"]
	if !ok {
		t.Fatalf("got devices %+v, want a \"switch1\" entry", got.Devices)
	}
	if device.Type != "mds" || device.Host != "10.0.0.1" || device.Port != "443" ||
		device.Username != "admin" || device.Password != "secret" {
		t.Errorf("got %+v, unexpected field values", device)
	}
}

func TestLoadFile_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.yaml")

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
	if !strings.Contains(err.Error(), "Load config") {
		t.Errorf("error %q does not mention the load failure", err.Error())
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "devices: [this is not valid yaml for a map")

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected an error for malformed yaml, got nil")
	}
	if !strings.Contains(err.Error(), "Parse config") {
		t.Errorf("error %q does not mention the parse failure", err.Error())
	}
}

func TestLoadFile_NoDevices(t *testing.T) {
	path := writeTempConfig(t, `
devices: {}
`)

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected an error when no devices are defined, got nil")
	}
	if !strings.Contains(err.Error(), "must define at least one device") {
		t.Errorf("error %q does not mention the missing devices requirement", err.Error())
	}
}

func TestLoadDevice_AutoSelectsSingleMatch(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  switch1:
    type: mds
    host: 10.0.0.1
    port: "443"
    username: admin
    password: secret
  ucsm1:
    type: ucsm
    host: 10.0.0.2
    port: "443"
    username: admin
    password: secret
`)

	got, err := LoadDevice(path, "", "mds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Host != "10.0.0.1" {
		t.Errorf("got host %q, want 10.0.0.1 (should auto-select switch1)", got.Host)
	}
}

func TestLoadDevice_AutoSelectFailsWhenNoMatch(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  ucsm1:
    type: ucsm
    host: 10.0.0.2
    port: "443"
    username: admin
    password: secret
`)

	_, err := LoadDevice(path, "", "mds")
	if err == nil {
		t.Fatal("expected an error when no device matches the type, got nil")
	}
}

func TestLoadDevice_AutoSelectFailsWhenAmbiguous(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  switch-a:
    type: mds
    host: 10.0.0.1
    port: "443"
    username: admin
    password: secret
  switch-b:
    type: mds
    host: 10.0.0.3
    port: "443"
    username: admin
    password: secret
`)

	_, err := LoadDevice(path, "", "mds")
	if err == nil {
		t.Fatal("expected an error when multiple devices match the type, got nil")
	}
}

func TestLoadDevice_NameNotFound(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  switch1:
    type: mds
    host: 10.0.0.1
    port: "443"
    username: admin
    password: secret
`)

	_, err := LoadDevice(path, "does-not-exist", "mds")
	if err == nil {
		t.Fatal("expected an error for an unknown device name, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not mention the device is missing", err.Error())
	}
}

func TestLoadDevice_TypeMismatch(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  switch1:
    type: ucsm
    host: 10.0.0.1
    port: "443"
    username: admin
    password: secret
`)

	_, err := LoadDevice(path, "switch1", "mds")
	if err == nil {
		t.Fatal("expected an error for a device type mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "is type") {
		t.Errorf("error %q does not mention the type mismatch", err.Error())
	}
}

func TestLoadDevice_MissingRequiredFields(t *testing.T) {
	path := writeTempConfig(t, `
devices:
  switch1:
    type: mds
    host: 10.0.0.1
    port: "443"
    username: admin
`)

	_, err := LoadDevice(path, "switch1", "mds")
	if err == nil {
		t.Fatal("expected an error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "missing required fields") {
		t.Errorf("error %q does not mention the missing fields", err.Error())
	}
}
