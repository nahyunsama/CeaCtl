package config_load

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const DefaultPath = ".config.yaml"

type File struct {
	Devices     map[string]Device `yaml:"devices"`
	LLMAnalysis LLMAnalysis       `yaml:"llm_analysis"`
}

type Device struct {
	Type        string `yaml:"type"`
	Host        string `yaml:"host"`
	Port        string `yaml:"port"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	InsecureTLS bool   `yaml:"insecure_tls"`
}

type LLMAnalysis struct {
	Enabled bool         `yaml:"enabled"`
	Backend string       `yaml:"backend"`
	Ollama  OllamaConfig `yaml:"ollama"`
	Output  OutputConfig `yaml:"output"`
}

type OllamaConfig struct {
	Endpoint string `yaml:"endpoint"`
	Model    string `yaml:"model"`
}

type OutputConfig struct {
	Translate  bool   `yaml:"translate"`
	TargetLang string `yaml:"target_lang"`
}

func LoadDevice(path, name, deviceType string) (Device, error) {
	if path == "" {
		path = DefaultPath
	}

	cfg, err := LoadFile(path)
	if err != nil {
		return Device{}, err
	}

	if name == "" {
		name, err = onlyDeviceName(cfg.Devices, deviceType)
		if err != nil {
			return Device{}, err
		}
	}

	device, ok := cfg.Devices[name]
	if !ok {
		return Device{}, fmt.Errorf("device %q not found in %s", name, path)
	}

	if !strings.EqualFold(device.Type, deviceType) {
		return Device{}, fmt.Errorf("device %q is type %q, want %q", name, device.Type, deviceType)
	}

	if err := validateDevice(name, device); err != nil {
		return Device{}, err
	}

	return device, nil
}

func LoadFile(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("Load config %s: %w", path, err)
	}

	var cfg File
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return File{}, fmt.Errorf("Parse config %s: %w", path, err)
	}

	if len(cfg.Devices) == 0 {
		return File{}, fmt.Errorf("config %s: must define at least one device", path)
	}

	cfg.LLMAnalysis.Output.TargetLang = strings.TrimSpace(
		cfg.LLMAnalysis.Output.TargetLang,
	)
	if cfg.LLMAnalysis.Output.Translate &&
		cfg.LLMAnalysis.Output.TargetLang == "" {
		return File{}, fmt.Errorf(
			"config %s: llm_analysis.output.target_lang is required "+
				"when llm_analysis.output.translate is true",
			path,
		)
	}

	return cfg, nil
}

func onlyDeviceName(devices map[string]Device, deviceType string) (string, error) {
	var names []string
	for name, device := range devices {
		if strings.EqualFold(device.Type, deviceType) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	switch len(names) {
	case 0:
		return "", fmt.Errorf("no %q devices configured", deviceType)
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("multiple %q devices configured; choose one with --device (%s)", deviceType, strings.Join(names, ", "))
	}
}

func validateDevice(name string, device Device) error {
	var missing []string

	if device.Type == "" {
		missing = append(missing, "type")
	}
	if device.Host == "" {
		missing = append(missing, "host")
	}
	if device.Port == "" {
		missing = append(missing, "port")
	}
	if device.Username == "" {
		missing = append(missing, "username")
	}
	if device.Password == "" {
		missing = append(missing, "password")
	}

	if len(missing) > 0 {
		return fmt.Errorf("device %q is missing required fields: %s", name, strings.Join(missing, ", "))
	}

	return nil
}
