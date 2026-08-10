package transceiver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type nxapiRequest struct {
	InsAPI struct {
		Version      string `json:"version"`
		Type         string `json:"type"`
		Chunk        string `json:"chunk"`
		Sid          string `json:"sid"`
		Input        string `json:"input"`
		OutputFormat string `json:"output_format"`
	} `json:"ins_api"`
}

type nxapiResponseMetadata struct {
	InsAPI struct {
		Type    string `json:"type"`
		Outputs struct {
			Output struct {
				Code    json.RawMessage `json:"code"`
				Message string          `json:"msg"`
			} `json:"output"`
		} `json:"outputs"`
	} `json:"ins_api"`
}

func (c *Client) CLIShow(ctx context.Context, input string) ([]byte, error) {
	return c.cliShow(ctx, input, "cli_show")
}

func (c *Client) CLIShowASCII(ctx context.Context, input string) ([]byte, error) {
	return c.cliShow(ctx, input, "cli_show_ascii")
}

func (c *Client) cliShow(ctx context.Context, input, requestType string) ([]byte, error) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] running command: %s\n", input)
	}

	var req nxapiRequest
	req.InsAPI.Version = "1.0"
	req.InsAPI.Type = requestType
	req.InsAPI.Chunk = "0"
	req.InsAPI.Sid = "1"
	req.InsAPI.Input = input
	req.InsAPI.OutputFormat = "json"

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to build nx-api request: %w", err)
	}

	return c.SendRequest(ctx, payload)
}

func (c *Client) SendRequest(ctx context.Context, payload []byte) ([]byte, error) {

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] sending request: %s %s\n", req.Method, c.BaseURL)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if c.Verbose {
		fmt.Fprintln(os.Stderr, formatNXAPIResponseSummary(resp.StatusCode, body))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func formatNXAPIResponseSummary(httpStatus int, body []byte) string {
	summary := fmt.Sprintf("[verbose] received response: HTTP %d", httpStatus)

	var metadata nxapiResponseMetadata
	if err := json.Unmarshal(body, &metadata); err == nil {
		output := metadata.InsAPI.Outputs.Output
		if metadata.InsAPI.Type != "" {
			summary += fmt.Sprintf(", type=%s", metadata.InsAPI.Type)
		}
		if code := formatJSONScalar(output.Code); code != "" {
			summary += fmt.Sprintf(", code=%s", code)
		}
		if output.Message != "" {
			summary += fmt.Sprintf(", msg=%q", output.Message)
		}
	}

	return fmt.Sprintf("%s, bytes=%d", summary, len(body))
}

func formatJSONScalar(value json.RawMessage) string {
	if len(value) == 0 {
		return ""
	}

	var stringValue string
	if err := json.Unmarshal(value, &stringValue); err == nil {
		return stringValue
	}

	return string(bytes.TrimSpace(value))
}
