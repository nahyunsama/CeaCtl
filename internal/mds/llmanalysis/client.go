package llmanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultNumCtx      = 128000
	defaultTemperature = 0
)

type Client struct {
	Endpoint    string
	Model       string
	NumCtx      int
	Temperature float64
	HTTP        *http.Client
}

func NewClient(endpoint, model string) *Client {
	return &Client{
		Endpoint:    endpoint,
		Model:       model,
		NumCtx:      defaultNumCtx,
		Temperature: defaultTemperature,
		HTTP: &http.Client{
			Timeout: 600 * time.Second,
		},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	Options  chatOptions   `json:"options"`
}

type chatOptions struct {
	NumCtx      int     `json:"num_ctx"`
	Temperature float64 `json:"temperature"`
}

type chatResponse struct {
	Message chatMessage `json:"message"`
}

func (c *Client) Chat(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	result, err := c.ChatDetailed(ctx, systemPrompt, userPrompt)
	return result.Content, err
}

// ChatResult retains Ollama's complete response for benchmark inspection.
type ChatResult struct {
	Content     string
	StatusCode  int
	RawResponse []byte
}

// WriteVerbose preserves all JSON values while making the response readable.
func (r ChatResult) WriteVerbose(w io.Writer) error {
	if len(r.RawResponse) == 0 {
		return nil
	}

	var formatted bytes.Buffer
	if err := json.Indent(&formatted, r.RawResponse, "", "  "); err != nil {
		formatted.Reset()
		formatted.Write(r.RawResponse)
	}

	_, err := fmt.Fprintf(
		w,
		"[verbose] Ollama API response (HTTP %d):\n%s\n",
		r.StatusCode,
		formatted.Bytes(),
	)
	return err
}

// ChatDetailed retains the response body even for non-200 responses.
func (c *Client) ChatDetailed(ctx context.Context, systemPrompt, userPrompt string) (ChatResult, error) {
	var result ChatResult

	reqBody := chatRequest{
		Model: c.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Stream:  false,
		Options: chatOptions{NumCtx: c.NumCtx, Temperature: c.Temperature},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return result, fmt.Errorf("failed to build ollama request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return result, fmt.Errorf("failed to reach ollama at %s: %w", c.Endpoint, err)
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	result.RawResponse = body

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return result, fmt.Errorf("failed to parse ollama response: %w", err)
	}

	result.Content = chatResp.Message.Content
	return result, nil
}
