package llmanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChat_SendsExpectedPayload(t *testing.T) {
	var gotPath, gotContentType string
	var got chatRequest
	var gotJSON map[string]json.RawMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if err := json.Unmarshal(body, &gotJSON); err != nil {
			t.Fatalf("failed to inspect request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":{"role":"assistant","content":"hello back"}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma4:e2b")
	client.HTTP = server.Client()

	gotReply, err := client.Chat(context.Background(), "sys prompt", "user prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotReply != "hello back" {
		t.Errorf("got reply %q, want %q", gotReply, "hello back")
	}
	if gotPath != "/api/chat" {
		t.Errorf("got path %q, want /api/chat", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("got Content-Type %q, want application/json", gotContentType)
	}
	if got.Model != "gemma4:e2b" {
		t.Errorf("got model %q, want gemma4:e2b", got.Model)
	}
	if got.Stream {
		t.Errorf("got stream=true, want false")
	}
	if got.Think {
		t.Errorf("got think=true, want false")
	}
	if rawThink, ok := gotJSON["think"]; !ok {
		t.Error("request body does not contain think")
	} else if string(rawThink) != "false" {
		t.Errorf("got raw think value %s, want false", rawThink)
	}
	if got.Options.NumCtx != defaultNumCtx {
		t.Errorf("got num_ctx %d, want %d", got.Options.NumCtx, defaultNumCtx)
	}
	if got.Options.Temperature != defaultTemperature {
		t.Errorf("got temperature %v, want %v", got.Options.Temperature, defaultTemperature)
	}
	if len(got.Messages) != 2 || got.Messages[0].Role != "system" || got.Messages[0].Content != "sys prompt" {
		t.Errorf("got messages[0] = %+v, want system/sys prompt", got.Messages[0])
	}
	if len(got.Messages) != 2 || got.Messages[1].Role != "user" || got.Messages[1].Content != "user prompt" {
		t.Errorf("got messages[1] = %+v, want user/user prompt", got.Messages[1])
	}
}

func TestChat_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma4:e2b")
	client.HTTP = server.Client()

	_, err := client.Chat(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected an error for non-200 status code, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention status code 500", err.Error())
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error %q does not include response body", err.Error())
	}
}

func TestChat_UnreachableServer(t *testing.T) {
	client := NewClient("http://127.0.0.1:0", "gemma4:e2b")

	_, err := client.Chat(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected an error when the server is unreachable, got nil")
	}
}

func TestChatDetailed_PreservesCompleteAPIResponse(t *testing.T) {
	const response = `{"model":"gemma4:e2b","created_at":"2026-07-28T01:02:03Z","message":{"role":"assistant","content":"analysis"},"done":true,"done_reason":"stop","total_duration":420000000000,"load_duration":1000000000,"prompt_eval_count":1200,"prompt_eval_duration":300000000000,"eval_count":300,"eval_duration":119000000000}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma4:e2b")
	client.HTTP = server.Client()

	result, err := client.ChatDetailed(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Content != "analysis" {
		t.Errorf("got content %q, want %q", result.Content, "analysis")
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", result.StatusCode, http.StatusOK)
	}
	if string(result.RawResponse) != response {
		t.Errorf("raw response was changed:\ngot  %s\nwant %s", result.RawResponse, response)
	}

	var verbose bytes.Buffer
	if err := result.WriteVerbose(&verbose); err != nil {
		t.Fatalf("failed to write verbose response: %v", err)
	}
	for _, want := range []string{
		"[verbose] Ollama API response (HTTP 200):",
		`"total_duration": 420000000000`,
		`"load_duration": 1000000000`,
		`"prompt_eval_count": 1200`,
		`"prompt_eval_duration": 300000000000`,
		`"eval_count": 300`,
		`"eval_duration": 119000000000`,
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose output does not contain %q:\n%s", want, verbose.String())
		}
	}
}

func TestChatDetailed_PreservesErrorResponse(t *testing.T) {
	const response = `{"error":"model runner failed","detail":{"duration":123}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := NewClient(server.URL, "gemma4:e2b")
	client.HTTP = server.Client()

	result, err := client.ChatDetailed(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected an error for non-200 status code, got nil")
	}
	if result.StatusCode != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", result.StatusCode, http.StatusInternalServerError)
	}
	if string(result.RawResponse) != response {
		t.Errorf("got raw response %q, want %q", result.RawResponse, response)
	}
}

func TestChatResultAnalysis_ReturnsOnlyAssistantContent(t *testing.T) {
	result := ChatResult{
		Content:     "analysis only",
		StatusCode:  http.StatusOK,
		RawResponse: []byte(`{"message":{"content":"analysis only"},"eval_count":42}`),
	}

	got := result.Analysis()
	if got != "analysis only" {
		t.Fatalf("got %q, want %q", got, "analysis only")
	}
	if strings.Contains(got, "eval_count") {
		t.Fatalf("analysis contains Ollama response metadata: %q", got)
	}
}
