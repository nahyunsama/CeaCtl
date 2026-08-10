package transceiver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendRequest_Success(t *testing.T) {
	var gotMethod, gotContentType, gotAuth string
	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ins_api":{"outputs":{"output":{"body":{}}}}}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:  server.URL,
		HTTP:     server.Client(),
		Username: "admin",
		Password: "secret",
	}

	got, err := client.SendRequest(context.Background(), []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(got) != `{"ins_api":{"outputs":{"output":{"body":{}}}}}` {
		t.Errorf("got body %q, unexpected", got)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("got method %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("got Content-Type %q, want application/json", gotContentType)
	}

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	if gotAuth != wantAuth {
		t.Errorf("got Authorization %q, want %q", gotAuth, wantAuth)
	}
	if string(gotBody) != `{"hello":"world"}` {
		t.Errorf("server received body %q, want %q", gotBody, `{"hello":"world"}`)
	}
}

func TestSendRequest_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTP: server.Client()}

	_, err := client.SendRequest(context.Background(), []byte(`{}`))
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

func TestFormatNXAPIResponseSummary(t *testing.T) {
	body := []byte(`{
		"ins_api": {
			"type": "cli_show_ascii",
			"outputs": {
				"output": {
					"code": "501",
					"msg": "Structured output unsupported",
					"body": "content that must not be printed",
					"clierror": "error content that must not be printed"
				}
			}
		}
	}`)

	got := formatNXAPIResponseSummary(http.StatusOK, body)
	want := fmt.Sprintf(
		`[verbose] received response: HTTP 200, type=cli_show_ascii, code=501, msg="Structured output unsupported", bytes=%d`,
		len(body),
	)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, sensitive := range []string{"content that must not be printed", "error content that must not be printed"} {
		if strings.Contains(got, sensitive) {
			t.Errorf("summary %q includes response content %q", got, sensitive)
		}
	}
}

func TestFormatNXAPIResponseSummary_NumericCode(t *testing.T) {
	body := []byte(`{"ins_api":{"type":"cli_show","outputs":{"output":{"code":200,"msg":"Success"}}}}`)

	got := formatNXAPIResponseSummary(http.StatusOK, body)
	if !strings.Contains(got, `code=200, msg="Success"`) {
		t.Errorf("summary %q does not include the numeric code and message", got)
	}
}

func TestFormatNXAPIResponseSummary_NonJSON(t *testing.T) {
	body := []byte(`service unavailable`)

	got := formatNXAPIResponseSummary(http.StatusServiceUnavailable, body)
	want := fmt.Sprintf(`[verbose] received response: HTTP 503, bytes=%d`, len(body))
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCLIShow_SendsExpectedPayload(t *testing.T) {
	var got nxapiRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ins_api":{"outputs":{"output":{"body":{}}}}}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTP: server.Client()}

	if _, err := client.CLIShow(context.Background(), "show version"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.InsAPI.Version != "1.0" {
		t.Errorf("got version %q, want 1.0", got.InsAPI.Version)
	}
	if got.InsAPI.Type != "cli_show" {
		t.Errorf("got type %q, want cli_show", got.InsAPI.Type)
	}
	if got.InsAPI.Chunk != "0" {
		t.Errorf("got chunk %q, want 0", got.InsAPI.Chunk)
	}
	if got.InsAPI.Sid != "1" {
		t.Errorf("got sid %q, want 1", got.InsAPI.Sid)
	}
	if got.InsAPI.Input != "show version" {
		t.Errorf("got input %q, want %q", got.InsAPI.Input, "show version")
	}
	if got.InsAPI.OutputFormat != "json" {
		t.Errorf("got output_format %q, want json", got.InsAPI.OutputFormat)
	}
}

func TestCLIShowASCII_SendsExpectedPayload(t *testing.T) {
	var got nxapiRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ins_api":{"outputs":{"output":{"body":"log content"}}}}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTP: server.Client()}

	if _, err := client.CLIShowASCII(context.Background(), "show logging logfile"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.InsAPI.Version != "1.0" {
		t.Errorf("got version %q, want 1.0", got.InsAPI.Version)
	}
	if got.InsAPI.Type != "cli_show_ascii" {
		t.Errorf("got type %q, want cli_show_ascii", got.InsAPI.Type)
	}
	if got.InsAPI.Chunk != "0" {
		t.Errorf("got chunk %q, want 0", got.InsAPI.Chunk)
	}
	if got.InsAPI.Sid != "1" {
		t.Errorf("got sid %q, want 1", got.InsAPI.Sid)
	}
	if got.InsAPI.Input != "show logging logfile" {
		t.Errorf("got input %q, want %q", got.InsAPI.Input, "show logging logfile")
	}
	if got.InsAPI.OutputFormat != "json" {
		t.Errorf("got output_format %q, want json", got.InsAPI.OutputFormat)
	}
}

func TestCLIShow_PropagatesSendRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTP: server.Client()}

	_, err := client.CLIShow(context.Background(), "show version")
	if err == nil {
		t.Fatal("expected an error when the server returns a non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention status code 500", err.Error())
	}
}
