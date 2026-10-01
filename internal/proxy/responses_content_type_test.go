package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"nospyai/internal/payload"
	"nospyai/internal/redact"
)

func TestResponsesStreamWithoutContentType(t *testing.T) {
	const stream = "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"[REDACTED_EMAIL_\"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"1]\"}\n\n"
	for _, tc := range []struct {
		name, contentType, body string
		restored                bool
	}{
		{"missing", "", stream, true},
		{"explicit SSE", "text/event-stream", stream, true},
		{"explicit other type", "text/plain", stream, false},
		{"short unrelated body", "", "ok", false},
		{"unrelated event", "", "event: other\ndata: [REDACTED_EMAIL_1]\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vault := redact.NewVault()
			red := redact.NewRedactor(redact.NewDetector(redact.Config{}), vault)
			red.Scan("canary@example.com")
			red.Rewrite("canary@example.com")
			st := &reqState{dialect: payload.OpenAIResponses, vault: vault}
			req := (&http.Request{}).WithContext(context.WithValue(context.Background(), ctxKey{}, st))
			resp := &http.Response{Request: req, StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(tc.body)), ContentLength: int64(len(tc.body))}
			if tc.contentType != "" {
				resp.Header.Set("Content-Type", tc.contentType)
			}
			if err := modifyResponse(resp); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.restored {
				if !strings.Contains(string(body), "canary@example.com") || strings.Contains(string(body), "[REDACTED_EMAIL_") {
					t.Fatalf("reply not restored: %s", body)
				}
				if resp.Header.Get("Content-Type") != "text/event-stream" {
					t.Fatal("stream content type missing")
				}
			} else if string(body) != tc.body {
				t.Fatalf("unrelated response changed: %s", body)
			}
		})
	}
}
