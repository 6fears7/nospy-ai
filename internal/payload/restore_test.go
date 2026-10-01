package payload

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"nospyai/internal/redact"
)

func restoreVault() *redact.Vault {
	v := redact.NewVault()
	v.Placeholder(redact.KindEmail, "alice@corp.io")          // [REDACTED_EMAIL_1]
	v.Placeholder(redact.KindPassword, `pa"ss\word`)          // [REDACTED_PASSWORD_1]
	v.Placeholder(redact.KindIPv4, "10.0.0.5")                // [REDACTED_IPV4_1]
	v.Placeholder(redact.KindPrivateKey, "-----BEGIN X-----") // [REDACTED_PRIVATE_KEY_1]
	return v
}

func TestRestoreResponseJSON(t *testing.T) {
	body := `{"id":"msg_1","type":"message","role":"assistant","content":[
	  {"type":"thinking","thinking":"keep [REDACTED_EMAIL_1] as is","signature":"sig"},
	  {"type":"text","text":"Mail [REDACTED_EMAIL_1] now"},
	  {"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ssh [REDACTED_IPV4_1] -p [REDACTED_PASSWORD_1]"}}]}`
	out, err := RestoreResponse(Anthropic, []byte(body), restoreVault())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Content []map[string]any `json:"content"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Content[0]["thinking"] != "keep [REDACTED_EMAIL_1] as is" {
		t.Errorf("thinking modified: %v", got.Content[0]["thinking"])
	}
	if got.Content[1]["text"] != "Mail alice@corp.io now" {
		t.Errorf("text = %v", got.Content[1]["text"])
	}
	if cmd := got.Content[2]["input"].(map[string]any)["command"]; cmd != `ssh 10.0.0.5 -p pa"ss\word` {
		t.Errorf("tool input = %v", cmd)
	}
}

func TestRestoreResponseNoPlaceholderIsUntouched(t *testing.T) {
	body := []byte(`{"b":1,  "a":"x"}`)
	out, err := RestoreResponse(Anthropic, body, restoreVault())
	if err != nil || string(out) != string(body) {
		t.Fatalf("got %s, %v", out, err)
	}
}

func sse(events ...string) string {
	return strings.Join(events, "\n\n") + "\n\n"
}

func delta(idx int, dt, field, text string) string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": dt, field: text}})
	return "event: content_block_delta\ndata: " + string(b)
}

const thinkingDelta = `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm [REDACTED_EMAIL_1]"}}`

func runSSE(t *testing.T, in string) string {
	t.Helper()
	out, err := io.ReadAll(NewSSERestorer(Anthropic, io.NopCloser(strings.NewReader(in)), restoreVault()))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// collect reassembles every delta of the given type, per index, from an SSE stream.
func collect(t *testing.T, stream, dt, field string) map[float64]string {
	t.Helper()
	out := map[float64]string{}
	for _, ev := range strings.Split(stream, "\n\n") {
		for _, line := range strings.Split(ev, "\n") {
			data, ok := strings.CutPrefix(line, "data: ")
			if !ok {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(data), &m); err != nil {
				t.Fatalf("bad data line %q: %v", data, err)
			}
			if d, ok := m["delta"].(map[string]any); ok && d["type"] == dt {
				out[m["index"].(float64)] += d[field].(string)
			}
		}
	}
	return out
}

func TestSSERestoreSplitPlaceholders(t *testing.T) {
	in := sse(
		`event: message_start
data: {"type":"message_start","message":{"id":"msg_1","content":[]}}`,
		`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		thinkingDelta,
		`event: content_block_stop
data: {"type":"content_block_stop","index":0}`,
		`event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		delta(1, "text_delta", "text", "Mail [REDACT"),
		delta(1, "text_delta", "text", "ED_EMA"),
		delta(1, "text_delta", "text", "IL_1] soon ["),
		`event: content_block_stop
data: {"type":"content_block_stop","index":1}`,
		`event: content_block_start
data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`,
		delta(2, "input_json_delta", "partial_json", `{"command": "login [REDACTED_PASS`),
		delta(2, "input_json_delta", "partial_json", `WORD_1] at [REDACTED_IPV4_1`),
		delta(2, "input_json_delta", "partial_json", `]"}`),
		`event: content_block_stop
data: {"type":"content_block_stop","index":2}`,
		"event: ping\ndata: {\"type\": \"ping\"}",
		`event: message_stop
data: {"type":"message_stop"}`,
	)
	out := runSSE(t, in)

	if text := collect(t, out, "text_delta", "text")[1]; text != "Mail alice@corp.io soon [" {
		t.Errorf("text = %q", text)
	}
	var input map[string]string
	args := collect(t, out, "input_json_delta", "partial_json")[2]
	if err := json.Unmarshal([]byte(args), &input); err != nil {
		t.Fatalf("tool input %q is not JSON: %v", args, err)
	}
	if input["command"] != `login pa"ss\word at 10.0.0.5` {
		t.Errorf("command = %q", input["command"])
	}
	if !strings.Contains(out, thinkingDelta+"\n\n") {
		t.Errorf("thinking delta not byte-identical:\n%s", out)
	}
	if !strings.Contains(out, "event: ping\ndata: {\"type\": \"ping\"}\n\n") {
		t.Errorf("unchanged event was re-encoded")
	}
	// the held-back "[" must be emitted before its block's stop event
	stop := strings.Index(out, `"type":"content_block_stop","index":1`)
	if last := strings.LastIndex(out[:stop], `"text":"["`); last < 0 {
		t.Errorf("held-back text not flushed before content_block_stop:\n%s", out)
	}
}

func TestSSEFlushOnTruncatedStream(t *testing.T) {
	out := runSSE(t, sse(delta(0, "text_delta", "text", "cut [REDACTED_EMAIL_1")))
	if text := collect(t, out, "text_delta", "text")[0]; text != "cut [REDACTED_EMAIL_1" {
		t.Errorf("text = %q", text)
	}
}

func TestSSECRLFAndNoTrailingBlank(t *testing.T) {
	in := "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi [REDACTED_EMAIL_1]\"}}"
	if text := collect(t, runSSE(t, in), "text_delta", "text")[0]; text != "hi alice@corp.io" {
		t.Errorf("text = %q", text)
	}
}
