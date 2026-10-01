package proxy

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// Check the bytes received by each API's upstream and the restored JSON/SSE reply.
func TestRedactionGapsRoundTrip(t *testing.T) {
	text := jsonString("data: alice@example.com PASSWORD=foo.example.com/swordfish\nThe credential is foo.example.com/swordfish")
	args := `{"password":"apricot42","token":"abc"}`
	for _, tc := range []struct {
		name, path, body string
	}{
		{"anthropic", "/anthropic/v1/messages", `{"stream":%t,"messages":[{"role":"user","content":` + text + `},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"login","input":` + args + `}]}]}`},
		{"chat", "/openai/v1/chat/completions", `{"stream":%t,"messages":[{"role":"user","content":` + text + `},{"role":"assistant","tool_calls":[{"id":"t1","type":"function","function":{"name":"login","arguments":` + jsonString(args) + `}}]}]}`},
		{"responses", "/openai/v1/responses", `{"stream":%t,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":` + text + `}]},{"type":"function_call","call_id":"t1","name":"login","arguments":` + jsonString(args) + `}]}`},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				var base string
				var recorded func() []call
				if tc.name == "anthropic" {
					fu, px := setup(t, "")
					base, recorded = px.URL, fu.recorded
				} else {
					e := setupOpenAI(t, "")
					base, recorded = e.px.URL, e.fu.recorded
				}
				resp := post(t, base+"/"+testToken+tc.path, fmt.Sprintf(tc.body, stream), nil)
				body, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("response status=%d body=%s error=%v", resp.StatusCode, body, err)
				}
				calls := recorded()
				if len(calls) != 1 {
					t.Fatalf("upstream calls=%d, want 1", len(calls))
				}
				for _, value := range []string{"alice@example.com", "foo.example.com/swordfish", "apricot42", "abc"} {
					if strings.Contains(calls[0].body, value) {
						t.Errorf("upstream received %q: %s", value, calls[0].body)
					}
					if !strings.Contains(string(body), value) {
						t.Errorf("client did not get %q back: %s", value, body)
					}
				}
				if strings.Contains(calls[0].body, "swordfish") || strings.Contains(string(body), "[REDACTED_") {
					t.Errorf("partial redaction or incomplete restoration: upstream=%s client=%s", calls[0].body, body)
				}
			})
		}
	}
}
