package payload

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"nospyai/internal/redact"
)

const (
	pngDataURL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
	audioB64   = "UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA="
	sig        = "gAAAAABk_encrypted_reasoning_blob_with_a@b.com_inside"
)

// An IP whose surrounding JSON value contains quotes, in a tool-call arguments string.
const chatArgs = `{"cmd":"echo \"hi\" && ssh root@10.0.0.5","name":"carol@corp.io","nested":{"host":"10.0.0.6"}}`

func chatRequest() string {
	args, _ := json.Marshal(chatArgs)
	return `{
  "model": "gpt-5",
  "user": "dave@corp.io",
  "tools": [{"type":"function","function":{"name":"run","description":"runs on 10.9.9.9",
    "parameters":{"type":"object","properties":{"cmd":{"type":"string","pattern":"^ssh 10\\.0\\.0\\.5$"}}}}}],
  "messages": [
    {"role":"system","content":"Deploy host is build.corp.io"},
    {"role":"user","content":"my email is alice@corp.io"},
    {"role":"user","content":[
      {"type":"text","text":"and bob@corp.io"},
      {"type":"image_url","image_url":{"url":"` + pngDataURL + `"}},
      {"type":"input_audio","input_audio":{"data":"` + audioB64 + `","format":"wav"}}]},
    {"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"run","arguments":` + string(args) + `}}]},
    {"role":"tool","tool_call_id":"call_1","content":"db_url: x\npassword=hunter22\n"}
  ]}`
}

func responsesRequest() string {
	args, _ := json.Marshal(chatArgs)
	return `{
  "model": "gpt-5",
  "user": "dave@corp.io",
  "previous_response_id": "resp_prev",
  "instructions": "Deploy host is build.corp.io",
  "tools": [{"type":"function","name":"run","description":"runs on 10.9.9.9",
    "parameters":{"type":"object","properties":{"cmd":{"type":"string","pattern":"^ssh 10\\.0\\.0\\.5$"}}}}],
  "text": {"format": {"type":"json_schema","name":"out","schema":{"type":"object","pattern":"^10\\.1\\.1\\.1$"}}},
  "input": [
    {"type":"message","role":"user","content":[
      {"type":"input_text","text":"my email is alice@corp.io"},
      {"type":"input_image","image_url":"` + pngDataURL + `"}]},
    {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"` + sig + `"},
    {"type":"function_call","call_id":"call_1","name":"run","arguments":` + string(args) + `},
    {"type":"function_call_output","call_id":"call_1","output":"db_url: x\npassword=hunter22\n"}
  ]}`
}

func redactWith(t *testing.T, d Dialect, body string) (string, *redact.Vault) {
	t.Helper()
	v := redact.NewVault()
	out, _, err := RedactRequest(d, []byte(body), redact.NewRedactor(testDet, v))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), v
}

// toolArguments pulls every "arguments" string out of a request or response body.
func toolArguments(t *testing.T, body string) []string {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, body)
	}
	var out []string
	var rec func(any)
	rec = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if s, ok := c.(string); ok && k == "arguments" {
					out = append(out, s)
				} else {
					rec(c)
				}
			}
		case []any:
			for _, c := range x {
				rec(c)
			}
		}
	}
	rec(doc)
	return out
}

func TestRedactRequestOpenAI(t *testing.T) {
	cases := []struct {
		name   string
		d      Dialect
		body   string
		keep   []string
		counts map[string]int
	}{
		{"chat", OpenAIChat, chatRequest(), []string{
			pngDataURL, audioB64, `"format":"wav"`, `"tool_call_id":"call_1"`, `"id":"call_1"`, `"model":"gpt-5"`,
			`"pattern":"^ssh 10\\.0\\.0\\.5$"`, // tool parameter schema untouched
		}, map[string]int{redact.KindEmail: 3, redact.KindIPv4: 3}},
		{"responses", OpenAIResponses, responsesRequest(), []string{
			pngDataURL, sig, `"previous_response_id":"resp_prev"`, `"call_id":"call_1"`, `"id":"rs_1"`,
			`"pattern":"^ssh 10\\.0\\.0\\.5$"`, `"pattern":"^10\\.1\\.1\\.1$"`, // tool schema, text.format.schema
		}, map[string]int{redact.KindEmail: 3, redact.KindIPv4: 3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, v := redactWith(t, c.d, c.body)
			for _, secret := range []string{"alice@corp.io", "bob@corp.io", "carol@corp.io", "dave@corp.io", "hunter22",
				"build.corp.io", "10.9.9.9", "10.0.0.5\\\"", "10.0.0.6", "root@10.0.0.5"} {
				if strings.Contains(out, secret) {
					t.Errorf("leaked %q", secret)
				}
			}
			for _, keep := range c.keep {
				if !strings.Contains(out, keep) {
					t.Errorf("missing %s in\n%s", keep, out)
				}
			}
			args := toolArguments(t, out)
			if len(args) != 1 {
				t.Fatalf("arguments = %q", args)
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(args[0]), &parsed); err != nil {
				t.Fatalf("redacted arguments %q is not JSON: %v", args[0], err)
			}
			if !strings.Contains(args[0], "[REDACTED_IPV4_") || !strings.Contains(args[0], "[REDACTED_EMAIL_") {
				t.Errorf("arguments not redacted: %s", args[0])
			}
			// A tool argument named "name" holding an email is still user data (invariant 6).
			if strings.Contains(args[0], "carol@corp.io") {
				t.Errorf("structural-key skip applied inside arguments: %s", args[0])
			}

			// The vault holds decoded values, so restoring the redacted body yields the
			// original arguments exactly (quotes intact) and the same document overall.
			back, err := RestoreResponse(c.d, []byte(out), v)
			if err != nil {
				t.Fatal(err)
			}
			got := toolArguments(t, string(back))
			if len(got) != 1 {
				t.Fatalf("restored arguments = %q", got)
			}
			var a, b any
			if json.Unmarshal([]byte(got[0]), &a) != nil || json.Unmarshal([]byte(chatArgs), &b) != nil {
				t.Fatalf("restored arguments not JSON: %q", got[0])
			}
			if ja, jb := mustJSON(a), mustJSON(b); ja != jb {
				t.Errorf("restored arguments = %s, want %s", ja, jb)
			}
			if strings.Contains(stripNote(string(back)), "[REDACTED_") {
				t.Errorf("placeholder left after restore:\n%s", back)
			}
		})
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Invalid JSON in arguments (a model slip) is redacted as plain text, never forwarded raw.
func TestRedactRequestOpenAIInvalidArguments(t *testing.T) {
	body := `{"messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{\"cmd\": ssh 10.0.0.5"}}]}]}`
	out, _ := redactWith(t, OpenAIChat, body)
	if strings.Contains(out, "10.0.0.5") || !strings.Contains(out, "[REDACTED_IPV4_1]") {
		t.Errorf("got %s", out)
	}
}

func TestRedactRequestOpenAIDeterministic(t *testing.T) {
	for _, c := range []struct {
		d    Dialect
		body string
	}{{OpenAIChat, chatRequest()}, {OpenAIResponses, responsesRequest()}} {
		first, _ := redactWith(t, c.d, c.body)
		for i := 0; i < 30; i++ {
			if got, _ := redactWith(t, c.d, c.body); got != first {
				t.Fatalf("%s run %d differs:\n%s\n%s", c.d.Name, i, first, got)
			}
		}
	}
}

func TestChainRef(t *testing.T) {
	for _, c := range []struct {
		d       Dialect
		body    string
		want    string
		wantErr bool
	}{
		{OpenAIResponses, `{"previous_response_id":"resp_1","input":"x"}`, "resp_1", false},
		{OpenAIResponses, `{"previous_response_id":null}`, "", false},
		{OpenAIResponses, `{"input":"x"}`, "", false},
		{OpenAIResponses, `{"previous_response_id":5}`, "", true},
		{OpenAIResponses, `{`, "", true},
		{OpenAIChat, `{"previous_response_id":"resp_1"}`, "", false}, // no chain key for Chat
	} {
		got, err := ChainRef(c.d, []byte(c.body))
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("%s %s: got %q, %v", c.d.Name, c.body, got, err)
		}
	}
}

func TestDialectNames(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{Anthropic.Name, "anthropic-messages"}, {OpenAIChat.Name, "openai-chat"}, {OpenAIResponses.Name, "openai-responses"},
	} {
		if c.got != c.want {
			t.Errorf("dialect name %q, want %q", c.got, c.want)
		}
	}
}

func TestRestoreResponseChatJSON(t *testing.T) {
	body := `{"id":"chatcmpl-1","object":"chat.completion","model":"m","choices":[
	 {"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":"Mail [REDACTED_EMAIL_1]",
	  "tool_calls":[{"id":"call_1","type":"function","function":{"name":"run",
	    "arguments":"{\"cmd\":\"login [REDACTED_PASSWORD_1] at [REDACTED_IPV4_1]\"}"}}]}}]}`
	out, err := RestoreResponse(OpenAIChat, []byte(body), restoreVault())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Choices []struct {
			Message struct {
				Content   string
				ToolCalls []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
			}
		}
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	m := got.Choices[0].Message
	if m.Content != "Mail alice@corp.io" {
		t.Errorf("content = %q", m.Content)
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(m.ToolCalls[0].Function.Arguments), &args); err != nil {
		t.Fatalf("arguments %q not JSON: %v", m.ToolCalls[0].Function.Arguments, err)
	}
	if args["cmd"] != `login pa"ss\word at 10.0.0.5` {
		t.Errorf("cmd = %q", args["cmd"])
	}
}

// --- SSE ---

func runSSEWith(t *testing.T, d Dialect, in string, onID func(string)) string {
	t.Helper()
	out, err := io.ReadAll(NewSSERestorerWith(d, io.NopCloser(strings.NewReader(in)), restoreVault(), onID))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func chatChunk(choice int, delta string, finish string) string {
	if finish == "" {
		finish = "null"
	} else {
		finish = `"` + finish + `"`
	}
	return `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":` +
		itoa(choice) + `,"delta":` + delta + `,"finish_reason":` + finish + `}]}`
}

func itoa(n int) string { return string(rune('0' + n)) }

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

// chatStreams reassembles, per choice, the content and the tool-call arguments.
func chatStreams(t *testing.T, stream string) (content map[int]string, args map[int]string) {
	t.Helper()
	content, args = map[int]string{}, map[int]string{}
	for _, ev := range strings.Split(stream, "\n\n") {
		data, ok := strings.CutPrefix(ev, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var c struct {
			Choices []struct {
				Index int
				Delta struct {
					Content   *string
					ToolCalls []struct {
						Index    int
						Function struct{ Arguments string }
					} `json:"tool_calls"`
				}
			}
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatalf("bad chunk %q: %v", data, err)
		}
		for _, ch := range c.Choices {
			if ch.Delta.Content != nil {
				content[ch.Index] += *ch.Delta.Content
			}
			for _, tc := range ch.Delta.ToolCalls {
				args[ch.Index*10+tc.Index] += tc.Function.Arguments
			}
		}
	}
	return content, args
}

func TestChatSSESplitPlaceholders(t *testing.T) {
	in := sse(
		chatChunk(0, `{"role":"assistant","content":""}`, ""),
		chatChunk(0, `{"content":"Mail [REDACT"}`, ""),
		chatChunk(0, `{"content":"ED_EMA"}`, ""),
		chatChunk(0, `{"content":"IL_1] soon ["}`, ""),
		chatChunk(0, `{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run","arguments":""}}]}`, ""),
		chatChunk(0, `{"tool_calls":[{"index":0,"function":{"arguments":`+jsonStr(`{"cmd": "login [REDACTED_PASS`)+`}}]}`, ""),
		chatChunk(0, `{"tool_calls":[{"index":0,"function":{"arguments":`+jsonStr(`WORD_1] at [REDACTED_IPV4_1`)+`}}]}`, ""),
		chatChunk(0, `{"tool_calls":[{"index":0,"function":{"arguments":`+jsonStr(`]"}`)+`}}]}`, ""),
		chatChunk(0, `{}`, "tool_calls"),
		"data: [DONE]",
	)
	out := runSSEWith(t, OpenAIChat, in, nil)
	content, args := chatStreams(t, out)
	if content[0] != "Mail alice@corp.io soon [" {
		t.Errorf("content = %q", content[0])
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(args[0]), &parsed); err != nil {
		t.Fatalf("arguments %q not JSON: %v", args[0], err)
	}
	if parsed["cmd"] != `login pa"ss\word at 10.0.0.5` {
		t.Errorf("cmd = %q", parsed["cmd"])
	}
	if !strings.HasSuffix(out, "data: [DONE]\n\n") {
		t.Errorf("[DONE] not passed through verbatim:\n%s", out)
	}
	// the held-back "[" must be emitted before the finish chunk
	if i, j := strings.LastIndex(out, `"content":"["`), strings.Index(out, `"finish_reason":"tool_calls"`); i < 0 || i > j {
		t.Errorf("held-back text not flushed before the finish chunk:\n%s", out)
	}
}

// The last chunk of a choice may carry content itself: the remainder must follow it in order.
func TestChatSSEFinishChunkWithContent(t *testing.T) {
	out := runSSEWith(t, OpenAIChat, sse(
		chatChunk(0, `{"content":"hi [REDACTED_EMAIL_1] and ["}`, ""),
		chatChunk(0, `{"content":"[REDACTED_IPV4"}`, "stop"),
		"data: [DONE]",
	), nil)
	if c, _ := chatStreams(t, out); c[0] != "hi alice@corp.io and [[REDACTED_IPV4" {
		t.Errorf("content = %q\n%s", c[0], out)
	}
}

func TestChatSSETwoChoicesDoNotCrossContaminate(t *testing.T) {
	out := runSSEWith(t, OpenAIChat, sse(
		chatChunk(0, `{"content":"a [REDACT"}`, ""),
		chatChunk(1, `{"content":"b [REDACT"}`, ""),
		chatChunk(0, `{"content":"ED_EMAIL_1]"}`, ""),
		chatChunk(1, `{"content":"ED_IPV4_1]"}`, ""),
		chatChunk(1, `{"tool_calls":[{"index":0,"function":{"arguments":"{\"k\":\"[REDACTED_"}}]}`, ""),
		chatChunk(0, `{"tool_calls":[{"index":0,"function":{"arguments":"{\"k\":\"[REDACTED_"}}]}`, ""),
		chatChunk(1, `{"tool_calls":[{"index":0,"function":{"arguments":"IPV4_1]\"}"}}]}`, ""),
		chatChunk(0, `{"tool_calls":[{"index":0,"function":{"arguments":"EMAIL_1]\"}"}}]}`, ""),
		chatChunk(0, `{}`, "stop"),
		chatChunk(1, `{}`, "stop"),
		"data: [DONE]",
	), nil)
	c, a := chatStreams(t, out)
	if c[0] != "a alice@corp.io" || c[1] != "b 10.0.0.5" {
		t.Errorf("content = %v", c)
	}
	if a[0] != `{"k":"alice@corp.io"}` || a[10] != `{"k":"10.0.0.5"}` {
		t.Errorf("args = %v", a)
	}
}

func TestChatSSEPassThrough(t *testing.T) {
	ping := `: keep-alive`
	plain := chatChunk(0, `{"content":"hello"}`, "")
	usage := `data: {"id":"x","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":3}}`
	out := runSSEWith(t, OpenAIChat, sse(ping, plain, usage, "data: [DONE]"), nil)
	for _, want := range []string{ping + "\n\n", plain + "\n\n", usage + "\n\n", "data: [DONE]\n\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("unchanged event not byte-identical, missing %q in\n%s", want, out)
		}
	}
}

func TestChatSSEFlushOnTruncatedStream(t *testing.T) {
	out := runSSEWith(t, OpenAIChat, sse(chatChunk(0, `{"content":"cut [REDACTED_EMAIL_1"}`, "")), nil)
	if c, _ := chatStreams(t, out); c[0] != "cut [REDACTED_EMAIL_1" {
		t.Errorf("content = %q", c[0])
	}
}

// [DONE] without a finish chunk still flushes held-back text before it.
func TestChatSSEDoneFlushes(t *testing.T) {
	out := runSSEWith(t, OpenAIChat, sse(chatChunk(0, `{"content":"x ["}`, ""), "data: [DONE]"), nil)
	if c, _ := chatStreams(t, out); c[0] != "x [" || !strings.HasSuffix(out, "data: [DONE]\n\n") {
		t.Errorf("content = %q\n%s", c[0], out)
	}
}

func respEvent(typ, data string) string {
	return "event: " + typ + "\ndata: " + data
}

func TestResponsesSSESplitPlaceholders(t *testing.T) {
	d := func(typ string, oi int, extra, delta string) string {
		return respEvent(typ, `{"type":"`+typ+`","item_id":"it_1","output_index":`+itoa(oi)+extra+`,"sequence_number":7,"delta":`+jsonStr(delta)+`}`)
	}
	const text, fn = "response.output_text.delta", "response.function_call_arguments.delta"
	reasoning := respEvent("response.reasoning_summary_text.delta",
		`{"type":"response.reasoning_summary_text.delta","item_id":"rs_1","output_index":0,"summary_index":0,"delta":"mail [REDACTED_EMAIL_1]"}`)
	completed := respEvent("response.completed", `{"type":"response.completed","response":{"id":"resp_9","status":"completed","output":[`+
		`{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"see [REDACTED_EMAIL_1]"}],"encrypted_content":"x[REDACTED_EMAIL_1]"},`+
		`{"type":"message","id":"m_1","content":[{"type":"output_text","text":"Mail [REDACTED_EMAIL_1] soon ["}]},`+
		`{"type":"function_call","id":"fc_1","call_id":"call_1","name":"run","arguments":"{\"command\": \"login [REDACTED_PASSWORD_1] at [REDACTED_IPV4_1]\"}"}]}}`)
	var ids []string
	out := runSSEWith(t, OpenAIResponses, sse(
		respEvent("response.created", `{"type":"response.created","response":{"id":"resp_9","status":"in_progress","output":[]}}`),
		d(text, 0, `,"content_index":0`, "Mail [REDACT"),
		d(text, 0, `,"content_index":0`, "ED_EMA"),
		d(text, 0, `,"content_index":0`, "IL_1] soon ["),
		respEvent("response.output_text.done", `{"type":"response.output_text.done","item_id":"it_1","output_index":0,"content_index":0,"text":"Mail [REDACTED_EMAIL_1] soon ["}`),
		d(fn, 1, ``, `{"command": "login [REDACTED_PASS`),
		d(fn, 1, ``, `WORD_1] at [REDACTED_IPV4_1`),
		d(fn, 1, ``, `]"}`),
		respEvent("response.function_call_arguments.done", `{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":1,"arguments":"{\"command\": \"login [REDACTED_PASSWORD_1] at [REDACTED_IPV4_1]\"}"}`),
		reasoning,
		completed,
	), func(id string) { ids = append(ids, id) })

	if len(ids) != 1 || ids[0] != "resp_9" {
		t.Errorf("response ids reported = %v", ids)
	}
	var text0, fn1 strings.Builder
	var doneText, doneArgs string
	var reasoningOK, sawCompleted bool
	for _, ev := range strings.Split(strings.TrimSpace(out), "\n\n") {
		lines := strings.Split(ev, "\n")
		data, _ := strings.CutPrefix(lines[len(lines)-1], "data: ")
		var m map[string]any
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			t.Fatalf("bad event %q: %v", ev, err)
		}
		if typ := m["type"].(string); lines[0] != "event: "+typ {
			t.Errorf("event line %q does not match type %q", lines[0], typ)
		}
		switch m["type"] {
		case text:
			text0.WriteString(m["delta"].(string))
		case fn:
			fn1.WriteString(m["delta"].(string))
		case "response.output_text.done":
			doneText = m["text"].(string)
		case "response.function_call_arguments.done":
			doneArgs = m["arguments"].(string)
		case "response.reasoning_summary_text.delta":
			reasoningOK = ev == reasoning
		case "response.completed":
			sawCompleted = true
			items := m["response"].(map[string]any)["output"].([]any)
			rs := items[0].(map[string]any)
			if rs["encrypted_content"] != "x[REDACTED_EMAIL_1]" || rs["summary"].([]any)[0].(map[string]any)["text"] != "see [REDACTED_EMAIL_1]" {
				t.Errorf("reasoning item modified: %v", rs)
			}
			if txt := items[1].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]; txt != "Mail alice@corp.io soon [" {
				t.Errorf("completed text = %q", txt)
			}
			var args map[string]string
			if err := json.Unmarshal([]byte(items[2].(map[string]any)["arguments"].(string)), &args); err != nil || args["command"] != `login pa"ss\word at 10.0.0.5` {
				t.Errorf("completed arguments = %v, %v", items[2], err)
			}
		}
	}
	if text0.String() != "Mail alice@corp.io soon [" || doneText != "Mail alice@corp.io soon [" {
		t.Errorf("text deltas = %q, done = %q", text0.String(), doneText)
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(fn1.String()), &args); err != nil || args["command"] != `login pa"ss\word at 10.0.0.5` {
		t.Errorf("argument deltas = %q, %v", fn1.String(), err)
	}
	var done map[string]string
	if err := json.Unmarshal([]byte(doneArgs), &done); err != nil || done["command"] != `login pa"ss\word at 10.0.0.5` {
		t.Errorf("done arguments = %q, %v", doneArgs, err)
	}
	if !reasoningOK {
		t.Error("reasoning summary delta was modified")
	}
	if !sawCompleted {
		t.Error("no response.completed event")
	}
	// the held-back "[" is emitted before output_text.done
	if i, j := strings.LastIndex(out, `"delta":"["`), strings.Index(out, "event: response.output_text.done"); i < 0 || i > j {
		t.Errorf("held-back text not flushed before output_text.done:\n%s", out)
	}
}

func TestResponsesSSEOutputsDoNotCrossContaminate(t *testing.T) {
	d := func(oi, ci int, delta string) string {
		return respEvent("response.output_text.delta", `{"type":"response.output_text.delta","output_index":`+itoa(oi)+`,"content_index":`+itoa(ci)+`,"delta":`+jsonStr(delta)+`}`)
	}
	out := runSSEWith(t, OpenAIResponses, sse(
		d(0, 0, "[REDACT"), d(0, 1, "[REDACT"), d(1, 0, "[REDACT"),
		d(0, 0, "ED_EMAIL_1]"), d(0, 1, "ED_IPV4_1]"), d(1, 0, "ED_PASSWORD_1]"),
	), nil)
	got := map[string]string{}
	for _, ev := range strings.Split(strings.TrimSpace(out), "\n\n") {
		var m struct {
			OutputIndex  int `json:"output_index"`
			ContentIndex int `json:"content_index"`
			Delta        string
		}
		lines := strings.Split(ev, "\n")
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[len(lines)-1], "data: ")), &m); err != nil {
			t.Fatal(err)
		}
		got[itoa(m.OutputIndex)+itoa(m.ContentIndex)] += m.Delta
	}
	if got["00"] != "alice@corp.io" || got["01"] != "10.0.0.5" || got["10"] != `pa"ss\word` {
		t.Errorf("got %v", got)
	}
}

func TestResponsesSSEFlushOnTruncatedStream(t *testing.T) {
	out := runSSEWith(t, OpenAIResponses, sse(
		respEvent("response.output_text.delta", `{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"cut [REDACTED_EMAIL_1"}`),
	), nil)
	if !strings.Contains(out, `"delta":"cut "`) || !strings.Contains(out, `"delta":"[REDACTED_EMAIL_1"`) {
		t.Errorf("held-back text lost on truncation:\n%s", out)
	}
}
