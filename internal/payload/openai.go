package payload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// OpenAIChat is the Chat Completions API (/v1/chat/completions). Embeddings requests use it
// too: only "input" carries text, and the response is vectors. Tool-call "arguments" is a JSON
// document inside a string; JSONStrKeys makes the walker decode it, treat it as user data
// and re-encode it, so the vault only ever holds decoded values.
var OpenAIChat = Dialect{
	Name: "openai-chat",
	SkipKeys: set("model", "role", "type", "id", "tool_call_id", "name", "object", "finish_reason",
		"logprobs", "response_format", "prompt_cache_key", "service_tier",
		"system_fingerprint", "file_data"),
	SkipTypes:   set("input_audio"), // base64 audio: binary, never touched
	SkipPaths:   [][]string{{"tools", "*", "function", "parameters"}},
	JSONStrKeys: set("arguments"),
	DropKeys:    []string{"user", "safety_identifier", "metadata"},
	KeyOrder:    []string{"tools", "messages"},
	sse:         openAIChatSSE,
	addNote:     openAIChatNote,
}

// OpenAIResponses is the Responses API (/v1/responses). Experimental: built from the published
// API reference and fixtures, not yet verified against the real API.
var OpenAIResponses = Dialect{
	Name: "openai-responses",
	SkipKeys: set("model", "role", "type", "id", "call_id", "item_id", "name", "status", "object",
		"previous_response_id", "encrypted_content", "prompt_cache_key", "service_tier"),
	SkipTypes:   set("reasoning", "input_image", "input_file", "computer_screenshot"), // screenshot image_url is a bare data: string
	SkipPaths:   [][]string{{"tools", "*", "parameters"}, {"text", "format", "schema"}},
	JSONStrKeys: set("arguments"),
	DropKeys:    []string{"user", "safety_identifier", "metadata"},
	KeyOrder:    []string{"tools", "instructions", "input"},
	ChainKey:    "previous_response_id",
	sse:         openAIResponsesSSE,
	addNote:     openAIResponsesNote,
}

// ChainRef returns the value of the dialect's ChainKey in a request body ("" when the body
// has none or the dialect has no chain key). An error means the body must be rejected.
func ChainRef(d Dialect, body []byte) (string, error) {
	if d.ChainKey == "" {
		return "", nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return "", err
	}
	raw, ok := top[d.ChainKey]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return "", fmt.Errorf("%s must be a string", d.ChainKey)
	}
	return id, nil
}

// ResponseID returns the top-level "id" of a non-streaming Responses body, or "".
func ResponseID(body []byte) string {
	var r struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &r) != nil {
		return ""
	}
	return r.ID
}

// held is a streamed string field taken out of an event while the generic restore walk runs
// over the rest, so text that went through a StreamRestorer is never restored twice.
type held struct {
	m   map[string]any
	key string
	val string
}

// finishEvent runs the generic restore walk over ev (minus the held fields), then puts the
// held fields back. changed says whether any held field differs from what arrived.
func (st *sseState) finishEvent(ev *sseEvent, holds []held, changed bool) {
	for _, h := range holds {
		delete(h.m, h.key)
	}
	if strings.Contains(ev.data, "[REDACTED_") {
		st.w.walk(ev.obj, nil, false)
		changed = true
	}
	for _, h := range holds {
		h.m[h.key] = h.val
	}
	if changed {
		ev.changed = true
	}
}

// indexOr returns the stream index of an element: its "index" field, else its position.
func indexOr(m map[string]any, pos int) string {
	if n, ok := m["index"]; ok && n != nil {
		return fmt.Sprint(n)
	}
	return fmt.Sprint(pos)
}

func cloneMap(m map[string]any, drop ...string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, k := range drop {
		delete(out, k)
	}
	return out
}

// openAIChatSSE handles Chat Completions chunks. Text, reasoning and tool-call argument deltas
// go through per-choice StreamRestorers, because a placeholder can be split across chunks.
// "data: [DONE]" is not JSON and passes through verbatim, after flushing anything still held.
func openAIChatSSE(st *sseState, ev *sseEvent) []*sseEvent {
	m := ev.obj
	if m == nil {
		if strings.TrimSpace(ev.data) == "[DONE]" {
			return append(st.flushAll(), ev)
		}
		return []*sseEvent{ev}
	}
	envelope := cloneMap(m, "choices", "usage")
	chunk := func(ci string, delta map[string]any) *sseEvent {
		o := cloneMap(envelope)
		idx := any(json.Number(ci))
		o["choices"] = []any{map[string]any{"index": idx, "delta": delta, "finish_reason": nil}}
		return &sseEvent{obj: o, changed: true}
	}

	var pre []*sseEvent
	var holds []held
	changed := false
	choices, _ := m["choices"].([]any)
	for pos, c := range choices {
		ch, _ := c.(map[string]any)
		if ch == nil {
			continue
		}
		ci := indexOr(ch, pos)
		finish := ch["finish_reason"] != nil
		// hold feeds one string field through its stream. On the last chunk of a choice the
		// stream's remainder is appended to the field, which keeps the order right.
		hold := func(owner map[string]any, key, id string, jsonEscape bool, synth func(string) *sseEvent) {
			in, ok := owner[key].(string)
			if !ok {
				return
			}
			out := st.feed(id, jsonEscape, in, synth)
			if finish {
				out += st.flushText(id)
			}
			if out != in {
				changed = true
			}
			holds = append(holds, held{owner, key, out})
		}
		if delta, ok := ch["delta"].(map[string]any); ok {
			for _, key := range []string{"content", "reasoning_content", "reasoning"} {
				hold(delta, key, "c:"+ci+":"+key, false, func(rem string) *sseEvent {
					return chunk(ci, map[string]any{key: rem})
				})
			}
			tcs, _ := delta["tool_calls"].([]any)
			for j, t := range tcs {
				tc, _ := t.(map[string]any)
				fn, _ := tc["function"].(map[string]any)
				if fn == nil {
					continue
				}
				ti := indexOr(tc, j)
				hold(fn, "arguments", "c:"+ci+":tool:"+ti, true, func(rem string) *sseEvent {
					return chunk(ci, map[string]any{"tool_calls": []any{map[string]any{
						"index": json.Number(ti), "function": map[string]any{"arguments": rem}}}})
				})
			}
		}
		if finish {
			// Streams this chunk doesn't carry (the ones it carries were flushed into it above):
			// their remainder goes out first, as a chunk of its own.
			for _, id := range st.openWithPrefix("c:" + ci + ":") {
				pre = append(pre, st.flush(id)...)
			}
		}
	}
	st.finishEvent(ev, holds, changed)
	return append(pre, ev)
}

// openAIResponsesSSE handles Responses events. The event's "type" names it; output text and
// function-call argument deltas go through StreamRestorers keyed by output (and content) index.
func openAIResponsesSSE(st *sseState, ev *sseEvent) []*sseEvent {
	m := ev.obj
	if m == nil {
		return []*sseEvent{ev}
	}
	typ, _ := m["type"].(string)
	synth := func(rem string) *sseEvent {
		o := cloneMap(m, "delta")
		o["delta"] = rem
		n := &sseEvent{obj: o, changed: true}
		if len(ev.other) > 0 {
			n.other = []string{"event: " + typ}
		}
		return n
	}
	oi, ci := fmt.Sprint(m["output_index"]), fmt.Sprint(m["content_index"])
	switch typ {
	case "response.output_text.delta", "response.function_call_arguments.delta":
		id, jsonEscape := "o:"+oi+":"+ci, false
		if typ == "response.function_call_arguments.delta" {
			id, jsonEscape = "f:"+oi, true
		}
		in, ok := m["delta"].(string)
		if !ok {
			st.restore(ev)
			return []*sseEvent{ev}
		}
		out := st.feed(id, jsonEscape, in, synth)
		st.finishEvent(ev, []held{{m, "delta", out}}, out != in)
		return []*sseEvent{ev}
	case "response.output_text.done":
		pre := st.flush("o:" + oi + ":" + ci)
		st.restore(ev)
		return append(pre, ev)
	case "response.function_call_arguments.done":
		pre := st.flush("f:" + oi)
		st.restore(ev)
		return append(pre, ev)
	case "response.created", "response.in_progress", "response.completed", "response.failed", "response.incomplete":
		if r, ok := m["response"].(map[string]any); ok {
			if id, ok := r["id"].(string); ok {
				st.responseID(id)
			}
		}
		st.restore(ev)
		return []*sseEvent{ev}
	}
	if strings.HasPrefix(typ, "response.reasoning") {
		return []*sseEvent{ev} // reasoning summaries pass through untouched
	}
	st.restore(ev)
	return []*sseEvent{ev}
}
