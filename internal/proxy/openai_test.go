package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nospyai/internal/redact"
)

// fakeOpenAI records requests and answers like the OpenAI API would: it echoes the placeholders
// it saw, as a chat completion or a Responses object, JSON or SSE (split into 3-byte deltas).
type fakeOpenAI struct {
	mu    sync.Mutex
	calls []call
	n     int
}

func (f *fakeOpenAI) recorded() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeOpenAI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, call{string(body), r.URL.RequestURI(), r.Header.Clone()})
	f.n++
	id := fmt.Sprintf("resp_%d", f.n)
	f.mu.Unlock()

	echo := strings.Join(phRe.FindAllString(noNote(body), -1), " ")
	var req struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); len(body) > 0 && err != nil {
		http.Error(w, "invalid test request", http.StatusBadRequest)
		return
	}
	argStr := `{"cmd":"ssh ` + echo + `"}`
	args := []byte(jsonString(argStr))
	responses := strings.HasSuffix(r.URL.Path, "/responses")

	if !req.Stream {
		w.Header().Set("Content-Type", "application/json")
		if responses {
			_, _ = fmt.Fprintf(w, `{"id":%q,"object":"response","status":"completed","output":[{"type":"message","id":"m1","content":[{"type":"output_text","text":%s}]},{"type":"function_call","call_id":"c1","name":"run","arguments":%s}]}`,
				id, jsonString(echo), args)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":%s,"tool_calls":[{"id":"c1","type":"function","function":{"name":"run","arguments":%s}}]}}]}`,
			jsonString(echo), args)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	flush := w.(http.Flusher).Flush
	pieces := func(s string) []string {
		var out []string
		for i := 0; i < len(s); i += 3 {
			out = append(out, s[i:min(i+3, len(s))])
		}
		return out
	}
	if responses {
		_, _ = fmt.Fprintf(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":%q,\"status\":\"in_progress\",\"output\":[]}}\n\n", id)
		for _, p := range pieces(echo) {
			_, _ = fmt.Fprintf(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"m1\",\"output_index\":0,\"content_index\":0,\"delta\":%s}\n\n", jsonString(p))
			flush()
		}
		_, _ = fmt.Fprintf(w, "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"output_index\":0,\"content_index\":0,\"text\":%s}\n\n", jsonString(echo))
		for _, p := range pieces(argStr) {
			_, _ = fmt.Fprintf(w, "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"delta\":%s}\n\n", jsonString(p))
			flush()
		}
		_, _ = fmt.Fprint(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\""+id+"\",\"status\":\"completed\",\"output\":[]}}\n\n")
		return
	}
	for _, p := range pieces(echo) {
		_, _ = fmt.Fprintf(w, "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%s},\"finish_reason\":null}]}\n\n", jsonString(p))
		flush()
	}
	for _, p := range pieces(argStr) {
		_, _ = fmt.Fprintf(w, "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":%s}}]},\"finish_reason\":null}]}\n\n", jsonString(p))
		flush()
	}
	_, _ = fmt.Fprint(w, "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n")
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

type openAIEnv struct {
	fu     *fakeOpenAI
	px     *httptest.Server
	chains *ChainStore
	client string // what WithClient reports; tests change it
	mu     sync.Mutex
}

func (e *openAIEnv) setClient(c string) { e.mu.Lock(); e.client = c; e.mu.Unlock() }

// setupOpenAI serves the fake at upstreamPath under /openai and /ollama (a provider route).
func setupOpenAI(t *testing.T, upstreamPath string) *openAIEnv {
	t.Helper()
	e := &openAIEnv{fu: &fakeOpenAI{}, chains: NewChainStore(0, 0), client: "a"}
	up := httptest.NewServer(e.fu)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL + upstreamPath)
	h, err := New([]Route{
		{Prefix: "/openai", Upstream: u, Dialect: OpenAIDialect},
		{Prefix: "/ollama", Upstream: u, Dialect: OpenAIDialect},
	}, testToken, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler),
		WithChainStore(e.chains), WithClient(func(*http.Request) string { e.mu.Lock(); defer e.mu.Unlock(); return e.client }))
	if err != nil {
		t.Fatal(err)
	}
	e.px = httptest.NewServer(h)
	t.Cleanup(e.px.Close)
	return e
}

func chatBody(stream bool) string {
	b, _ := json.Marshal(map[string]any{
		"model": "gpt-5", "stream": stream,
		"messages": []any{
			map[string]any{"role": "system", "content": "Deploy host is build.corp.io"},
			map[string]any{"role": "user", "content": "mail alice@corp.io, ssh 10.20.30.40, login password=hunter22 now, key " + secrets[3]},
		},
	})
	return string(b)
}

func responsesBody(stream bool, prev string, extra string) string {
	m := map[string]any{
		"model": "gpt-5", "stream": stream,
		"instructions": "Deploy host is build.corp.io",
		"input":        "mail alice@corp.io, ssh 10.20.30.40, login password=hunter22 now, key " + secrets[3] + extra,
	}
	if prev != "" {
		m["previous_response_id"] = prev
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// clientText reassembles what a client would see from a JSON or SSE reply: the assistant
// text, plus every tool-call arguments string.
func clientText(t *testing.T, resp *http.Response) (text, args string) {
	t.Helper()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	return replyText(t, resp.Header.Get("Content-Type"), raw)
}

// replyText extracts the assistant text and the tool-call arguments from a raw JSON or SSE reply.
func replyText(t *testing.T, contentType string, raw []byte) (text, args string) {
	t.Helper()
	var tb, ab strings.Builder
	if strings.HasPrefix(contentType, "text/event-stream") {
		for line := range strings.SplitSeq(string(raw), "\n") {
			data, ok := strings.CutPrefix(line, "data: ")
			if !ok || data == "[DONE]" {
				continue
			}
			var ev struct {
				Type    string
				Delta   string
				Choices []struct {
					Delta struct {
						Content   string
						ToolCalls []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
					}
				}
			}
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				t.Fatalf("bad event %q: %v", data, err)
			}
			switch ev.Type {
			case "response.output_text.delta":
				tb.WriteString(ev.Delta)
			case "response.function_call_arguments.delta":
				ab.WriteString(ev.Delta)
			}
			for _, c := range ev.Choices {
				tb.WriteString(c.Delta.Content)
				for _, tc := range c.Delta.ToolCalls {
					ab.WriteString(tc.Function.Arguments)
				}
			}
		}
		if !strings.Contains(string(raw), "data: [DONE]") && strings.Contains(string(raw), "chat.completion.chunk") {
			t.Errorf("[DONE] missing:\n%s", raw)
		}
		return tb.String(), ab.String()
	}
	var doc struct {
		Choices []struct {
			Message struct {
				Content   string
				ToolCalls []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
			}
		}
		Output []struct {
			Content   []struct{ Text string }
			Arguments string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("reply not JSON: %v\n%s", err, raw)
	}
	for _, c := range doc.Choices {
		tb.WriteString(c.Message.Content)
		for _, tc := range c.Message.ToolCalls {
			ab.WriteString(tc.Function.Arguments)
		}
	}
	for _, o := range doc.Output {
		for _, c := range o.Content {
			tb.WriteString(c.Text)
		}
		ab.WriteString(o.Arguments)
	}
	return tb.String(), ab.String()
}

func TestOpenAIRoundTrips(t *testing.T) {
	cases := []struct {
		name, path string
		body       func(stream bool) string
	}{
		{"chat", "/openai/v1/chat/completions", chatBody},
		{"responses", "/openai/v1/responses", func(s bool) string { return responsesBody(s, "", "") }},
		{"provider route", "/ollama/v1/chat/completions", chatBody},
	}
	for _, c := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s stream=%v", c.name, stream), func(t *testing.T) {
				e := setupOpenAI(t, "/v1")
				resp := post(t, e.px.URL+"/"+testToken+c.path, c.body(stream), map[string]string{"Authorization": "Bearer client-key"})
				text, args := clientText(t, resp)
				assertRedactedAndRestored(t, &fakeUpstream{calls: e.fu.recorded()}, text)
				// The tool-call arguments come back as valid JSON holding the real values.
				var a struct{ Cmd string }
				if err := json.Unmarshal([]byte(args), &a); err != nil {
					t.Fatalf("arguments %q not JSON: %v", args, err)
				}
				for _, s := range secrets {
					if !strings.Contains(a.Cmd, s) {
						t.Errorf("arguments missing %q: %q", s, a.Cmd)
					}
				}
				call := e.fu.recorded()[0]
				if !strings.HasPrefix(call.path, "/v1/") || strings.HasPrefix(call.path, "/v1/v1") {
					t.Errorf("upstream path = %q", call.path)
				}
				if got := call.hdr.Get("Authorization"); got != "Bearer client-key" {
					t.Errorf("auth header = %q, want passthrough", got)
				}
			})
		}
	}
}

// /openai/v1/chat/completions reaches the upstream at /v1/chat/completions, never /v1/v1/....
func TestOpenAIUpstreamPathJoin(t *testing.T) {
	for _, c := range []struct{ upstream, path, want string }{
		{"/v1", "/v1/chat/completions", "/v1/chat/completions"},
		{"/v1/", "/v1/chat/completions", "/v1/chat/completions"},
		{"", "/v1/chat/completions", "/v1/chat/completions"},
		{"/gateway/v1", "/v1/responses", "/gateway/v1/responses"},
		{"/v1", "/v1/embeddings", "/v1/embeddings"},
	} {
		e := setupOpenAI(t, c.upstream)
		_ = post(t, e.px.URL+"/"+testToken+"/openai"+c.path, `{"model":"m","input":"hi"}`, nil).Body.Close()
		if got := e.fu.recorded()[0].path; got != c.want {
			t.Errorf("upstream %q: path %q, want %q", c.upstream, got, c.want)
		}
	}
}

func TestOpenAIEndpoints(t *testing.T) {
	e := setupOpenAI(t, "/v1")
	base := e.px.URL + "/" + testToken + "/openai"
	// Embeddings: the input is redacted, the response has nothing to restore.
	resp := post(t, base+"/v1/embeddings", `{"model":"e","input":"mail alice@corp.io"}`, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || strings.Contains(e.fu.recorded()[0].body, "alice@corp.io") {
		t.Errorf("embeddings: status %d, upstream body %s", resp.StatusCode, e.fu.recorded()[0].body)
	}
	// Bodyless GET passes through; anything else with a body is 415 and never forwarded.
	g, err := http.Get(base + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_ = g.Body.Close()
	if g.StatusCode != 200 || e.fu.recorded()[1].path != "/v1/models" {
		t.Errorf("GET /v1/models: status %d, calls %v", g.StatusCode, e.fu.recorded())
	}
	before := len(e.fu.recorded())
	for _, p := range []string{"/v1/audio/transcriptions", "/v1/files", "/v1/completions"} {
		r := post(t, base+p, `{"a":"alice@corp.io"}`, nil)
		_ = r.Body.Close()
		if r.StatusCode != 415 {
			t.Errorf("%s: status %d, want 415", p, r.StatusCode)
		}
	}
	mp := post(t, base+"/v1/audio/transcriptions", "--x\r\nalice@corp.io\r\n--x--", map[string]string{"Content-Type": "multipart/form-data; boundary=x"})
	_ = mp.Body.Close()
	if mp.StatusCode != 415 || len(e.fu.recorded()) != before {
		t.Errorf("multipart: status %d, upstream calls %d -> %d", mp.StatusCode, before, len(e.fu.recorded()))
	}
}

func TestOpenAIRejectedRequestsNeverReachUpstream(t *testing.T) {
	e := setupOpenAI(t, "/v1")
	for _, c := range []struct {
		name, path, body string
		want             int
	}{
		{"malformed chat", "/openai/v1/chat/completions", `{"messages": [`, 400},
		{"malformed responses", "/openai/v1/responses", `{"input": `, 400},
		{"chain ref not a string", "/openai/v1/responses", `{"previous_response_id": 5}`, 400},
		{"wrong token", "", "", 404},
	} {
		path := "/" + testToken + c.path
		if c.name == "wrong token" {
			path = "/nope/openai/v1/chat/completions"
			c.body = chatBody(false)
		}
		r := post(t, e.px.URL+path, c.body, nil)
		_ = r.Body.Close()
		if r.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", c.name, r.StatusCode, c.want)
		}
	}
	if n := len(e.fu.recorded()); n != 0 {
		t.Fatalf("upstream called %d times", n)
	}
}

// --- Responses chains ---

func TestResponsesChainContinuesVault(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			e := setupOpenAI(t, "/v1")
			url := e.px.URL + "/" + testToken + "/openai/v1/responses"
			first := post(t, url, responsesBody(stream, "", ""), nil)
			clientText(t, first)

			// The second turn carries a NEW email. Its placeholder must continue the numbering
			// (EMAIL_2), and the reply must restore both the old and the new value.
			second := post(t, url, responsesBody(stream, "resp_1", ", also bob@corp.io"), nil)
			text, _ := clientText(t, second)
			calls := e.fu.recorded()
			if len(calls) != 2 {
				t.Fatalf("upstream calls = %d", len(calls))
			}
			if !strings.Contains(calls[1].body, "[REDACTED_EMAIL_2]") || strings.Contains(calls[1].body, "bob@corp.io") {
				t.Errorf("second request did not continue numbering: %s", calls[1].body)
			}
			if !strings.Contains(text, "alice@corp.io") || !strings.Contains(text, "bob@corp.io") {
				t.Errorf("second reply not restored: %q", text)
			}
			if strings.Contains(calls[1].body, "alice@corp.io") {
				t.Errorf("secret reached upstream: %s", calls[1].body)
			}
			// The chain goes on: a third turn can continue from the second's id.
			third := post(t, url, responsesBody(stream, "resp_2", ", also carol@corp.io"), nil)
			text, _ = clientText(t, third)
			if body := e.fu.recorded()[2].body; !strings.Contains(body, "[REDACTED_EMAIL_3]") || strings.Contains(body, "carol@corp.io") {
				t.Errorf("third request did not continue numbering: %s", body)
			}
			if !strings.Contains(text, "carol@corp.io") || !strings.Contains(text, "alice@corp.io") {
				t.Errorf("third reply not restored: %q", text)
			}
		})
	}
}

func TestResponsesChainMissIs409(t *testing.T) {
	e := setupOpenAI(t, "/v1")
	url := e.px.URL + "/" + testToken + "/openai/v1/responses"
	clientText(t, post(t, url, responsesBody(false, "", ""), nil)) // stores resp_1 for client "a"
	calls := len(e.fu.recorded())

	check := func(name, u, client, prev string) {
		t.Helper()
		e.setClient(client)
		r := post(t, u, responsesBody(false, prev, ""), nil)
		body, _ := io.ReadAll(r.Body)
		if r.StatusCode != 409 {
			t.Errorf("%s: status %d, want 409", name, r.StatusCode)
		}
		var er struct {
			Error struct{ Message, Type, Param, Code string }
		}
		if err := json.Unmarshal(body, &er); err != nil || er.Error.Type != "invalid_request_error" || er.Error.Param != "previous_response_id" || er.Error.Message == "" {
			t.Errorf("%s: not an OpenAI-shaped error: %s", name, body)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: content type %q", name, r.Header.Get("Content-Type"))
		}
	}
	check("unknown id", url, "a", "resp_nope")
	check("other client", url, "b", "resp_1")
	check("other route with the same id", e.px.URL+"/"+testToken+"/ollama/v1/responses", "a", "resp_1")
	if n := len(e.fu.recorded()); n != calls {
		t.Errorf("upstream called on a chain miss (%d -> %d)", calls, n)
	}
	// And the right client on the right route still works.
	e.setClient("a")
	clientText(t, post(t, url, responsesBody(false, "resp_1", ""), nil))
}

func TestResponsesChainExpiredIs409(t *testing.T) {
	e := setupOpenAI(t, "/v1")
	now := time.Now()
	e.chains.now = func() time.Time { return now }
	url := e.px.URL + "/" + testToken + "/openai/v1/responses"
	clientText(t, post(t, url, responsesBody(false, "", ""), nil))
	now = now.Add(DefaultChainTTL + time.Second)
	r := post(t, url, responsesBody(false, "resp_1", ""), nil)
	_ = r.Body.Close()
	if r.StatusCode != 409 {
		t.Errorf("status %d, want 409", r.StatusCode)
	}
}

// Chat Completions has no chain: a stray previous_response_id must not be looked up.
func TestChatIgnoresChainKey(t *testing.T) {
	e := setupOpenAI(t, "/v1")
	r := post(t, e.px.URL+"/"+testToken+"/openai/v1/chat/completions", `{"previous_response_id":"x","messages":[]}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Errorf("status %d", r.StatusCode)
	}
}

func TestChainStoreBoundsAndTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	cs := NewChainStore(2, time.Minute)
	cs.now = func() time.Time { return now }
	v := func(val string) *redact.Vault { x := redact.NewVault(); x.Placeholder(redact.KindEmail, val); return x }

	cs.Put("a", "/openai", "1", v("one@x.io"))
	cs.Put("a", "/openai", "2", v("two@x.io"))
	if _, ok := cs.Get("a", "/openai", "1"); !ok { // touch 1: 2 is now the coldest
		t.Fatal("entry 1 missing")
	}
	cs.Put("a", "/openai", "3", v("three@x.io"))
	if _, ok := cs.Get("a", "/openai", "2"); ok {
		t.Error("LRU did not evict the coldest entry")
	}
	for _, id := range []string{"1", "3"} {
		if _, ok := cs.Get("a", "/openai", id); !ok {
			t.Errorf("entry %s evicted", id)
		}
	}
	// Scope: client and route are part of the key.
	if _, ok := cs.Get("b", "/openai", "1"); ok {
		t.Error("another client got the entry")
	}
	if _, ok := cs.Get("a", "/ollama", "1"); ok {
		t.Error("another route got the entry")
	}
	// Get returns an independent clone that continues the numbering.
	got, _ := cs.Get("a", "/openai", "1")
	if ph := got.Placeholder(redact.KindEmail, "new@x.io"); ph != "[REDACTED_EMAIL_2]" {
		t.Errorf("clone did not continue numbering: %s", ph)
	}
	again, _ := cs.Get("a", "/openai", "1")
	if ph := again.Placeholder(redact.KindEmail, "other@x.io"); ph != "[REDACTED_EMAIL_2]" {
		t.Errorf("stored vault was modified through a clone: %s", ph)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := cs.Get("a", "/openai", "1"); ok {
		t.Error("expired entry returned")
	}
	cs.Put("a", "/openai", "4", v("four@x.io")) // sweeps what expired
	if cs.Len() != 1 {
		t.Errorf("Len = %d after expiry sweep, want 1", cs.Len())
	}
}

func TestNewRejectsDuplicatePrefix(t *testing.T) {
	u, _ := url.Parse("https://x.example")
	r := Route{Prefix: "/openai", Upstream: u, Dialect: OpenAIDialect}
	if _, err := New([]Route{r, r}, "t", redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler)); err == nil {
		t.Error("duplicate prefix accepted")
	}
}

func TestProviderTable(t *testing.T) {
	if len(Providers) == 0 {
		t.Fatal("empty provider table")
	}
	seen := map[string]bool{}
	for _, p := range Providers {
		u, err := url.Parse(p.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			t.Errorf("%s: bad upstream", p.Name)
		}
		if p.API != "anthropic" && p.API != "openai" {
			t.Errorf("%s: api %q", p.Name, p.API)
		}
		if p.Name == "" || strings.ContainsAny(p.Name, "/ =,") || seen[p.Name] {
			t.Errorf("bad or duplicate name %q", p.Name)
		}
		seen[p.Name] = true
	}
	if p, ok := LookupProvider("ollama"); !ok || p.Upstream != "http://127.0.0.1:11434/v1" || p.API != "openai" {
		t.Errorf("ollama entry = %+v, %v", p, ok)
	}
	if _, ok := LookupProvider("nosuch"); ok {
		t.Error("unknown provider found")
	}
}
