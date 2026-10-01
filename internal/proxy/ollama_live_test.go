package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"nospyai/internal/payload"
	"nospyai/internal/redact"
)

// Live check against a real Ollama (its OpenAI-compatible API). Opt-in: set NOSPY_OLLAMA_URL,
// e.g. NOSPY_OLLAMA_URL=http://127.0.0.1:11434/v1 (and NOSPY_OLLAMA_MODEL, default qwen2.5:0.5b).
// A recording shim sits between nospy and Ollama, so "the upstream never received the secret"
// is checked on the exact bytes Ollama got. Models may paraphrase or ignore tools, so the hard
// assertions are about secrets, JSON validity and restoration of whatever placeholders the
// model did emit; what the model did is logged.

type exchange struct {
	path, ctype string
	req, resp   []byte
}

type shim struct {
	mu  sync.Mutex
	log []exchange
}

func (s *shim) exchanges() []exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]exchange(nil), s.log...)
}

// newShim returns a recording reverse proxy in front of the Ollama at origin.
func newShim(t *testing.T, origin *url.URL) (*shim, *httptest.Server) {
	t.Helper()
	s := &shim{}
	rp := &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { pr.SetURL(origin); pr.Out.Host = origin.Host },
		FlushInterval:  -1,
		ModifyResponse: nil,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		rec := &recordingWriter{ResponseWriter: w}
		rp.ServeHTTP(rec, r)
		s.mu.Lock()
		s.log = append(s.log, exchange{r.URL.Path, rec.Header().Get("Content-Type"), body, rec.buf})
		s.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return s, srv
}

type recordingWriter struct {
	http.ResponseWriter
	buf []byte
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.buf = append(w.buf, b...)
	return w.ResponseWriter.Write(b)
}
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestOllamaLive(t *testing.T) {
	base := os.Getenv("NOSPY_OLLAMA_URL")
	if base == "" {
		t.Skip("set NOSPY_OLLAMA_URL (e.g. http://127.0.0.1:11434/v1) to run against a live Ollama")
	}
	model := os.Getenv("NOSPY_OLLAMA_MODEL")
	if model == "" {
		model = "qwen2.5:0.5b"
	}
	ou, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	origin := &url.URL{Scheme: ou.Scheme, Host: ou.Host}
	sh, shimSrv := newShim(t, origin)

	su, _ := url.Parse(shimSrv.URL) // no /v1: nospy keeps the client's /v1/... path
	h, err := New([]Route{{Prefix: "/ollama", Upstream: su, Dialect: OpenAIDialect}},
		testToken, redact.NewDetector(redact.Config{AllowHosts: []string{su.Hostname()}}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	px := httptest.NewServer(h)
	defer px.Close()
	api := px.URL + "/" + testToken + "/ollama/v1"
	client := &http.Client{Timeout: 3 * time.Minute}

	fakes := []string{"alice.test@corp-example.io", "10.20.30.40", "hunter22", "sk-" + "ant-api03-" + "abcdefghijklmnopqrstuvwxyz0123"}
	prompt := "Repeat back exactly this line and nothing else: contact alice.test@corp-example.io, server 10.20.30.40, password=hunter22, key " + fakes[3]

	do := func(path string, body any) (*http.Response, []byte, exchange) {
		t.Helper()
		before := len(sh.exchanges())
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", api+path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		// The shim logs after its handler returns, which can be just after the client sees EOF.
		for i := 0; i < 200 && len(sh.exchanges()) == before; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		ex := sh.exchanges()
		if len(ex) == before {
			t.Fatal("the shim recorded no exchange")
		}
		return resp, raw, ex[len(ex)-1]
	}

	// checkPair holds the hard assertions for one exchange: no secret reached Ollama, and every
	// placeholder the model emitted that nospy had issued came back restored.
	checkPair := func(t *testing.T, name string, resp *http.Response, raw []byte, ex exchange) (text, args string) {
		t.Helper()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d: %s", name, resp.StatusCode, raw)
		}
		for _, f := range fakes {
			if strings.Contains(string(ex.req), f) {
				t.Errorf("%s: Ollama received %q:\n%s", name, f, ex.req)
			}
		}
		issued := map[string]bool{}
		for _, ph := range phRe.FindAllString(string(ex.req), -1) {
			issued[ph] = true
		}
		rawText, rawArgs := replyText(t, ex.ctype, ex.resp)
		text, args = replyText(t, resp.Header.Get("Content-Type"), raw)
		emitted := 0
		for _, ph := range phRe.FindAllString(rawText+" "+rawArgs, -1) {
			if issued[ph] {
				emitted++
				if strings.Contains(text+args, ph) {
					t.Errorf("%s: placeholder %s came back unrestored", name, ph)
				}
			}
		}
		if args != "" && !json.Valid([]byte(args)) {
			t.Errorf("%s: tool-call arguments %q are not valid JSON", name, args)
		}
		t.Logf("%s: upstream saw %d placeholders %v; model emitted %d of them; client text %q args %q",
			name, len(issued), keys(issued), emitted, text, args)
		return text, args
	}

	chat := func(stream bool, extra map[string]any, msgs ...any) map[string]any {
		m := map[string]any{"model": model, "stream": stream, "messages": msgs, "temperature": 0}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	user := func(s string) any { return map[string]any{"role": "user", "content": s} }
	tools := []any{map[string]any{"type": "function", "function": map[string]any{
		"name": "run_command", "description": "Run a shell command on a remote host",
		"parameters": map[string]any{"type": "object", "properties": map[string]any{
			"command": map[string]any{"type": "string"}}, "required": []string{"command"}}}}}

	for _, stream := range []bool{false, true} {
		name := map[bool]string{false: "chat", true: "chat stream"}[stream]
		t.Run(name, func(t *testing.T) {
			resp, raw, ex := do("/chat/completions", chat(stream, nil, user(prompt)))
			checkPair(t, name, resp, raw, ex)
			if stream && !strings.Contains(string(raw), "data: [DONE]") {
				t.Errorf("[DONE] missing from the client's stream")
			}
		})
		tname := name + " tools"
		t.Run(tname, func(t *testing.T) {
			resp, raw, ex := do("/chat/completions", chat(stream, map[string]any{"tools": tools},
				user("Use run_command to ping 10.20.30.40 once. Call the tool, do not explain.")))
			_, args := checkPair(t, tname, resp, raw, ex)
			if args == "" {
				t.Logf("%s: the model made no tool call (small models often don't)", tname)
			}
		})
	}

	t.Run("tool result follow-up", func(t *testing.T) {
		call := map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{
			"id": "call_1", "type": "function", "function": map[string]any{
				"name": "run_command", "arguments": `{"command":"ssh root@10.20.30.40 \"cat /etc/app.env\""}`}}}}
		toolMsg := map[string]any{"role": "tool", "tool_call_id": "call_1", "content": "DB_HOST=10.20.30.40\nDB_PASSWORD=hunter22\nOWNER=alice.test@corp-example.io\n"}
		for _, stream := range []bool{false, true} {
			name := map[bool]string{false: "follow-up", true: "follow-up stream"}[stream]
			resp, raw, ex := do("/chat/completions", chat(stream, map[string]any{"tools": tools},
				user("Check the server config."), call, toolMsg, user("Which host and owner did the file name? Repeat them.")))
			checkPair(t, name, resp, raw, ex)
			var req struct {
				Messages []struct {
					ToolCalls []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
				}
			}
			if err := json.Unmarshal(ex.req, &req); err != nil {
				t.Fatalf("upstream body not JSON: %v", err)
			}
			if got := req.Messages[1].ToolCalls[0].Function.Arguments; !json.Valid([]byte(got)) || !strings.Contains(got, "[REDACTED_IPV4_") {
				t.Errorf("%s: forwarded arguments = %q, want valid JSON with a placeholder", name, got)
			}
		}
	})

	// Ollama may serve /v1/responses too. The Responses path stays experimental either way.
	t.Run("responses (if served)", func(t *testing.T) {
		rtools := []any{map[string]any{"type": "function", "name": "run_command", "description": "Run a shell command on a remote host",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}, "required": []string{"command"}}}}
		var prevID string
		for _, c := range []struct {
			name   string
			stream bool
			body   map[string]any
		}{
			{"responses", false, map[string]any{"input": prompt}},
			{"responses stream", true, map[string]any{"input": prompt}},
			{"responses tools", false, map[string]any{"input": "Use run_command to ping 10.20.30.40 once. Call the tool, do not explain.", "tools": rtools}},
			{"responses tools stream", true, map[string]any{"input": "Use run_command to ping 10.20.30.40 once. Call the tool, do not explain.", "tools": rtools}},
		} {
			c.body["model"], c.body["stream"] = model, c.stream
			resp, raw, ex := do("/responses", c.body)
			if resp.StatusCode == 404 || resp.StatusCode == 405 {
				t.Skipf("this Ollama does not serve /v1/responses (status %d)", resp.StatusCode)
			}
			checkPair(t, c.name, resp, raw, ex)
			if !c.stream {
				prevID = payload.ResponseID(raw)
			}
		}
		// A chain: nospy continues the vault for previous_response_id (Ollama itself is stateless
		// and may ignore or reject the field; what matters is what nospy sent and returned).
		if prevID != "" {
			resp, raw, ex := do("/responses", map[string]any{"model": model, "previous_response_id": prevID,
				"input": "Also mention bob.test@corp-example.io in your answer."})
			t.Logf("responses chain: status %d; upstream saw %s; client got %.200s", resp.StatusCode, ex.req, raw)
			if strings.Contains(string(ex.req), "bob.test@corp-example.io") {
				t.Errorf("chain request leaked a secret upstream")
			}
		}
	})
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
