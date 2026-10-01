package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"nospyai/internal/payload"
	"nospyai/internal/redact"
)

const testToken = "tok123"

// secrets must never reach the upstream, and must come back to the client unchanged.
var secrets = []string{
	"alice@corp.io",
	"10.20.30.40",
	"hunter22",
	"sk-" + "ant-api03-" + "abcdefghijklmnopqrstuvwxyz0123",
	"build.corp.io",
}

var phRe = regexp.MustCompile(`\[REDACTED_[A-Z][A-Z0-9_]*_\d+\]`)

// fakeUpstream records requests and echoes the placeholders it saw, as JSON or, for
// "stream": true, as SSE text deltas split into 3-byte pieces.
type fakeUpstream struct {
	mu    sync.Mutex
	calls []call
}

type call struct {
	body, path string
	hdr        http.Header
}

func (f *fakeUpstream) recorded() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, call{string(body), r.URL.RequestURI(), r.Header.Clone()})
	f.mu.Unlock()

	echo := strings.Join(phRe.FindAllString(noNote(body), -1), " ")
	var req struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); len(body) > 0 && err != nil {
		http.Error(w, "invalid test request", http.StatusBadRequest)
		return
	}
	if !req.Stream {
		out, _ := json.Marshal(map[string]any{"type": "message", "content": []any{map[string]any{"type": "text", "text": echo}}})
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("gzip") != "" && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write(out)
			_ = gz.Close()
			return
		}
		_, _ = w.Write(out)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	for i := 0; i < len(echo); i += 3 {
		piece, _ := json.Marshal(echo[i:min(i+3, len(echo))])
		_, _ = fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", piece)
		w.(http.Flusher).Flush()
	}
	_, _ = fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
}

func setup(t *testing.T, upstreamPath string) (*fakeUpstream, *httptest.Server) {
	t.Helper()
	fu := &fakeUpstream{}
	up := httptest.NewServer(fu)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL + upstreamPath)
	h, err := New([]Route{{Prefix: "/anthropic", Upstream: u, Dialect: AnthropicDialect}},
		testToken, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	px := httptest.NewServer(h)
	t.Cleanup(px.Close)
	return fu, px
}

func messagesBody(stream bool) string {
	b, _ := json.Marshal(map[string]any{
		"model":  "claude-opus-5-5",
		"stream": stream,
		"system": "Deploy host is build.corp.io",
		"messages": []any{
			map[string]any{"role": "user", "content": "mail alice@corp.io, ssh 10.20.30.40, login password=hunter22 now, key " + secrets[3]},
		},
	})
	return string(b)
}

func post(t *testing.T, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func assertRedactedAndRestored(t *testing.T, fu *fakeUpstream, clientSaw string) {
	t.Helper()
	calls := fu.recorded()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d", len(calls))
	}
	for _, s := range secrets {
		if strings.Contains(calls[0].body, s) {
			t.Errorf("upstream received %q:\n%s", s, calls[0].body)
		}
		if !strings.Contains(clientSaw, s) {
			t.Errorf("client did not get %q back:\n%s", s, clientSaw)
		}
	}
	if strings.Contains(clientSaw, "[REDACTED_") {
		t.Errorf("client saw a placeholder:\n%s", clientSaw)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	fu, px := setup(t, "")
	resp := post(t, px.URL+"/"+testToken+"/anthropic/v1/messages?beta=true", messagesBody(false),
		map[string]string{"x-api-key": "client-key"})
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	assertRedactedAndRestored(t, fu, string(body))
	c := fu.recorded()[0]
	if c.path != "/v1/messages?beta=true" {
		t.Errorf("upstream path = %q", c.path)
	}
	if got := c.hdr.Get("X-Api-Key"); got != "client-key" {
		t.Errorf("auth header = %q, want passthrough", got)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length %d, body %d", resp.ContentLength, len(body))
	}
}

// The placeholder note reaches the upstream only when the request had something redacted.
func TestPlaceholderNoteOnlyWhenRedacted(t *testing.T) {
	fu, px := setup(t, "")
	url := px.URL + "/" + testToken + "/anthropic/v1/messages"
	post(t, url, messagesBody(false), nil)
	post(t, url, `{"model":"claude-opus-5-5","system":"be brief","messages":[{"role":"user","content":"hello"}]}`, nil)
	calls := fu.recorded()
	if len(calls) != 2 {
		t.Fatalf("upstream calls = %d", len(calls))
	}
	if !strings.Contains(calls[0].body, payload.PlaceholderNote) {
		t.Errorf("redacted request went upstream without the note:\n%s", calls[0].body)
	}
	if strings.Contains(calls[1].body, "privacy proxy") || !strings.Contains(calls[1].body, `"system":"be brief"`) {
		t.Errorf("unredacted request was changed:\n%s", calls[1].body)
	}
}

func TestGzipResponseIsRestored(t *testing.T) {
	fu, px := setup(t, "")
	resp := post(t, px.URL+"/"+testToken+"/anthropic/v1/messages?gzip=1", messagesBody(false),
		map[string]string{"Accept-Encoding": "br"})
	body, _ := io.ReadAll(resp.Body)
	if ae := fu.recorded()[0].hdr.Get("Accept-Encoding"); !strings.Contains(ae, "gzip") {
		t.Fatalf("client Accept-Encoding forwarded: %q", ae)
	}
	assertRedactedAndRestored(t, fu, string(body))
}

func TestSSERoundTrip(t *testing.T) {
	fu, px := setup(t, "")
	resp := post(t, px.URL+"/"+testToken+"/anthropic/v1/messages", messagesBody(true), nil)
	raw, _ := io.ReadAll(resp.Body)
	var text strings.Builder
	for line := range strings.SplitSeq(string(raw), "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Delta struct{ Text string } `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			t.Fatalf("bad event %q: %v", data, err)
		}
		text.WriteString(ev.Delta.Text)
	}
	assertRedactedAndRestored(t, fu, text.String())
}

func TestRejectedRequestsNeverReachUpstream(t *testing.T) {
	fu, px := setup(t, "")
	good := "/" + testToken + "/anthropic/v1/messages"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(messagesBody(false))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		hdr    map[string]string
		want   int
	}{
		{"missing token", "POST", "/anthropic/v1/messages", messagesBody(false), nil, 404},
		{"wrong token", "POST", "/tok124/anthropic/v1/messages", messagesBody(false), nil, 404},
		{"token prefix only", "POST", "/tok12/anthropic/v1/messages", messagesBody(false), nil, 404},
		{"unknown route", "POST", "/" + testToken + "/gemini/v1/x", messagesBody(false), nil, 404},
		{"malformed json", "POST", good, `{"messages": [`, nil, 400},
		{"trailing json", "POST", good, `{} {}`, nil, 400},
		{"gzip body", "POST", good, gz.String(), map[string]string{"Content-Encoding": "gzip"}, 415},
		{"websocket upgrade", "GET", good, "", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, 400},
		{"unsupported path with body", "POST", "/" + testToken + "/anthropic/v1/files", messagesBody(false), nil, 415},
		{"non-json body", "POST", good, "email alice@corp.io", map[string]string{"Content-Type": "text/plain"}, 415},
		{"too large", "POST", good, `{"a":"` + strings.Repeat("x", maxBody) + `"}`, nil, 413},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(c.method, px.URL+c.path, strings.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			for k, v := range c.hdr {
				req.Header.Set(k, v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, c.want)
			}
		})
	}
	if n := len(fu.recorded()); n != 0 {
		t.Fatalf("upstream called %d times for rejected requests", n)
	}
}

func TestUnsupportedPathWithoutBodyIsForwarded(t *testing.T) {
	fu, px := setup(t, "")
	resp, err := http.Get(px.URL + "/" + testToken + "/anthropic/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if calls := fu.recorded(); resp.StatusCode != 200 || len(calls) != 1 || calls[0].path != "/v1/models" {
		t.Fatalf("status %d, calls %v", resp.StatusCode, calls)
	}
}

func TestUpstreamPathJoin(t *testing.T) {
	for _, c := range []struct{ upstream, want string }{
		{"/gateway", "/gateway/v1/messages"}, // corporate gateway prefix is kept
		{"/v1", "/v1/messages"},              // no /v1/v1
		{"/v1/", "/v1/messages"},
	} {
		fu, px := setup(t, c.upstream)
		post(t, px.URL+"/"+testToken+"/anthropic/v1/messages", `{}`, nil)
		if got := fu.recorded()[0].path; got != c.want {
			t.Errorf("upstream %q: path %q, want %q", c.upstream, got, c.want)
		}
	}
}

func TestUpstreamDownIs502(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	h, _ := New([]Route{{Prefix: "/anthropic", Upstream: u, Dialect: AnthropicDialect}},
		testToken, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/"+testToken+"/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != 502 || strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Fatalf("status %d body %q", rec.Code, rec.Body)
	}
}

// The log line carries counts and the token-free path, never values or the token.
func TestLogHasNoValuesOrToken(t *testing.T) {
	fu := &fakeUpstream{}
	up := httptest.NewServer(fu)
	defer up.Close()
	u, _ := url.Parse(up.URL)
	var logs bytes.Buffer
	h, _ := New([]Route{{Prefix: "/anthropic", Upstream: u, Dialect: AnthropicDialect}},
		testToken, redact.NewDetector(redact.Config{}), slog.New(slog.NewJSONHandler(&logs, nil)))
	px := httptest.NewServer(h)
	defer px.Close()
	post(t, px.URL+"/"+testToken+"/anthropic/v1/messages", messagesBody(false), nil)
	px.Close() // wait for the handler's deferred log line

	s := logs.String()
	for _, bad := range append([]string{testToken}, secrets...) {
		if strings.Contains(s, bad) {
			t.Errorf("log contains %q: %s", bad, s)
		}
	}
	if !strings.Contains(s, `"path":"/anthropic/v1/messages"`) || !strings.Contains(s, `"EMAIL":1`) {
		t.Errorf("log missing path or counts: %s", s)
	}
}

func TestNewValidates(t *testing.T) {
	u, _ := url.Parse("https://api.anthropic.com")
	for _, c := range []struct {
		token string
		rt    Route
	}{
		{"", Route{Prefix: "/anthropic", Upstream: u}},
		{"a/b", Route{Prefix: "/anthropic", Upstream: u}},
		{"t", Route{Prefix: "anthropic", Upstream: u}},
		{"t", Route{Prefix: "/a/b", Upstream: u}},
		{"t", Route{Prefix: "/anthropic", Upstream: &url.URL{Path: "/v1"}}},
	} {
		if _, err := New([]Route{c.rt}, c.token, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler)); err == nil {
			t.Errorf("token %q route %+v: want error", c.token, c.rt)
		}
	}
}

// noNote drops the placeholder note from a request body: its example placeholder is not a value
// the vault issued, so echoing upstreams must not see it.
func noNote(b []byte) string { return strings.ReplaceAll(string(b), payload.PlaceholderNote, "") }
