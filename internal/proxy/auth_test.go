package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nospyai/internal/redact"
)

// Fake credentials, built by concatenation so no scanner sees a token-looking literal.
var (
	tokA    = "nspy" + "_client-a-token"
	tokB    = "nspy" + "_client-b-token"
	realKey = "sk-" + "ant-real-upstream-key-0123456789"
	cliKey  = "sk-" + "ant-client-own-key-0123456789"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func tokensFile(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tokens")
	writeFile(t, p, strings.Join(lines, "\n")+"\n")
	return p
}

// syncBuf is a log sink safe to read while the server goroutine is still writing.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// requestLogs waits until n "request" lines were logged (the server logs after the response is
// sent) and returns everything logged so far.
func requestLogs(t *testing.T, b *syncBuf, n int) string {
	t.Helper()
	for i := 0; i < 400; i++ {
		if strings.Count(b.String(), `"msg":"request"`) >= n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return b.String()
}

type serveEnv struct {
	px     *httptest.Server
	anth   *fakeUpstream
	oai    *fakeOpenAI
	chains *ChainStore
	logs   *syncBuf
}

// newServeEnv serves /anthropic (inject) and /openai (passthrough) behind static tokens a and b,
// plus /passanthropic (passthrough). The fake upstreams record what they receive.
func newServeEnv(t *testing.T) *serveEnv {
	t.Helper()
	e := &serveEnv{anth: &fakeUpstream{}, oai: &fakeOpenAI{}, chains: NewChainStore(0, 0), logs: &syncBuf{}}
	aUp, oUp := httptest.NewServer(e.anth), httptest.NewServer(e.oai)
	t.Cleanup(aUp.Close)
	t.Cleanup(oUp.Close)
	au, _ := url.Parse(aUp.URL)
	ou, _ := url.Parse(oUp.URL + "/v1")
	keyPath := filepath.Join(t.TempDir(), "key")
	writeFile(t, keyPath, realKey+"\n")
	log := slog.New(slog.NewJSONHandler(e.logs, nil))
	kf, err := LoadKeyFile(keyPath, log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := LoadStaticTokens(tokensFile(t, "a:"+HashToken(tokA), "b:"+HashToken(tokB)), log)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewServer([]Route{
		{Prefix: "/anthropic", Upstream: au, Dialect: AnthropicDialect, KeyMode: KeyInject, KeyHeader: "X-Api-Key", Key: kf.Get},
		{Prefix: "/openai", Upstream: ou, Dialect: OpenAIDialect},
		{Prefix: "/passanthropic", Upstream: au, Dialect: AnthropicDialect},
		{Prefix: "/injectoai", Upstream: ou, Dialect: OpenAIDialect, KeyMode: KeyInject, KeyHeader: "Authorization", KeyScheme: "Bearer", Key: kf.Get},
	}, st, redact.NewDetector(redact.Config{}), log, WithChainStore(e.chains))
	if err != nil {
		t.Fatal(err)
	}
	e.px = httptest.NewServer(NewHealth(h))
	t.Cleanup(e.px.Close)
	return e
}

func (e *serveEnv) upstreamCalls() int { return len(e.anth.recorded()) + len(e.oai.recorded()) }

func TestServeRejectsBadCredentialsBeforeUpstream(t *testing.T) {
	e := newServeEnv(t)
	body := messagesBody(false)
	cases := []struct {
		name, path string
		hdr        map[string]string
	}{
		{"inject: no key header", "/anthropic/v1/messages", nil},
		{"inject: unknown token", "/anthropic/v1/messages", map[string]string{"X-Api-Key": "nspy" + "_nope"}},
		{"inject: empty token", "/anthropic/v1/messages", map[string]string{"X-Api-Key": ""}},
		{"inject: token in wrong header", "/anthropic/v1/messages", map[string]string{"Authorization": "Bearer " + tokA}},
		{"inject: token in X-Nospy-Token only", "/anthropic/v1/messages", map[string]string{"X-Nospy-Token": tokA}},
		{"inject bearer: no scheme", "/injectoai/v1/chat/completions", map[string]string{"Authorization": tokA}},
		{"inject bearer: empty bearer", "/injectoai/v1/chat/completions", map[string]string{"Authorization": "Bearer "}},
		{"passthrough: none", "/openai/v1/chat/completions", map[string]string{"Authorization": "Bearer " + cliKey}},
		{"passthrough: unknown header token", "/openai/v1/chat/completions", map[string]string{"X-Nospy-Token": "nope"}},
		{"passthrough: empty header token", "/openai/v1/chat/completions", map[string]string{"X-Nospy-Token": ""}},
		{"passthrough: unknown path token", "/t/nope/openai/v1/chat/completions", nil},
		{"passthrough: empty path token", "/t//openai/v1/chat/completions", nil},
		{"passthrough: real key as token", "/openai/v1/chat/completions", map[string]string{"X-Nospy-Token": cliKey}},
		{"unknown route", "/nosuch/v1/messages", nil},
	}
	for _, c := range cases {
		r := post(t, e.px.URL+c.path, body, c.hdr)
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 401 {
			t.Errorf("%s: status %d, want 401", c.name, r.StatusCode)
		}
		if r.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(b), `"authentication_error"`) {
			t.Errorf("%s: body %q (%s)", c.name, b, r.Header.Get("Content-Type"))
		}
		if strings.Contains(string(b), "token") && !strings.Contains(string(b), "authentication_error") {
			t.Errorf("%s: 401 body has detail: %s", c.name, b)
		}
	}
	if n := e.upstreamCalls(); n != 0 {
		t.Errorf("upstream called %d times for unauthenticated requests", n)
	}
}

// Authentication happens before the body is read: a bad client never makes nospy read (or
// buffer) its payload.
type tripBody struct{ read atomic.Bool }

func (b *tripBody) Read([]byte) (int, error) { b.read.Store(true); return 0, io.EOF }

func TestServeAuthBeforeReadingBody(t *testing.T) {
	e := newServeEnv(t)
	_ = e
	h, _ := NewServer([]Route{{Prefix: "/openai", Upstream: mustURL("http://127.0.0.1:1"), Dialect: OpenAIDialect}},
		mustAuth(t), redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler))
	tb := &tripBody{}
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", tb)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 || tb.read.Load() {
		t.Errorf("status %d, body read = %v", rec.Code, tb.read.Load())
	}
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

func mustAuth(t *testing.T) Authenticator {
	t.Helper()
	st, err := LoadStaticTokens(tokensFile(t, "a:"+HashToken(tokA)), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestServeUnknownPathIs404OnlyWhenAuthenticated(t *testing.T) {
	e := newServeEnv(t)
	r := post(t, e.px.URL+"/nosuch/v1/x", "", map[string]string{"X-Nospy-Token": tokA})
	if r.StatusCode != 404 {
		t.Errorf("authenticated unknown path: %d, want 404", r.StatusCode)
	}
}

func TestServePassthroughStripsProxyToken(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		hdr        map[string]string
	}{
		{"header", "/passanthropic/v1/messages", map[string]string{"X-Nospy-Token": tokA}},
		{"path", "/t/" + tokA + "/passanthropic/v1/messages", nil},
		{"both", "/t/" + tokA + "/passanthropic/v1/messages", map[string]string{"X-Nospy-Token": tokA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newServeEnv(t)
			hdr := map[string]string{"X-Api-Key": cliKey, "Authorization": "Bearer " + cliKey}
			for k, v := range tc.hdr {
				hdr[k] = v
			}
			r := post(t, e.px.URL+tc.path, messagesBody(false), hdr)
			clientText(t, r)
			calls := e.anth.recorded()
			if len(calls) != 1 {
				t.Fatalf("upstream calls = %d", len(calls))
			}
			c := calls[0]
			if c.hdr.Get("X-Api-Key") != cliKey || c.hdr.Get("Authorization") != "Bearer "+cliKey {
				t.Errorf("client's real key was not forwarded untouched: %v", c.hdr)
			}
			if c.hdr.Get("X-Nospy-Token") != "" || strings.Contains(c.path, "/t/") || strings.Contains(c.path, tokA) {
				t.Errorf("proxy token reached upstream: path %q, header %q", c.path, c.hdr.Get("X-Nospy-Token"))
			}
			if c.path != "/v1/messages" {
				t.Errorf("upstream path %q", c.path)
			}
			for k, vs := range c.hdr {
				for _, v := range vs {
					if strings.Contains(v, tokA) {
						t.Errorf("header %s carries the proxy token", k)
					}
				}
			}
			assertNoSecretInLogs(t, requestLogs(t, e.logs, 1), tokA, tokB, realKey, cliKey)
		})
	}
}

func assertNoSecretInLogs(t *testing.T, logs string, vals ...string) {
	t.Helper()
	for _, v := range vals {
		if strings.Contains(logs, v) {
			t.Errorf("logs contain a credential: %s", logs)
		}
	}
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain a secret value %q", s)
		}
	}
}

func TestServeInjectReplacesEveryClientCredential(t *testing.T) {
	e := newServeEnv(t)
	hdr := map[string]string{
		"X-Api-Key":     tokA, // the proxy token travels in the key header
		"Authorization": "Bearer " + cliKey,
		"Api-Key":       cliKey, "X-Goog-Api-Key": cliKey, "Proxy-Authorization": "Basic " + cliKey, "Cookie": "s=" + cliKey,
		"X-Nospy-Token": tokA,
	}
	clientText(t, post(t, e.px.URL+"/anthropic/v1/messages", messagesBody(false), hdr))
	calls := e.anth.recorded()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d", len(calls))
	}
	h := calls[0].hdr
	if h.Get("X-Api-Key") != realKey {
		t.Errorf("x-api-key = %q, want the injected key", h.Get("X-Api-Key"))
	}
	for _, n := range []string{"Authorization", "Api-Key", "X-Goog-Api-Key", "Proxy-Authorization", "Cookie", "X-Nospy-Token"} {
		if h.Get(n) != "" {
			t.Errorf("client credential header %s reached upstream: %q", n, h.Get(n))
		}
	}
	for k, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, tokA) || strings.Contains(v, cliKey) {
				t.Errorf("header %s carries a client credential: %q", k, v)
			}
		}
	}
	assertNoSecretInLogs(t, requestLogs(t, e.logs, 1), tokA, realKey, cliKey)
}

func TestServeInjectBearer(t *testing.T) {
	e := newServeEnv(t)
	hdr := map[string]string{"Authorization": "bearer " + tokB, "X-Api-Key": cliKey}
	clientText(t, post(t, e.px.URL+"/injectoai/v1/chat/completions", chatBody(false), hdr))
	calls := e.oai.recorded()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d", len(calls))
	}
	if got := calls[0].hdr.Get("Authorization"); got != "Bearer "+realKey {
		t.Errorf("Authorization = %q", got)
	}
	if calls[0].hdr.Get("X-Api-Key") != "" {
		t.Errorf("client x-api-key reached upstream")
	}
}

func TestServeLogsClientAndRoute(t *testing.T) {
	e := newServeEnv(t)
	clientText(t, post(t, e.px.URL+"/t/"+tokB+"/passanthropic/v1/messages", messagesBody(false), nil))
	post(t, e.px.URL+"/anthropic/v1/messages", messagesBody(false), map[string]string{"X-Api-Key": "bad"})
	logs := requestLogs(t, e.logs, 2)
	for _, want := range []string{`"client":"b"`, `"route":"/passanthropic"`, `"path":"/passanthropic/v1/messages"`, `"status":200`, `"status":401`, `"redacted"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s:\n%s", want, logs)
		}
	}
	assertNoSecretInLogs(t, logs, tokA, tokB, "/t/")
}

func TestServeChainsArePerClient(t *testing.T) {
	e := newServeEnv(t)
	url := e.px.URL + "/openai/v1/responses"
	ha, hb := map[string]string{"X-Nospy-Token": tokA}, map[string]string{"X-Nospy-Token": tokB}
	clientText(t, post(t, url, responsesBody(false, "", ""), ha)) // stores resp_1 for client a
	n := e.upstreamCalls()

	r := post(t, url, responsesBody(false, "resp_1", ""), hb)
	_ = r.Body.Close()
	if r.StatusCode != 409 {
		t.Errorf("client b continuing a's chain: %d, want 409", r.StatusCode)
	}
	if e.upstreamCalls() != n {
		t.Errorf("upstream called on a chain miss")
	}
	clientText(t, post(t, url, responsesBody(false, "resp_1", ""), ha)) // a itself still can

	// An expired entry is a 409 too.
	now := time.Now()
	e.chains.now = func() time.Time { return now }
	clientText(t, post(t, url, responsesBody(false, "", ""), ha)) // resp_3, stored at `now`
	now = now.Add(DefaultChainTTL + time.Second)
	r = post(t, url, responsesBody(false, "resp_3", ""), ha)
	_ = r.Body.Close()
	if r.StatusCode != 409 {
		t.Errorf("expired chain: %d, want 409", r.StatusCode)
	}
}

func TestHealthEndpointsNeedNoAuthAndTouchNoUpstream(t *testing.T) {
	e := newServeEnv(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		r, err := http.Get(e.px.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != 200 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	r := post(t, e.px.URL+"/healthz", "", nil)
	if r.StatusCode != 405 {
		t.Errorf("POST /healthz: %d, want 405", r.StatusCode)
	}
	if e.upstreamCalls() != 0 {
		t.Errorf("a health check reached an upstream")
	}
	r = post(t, e.px.URL+"/anthropic/v1/messages", messagesBody(false), nil)
	if r.StatusCode != 401 {
		t.Errorf("/anthropic without auth: %d, want 401", r.StatusCode)
	}
}

func TestReadyzFlipsWhenDraining(t *testing.T) {
	h := NewHealth(http.NotFoundHandler())
	h.SetReady(false)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 {
		t.Errorf("readyz while draining: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("healthz while draining: %d", rec.Code)
	}
}

func TestServeNoneAuth(t *testing.T) {
	var seen string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer up.Close()
	a, err := NewNoneAuth("127.0.0.1:8788")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	writeFile(t, keyPath, realKey)
	kf, _ := LoadKeyFile(keyPath, slog.New(slog.DiscardHandler))
	h, _ := NewServer([]Route{{Prefix: "/anthropic", Upstream: mustURL(up.URL), Dialect: AnthropicDialect,
		KeyMode: KeyInject, KeyHeader: "X-Api-Key", Key: kf.Get}}, a, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler))
	px := httptest.NewServer(h)
	defer px.Close()
	// No token at all, and the client's own key is replaced.
	r := post(t, px.URL+"/anthropic/v1/messages", `{"messages":[]}`, map[string]string{"X-Api-Key": cliKey})
	_ = r.Body.Close()
	if r.StatusCode != 200 || seen != realKey {
		t.Errorf("status %d, upstream key %q", r.StatusCode, seen)
	}
}

func TestNoneAuthIsLoopbackOnly(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8788": true, "[::1]:8788": true, "localhost:0": true, "127.1.2.3:1": true,
		":8788": false, "0.0.0.0:8788": false, "[::]:8788": false, "10.0.0.5:8788": false,
		"example.com:80": false, "nonsense": false, "": false,
	} {
		if got := IsLoopbackListen(addr); got != want {
			t.Errorf("IsLoopbackListen(%q) = %v", addr, got)
		}
		_, err := NewNoneAuth(addr)
		if (err == nil) != want {
			t.Errorf("NewNoneAuth(%q) err = %v", addr, err)
		}
	}
}

func TestNewServerValidation(t *testing.T) {
	ok := Route{Prefix: "/x", Upstream: mustURL("http://h"), Dialect: OpenAIDialect}
	a := mustAuth(t)
	if _, err := NewServer([]Route{ok}, nil, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler)); err == nil {
		t.Error("no authenticator accepted")
	}
	for _, rt := range []Route{
		{Prefix: "/t", Upstream: ok.Upstream, Dialect: OpenAIDialect},
		{Prefix: "/healthz", Upstream: ok.Upstream, Dialect: OpenAIDialect},
		{Prefix: "/metrics", Upstream: ok.Upstream, Dialect: OpenAIDialect},
		{Prefix: "/y", Upstream: ok.Upstream, Dialect: OpenAIDialect, KeyMode: KeyInject},
	} {
		if _, err := NewServer([]Route{rt}, a, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler)); err == nil {
			t.Errorf("route %+v accepted", rt.Prefix)
		}
	}
	// The wrapper has no key modes.
	if _, err := New([]Route{{Prefix: "/y", Upstream: ok.Upstream, Dialect: OpenAIDialect, KeyMode: KeyInject, KeyHeader: "X", Key: func() string { return "k" }}},
		"tok", redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler)); err == nil {
		t.Error("wrapper accepted an inject route")
	}
}

// --- the static-tokens file ---

func TestStaticTokensParse(t *testing.T) {
	h := HashToken("x")
	ok := "# comment\n\n  a:" + h + "  \nb-2:" + HashToken("y") + "\n"
	es, err := parseStaticTokens(strings.NewReader(ok))
	if err != nil || len(es) != 2 || es[0].name != "a" || es[1].name != "b-2" {
		t.Fatalf("got %v, %v", es, err)
	}
	raw := "nspy" + "_rawtokenpastedbymistake0123456789012345678"
	bad := strings.Join([]string{
		raw,                       // no colon: must not be echoed
		"A:" + h,                  // upper-case name
		"-x:" + h,                 // bad first char
		"c:zz",                    // not hex
		"d:" + h[:62],             // too short
		"e:" + HashToken("z"),     // fine
		"e:" + HashToken("w"),     // duplicate name
		"f:" + HashToken("z"),     // duplicate hash
		":" + HashToken("q"),      // empty name
		"g:",                      // empty hash
		"h:" + strings.ToUpper(h), // fine: upper-case hex is accepted
	}, "\n")
	_, err = parseStaticTokens(strings.NewReader(bad))
	if err == nil {
		t.Fatal("want errors")
	}
	msg := err.Error()
	if strings.Contains(msg, raw) || strings.Contains(msg, h) {
		t.Errorf("error echoes file content: %s", msg)
	}
	if n := len(flattenErrs(err)); n < 9 {
		t.Errorf("expected every bad line reported, got %d:\n%s", n, msg)
	}
	for _, want := range []string{"tokens line 1:", "tokens line 2:", "tokens line 4:", "duplicate name", "duplicate token hash"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

func flattenErrs(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

func TestStaticTokensLoadErrors(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	if _, err := LoadStaticTokens(filepath.Join(t.TempDir(), "missing"), log); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := LoadStaticTokens(tokensFile(t, "# nothing"), log); err == nil {
		t.Error("empty token file accepted")
	}
}

func TestStaticTokensAuthenticate(t *testing.T) {
	st, err := LoadStaticTokens(tokensFile(t, "a:"+HashToken(tokA)), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := st.Authenticate(nil, tokA); c != "a" || err != nil {
		t.Errorf("valid: %q %v", c, err)
	}
	for _, tok := range []string{"", tokB, tokA + "x", strings.ToUpper(tokA), HashToken(tokA)} {
		if c, err := st.Authenticate(nil, tok); err == nil || c != "" || !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%q: %q %v", tok, c, err)
		}
	}
}

func TestStaticTokensReload(t *testing.T) {
	var logs syncBuf
	p := tokensFile(t, "a:"+HashToken(tokA))
	st, err := LoadStaticTokens(p, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	bump := func() { // make the mtime differ even on coarse filesystems
		future := time.Now().Add(time.Duration(len(logs.String())+1) * time.Hour)
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
	}
	who := func(tok string) string { c, _ := st.Authenticate(nil, tok); return c }

	writeFile(t, p, "b:"+HashToken(tokB)+"\n") // rotation: a revoked, b added
	bump()
	if who(tokA) != "" || who(tokB) != "b" {
		t.Errorf("rotation not applied: a=%q b=%q", who(tokA), who(tokB))
	}

	writeFile(t, p, "this is not a tokens file\n") // a broken write keeps the last good set
	if err := os.Chtimes(p, time.Now().Add(100*time.Hour), time.Now().Add(100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if who(tokB) != "b" {
		t.Errorf("a bad file dropped the working tokens")
	}
	if !strings.Contains(logs.String(), "keeping the previous tokens") || strings.Contains(logs.String(), "this is not") {
		t.Errorf("reload failure log: %q", logs.String())
	}

	writeFile(t, p, "# everyone revoked\n") // a valid, empty file locks everyone out
	if err := os.Chtimes(p, time.Now().Add(200*time.Hour), time.Now().Add(200*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if who(tokB) != "" || st.Len() != 0 {
		t.Errorf("emptied file still authenticates")
	}
}

func TestKeyFile(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	for name, content := range map[string]string{"empty": "  \n", "multi": "a\nb\n"} {
		p := filepath.Join(dir, name)
		writeFile(t, p, content)
		if _, err := LoadKeyFile(p, log); err == nil {
			t.Errorf("%s key file accepted", name)
		}
	}
	if _, err := LoadKeyFile(filepath.Join(dir, "absent"), log); err == nil {
		t.Error("missing key file accepted")
	}
	p := filepath.Join(dir, "k")
	writeFile(t, p, " key-one \n")
	kf, err := LoadKeyFile(p, log)
	if err != nil || kf.Get() != "key-one" {
		t.Fatalf("%v %q", err, kf.Get())
	}
	writeFile(t, p, "key-two\n")
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	if kf.Get() != "key-two" {
		t.Errorf("rotation not applied: %q", kf.Get())
	}
	writeFile(t, p, "")
	if err := os.Chtimes(p, future.Add(time.Hour), future.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if kf.Get() != "key-two" {
		t.Errorf("a bad rewrite replaced the key: %q", kf.Get())
	}
}

// --- TLS files ---

// writeCert writes a throwaway self-signed certificate and its key, valid from notBefore to notAfter.
func writeCert(t *testing.T, dir, name string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	writeFile(t, certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})))
	return
}

func TestCertFiles(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	now := time.Now()
	cert, key := writeCert(t, dir, "good", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	cf, err := LoadCertFiles(cert, key, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := cf.GetCertificate(nil); err != nil || c == nil {
		t.Fatalf("%v", err)
	}

	// A key that doesn't belong to the certificate, an expired one, and a not-yet-valid one.
	_, otherKey := writeCert(t, dir, "other", now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := LoadCertFiles(cert, otherKey, log, nil); err == nil {
		t.Error("mismatched key accepted")
	}
	expCert, expKey := writeCert(t, dir, "expired", now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := LoadCertFiles(expCert, expKey, log, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired cert: %v", err)
	}
	futCert, futKey := writeCert(t, dir, "future", now.Add(time.Hour), now.Add(2*time.Hour))
	if _, err := LoadCertFiles(futCert, futKey, log, nil); err == nil {
		t.Error("not-yet-valid cert accepted")
	}
	junk := filepath.Join(dir, "junk")
	writeFile(t, junk, "not pem")
	if _, err := LoadCertFiles(junk, junk, log, nil); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCertFilesRotateWithoutRestart(t *testing.T) {
	var logs syncBuf
	dir := t.TempDir()
	now := time.Now()
	cert, key := writeCert(t, dir, "live", now.Add(-time.Hour), now.Add(24*time.Hour))
	cf, err := LoadCertFiles(cert, key, slog.New(slog.NewJSONHandler(&logs, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	first := cf.NotAfter()

	// Renewal writes a new pair in place (the path names stay).
	nc, nk := writeCert(t, dir, "renewed", now.Add(-time.Hour), now.Add(200*24*time.Hour))
	cb, _ := os.ReadFile(nc)
	kb, _ := os.ReadFile(nk)
	writeFile(t, cert, string(cb))
	writeFile(t, key, string(kb))
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(cert, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(key, future, future); err != nil {
		t.Fatal(err)
	}
	if !cf.NotAfter().After(first.Add(24 * time.Hour)) {
		t.Errorf("renewed certificate not picked up: %v -> %v", first, cf.NotAfter())
	}

	// A half-written renewal keeps serving the old one, and says so.
	writeFile(t, cert, "garbage")
	if err := os.Chtimes(cert, future.Add(time.Hour), future.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := cf.GetCertificate(&tls.ClientHelloInfo{}); err != nil || !cf.NotAfter().After(first.Add(24*time.Hour)) {
		t.Errorf("bad rewrite broke serving: %v", err)
	}
	if !strings.Contains(logs.String(), "keeping the previous certificate") {
		t.Errorf("no warning logged: %q", logs.String())
	}
}
