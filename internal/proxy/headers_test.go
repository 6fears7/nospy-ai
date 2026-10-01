package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"nospyai/internal/redact"
)

// identityHeaders fingerprint the user, the machine or the session; none may go upstream.
var identityHeaders = map[string]string{
	"X-App": "cli", "X-Stainless-Os": "MacOS", "X-Stainless-Arch": "arm64", "X-Stainless-Lang": "js",
	"X-Stainless-Runtime": "node", "X-Stainless-Runtime-Version": "v24.3.0", "X-Stainless-Package-Version": "0.80.0",
	"X-Stainless-Retry-Count": "0", "X-Stainless-Timeout": "600", "X-Claude-Code-Session-Id": "sess-1",
	"X-Request-Id": "req-1", "Openai-Organization": "org-acme", "Openai-Project": "proj-1",
	"Cookie": "s=1", "Proxy-Authorization": "Basic x", "Traceparent": "00-abc-def-01", "X-Forwarded-For": "10.1.2.3",
	"Accept-Language": "en-GB", "Referer": "https://corp.internal/", "Anthropic-Dangerous-Direct-Browser-Access": "true",
	"Api-Key": "k", "X-Goog-Api-Key": "k",
}

func sortedNames(h http.Header) string {
	var ns []string
	for n := range h {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return strings.Join(ns, ",")
}

func TestOutboundHeadersAreAnAllowlist(t *testing.T) {
	fu := &fakeUpstream{}
	up := httptest.NewServer(fu)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h, err := New([]Route{{Prefix: "/anthropic", Upstream: u, Dialect: AnthropicDialect,
		ExtraHeaders: []string{"http-referer", "X-Title", TokenHeader, PeerHeader}}},
		testToken, redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler), WithUserAgent("nospy/1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	px := httptest.NewServer(h)
	t.Cleanup(px.Close)

	hdr := map[string]string{
		"Accept": "application/json", "Accept-Encoding": "br", "User-Agent": "claude-cli/2.1.285 (external, cli)",
		"Anthropic-Version": "2023-06-01", "Anthropic-Beta": "oauth-2025-04-20,interleaved-thinking-2025-05-14",
		"Openai-Beta": "responses=v1", "X-Api-Key": cliKey, "Authorization": "Bearer " + cliKey,
		"Http-Referer": "https://app.example", "X-Title": "My App", "X-Nospy-Token": "tok", PeerHeader: "1",
	}
	for k, v := range identityHeaders {
		hdr[k] = v
	}
	clientText(t, post(t, px.URL+"/"+testToken+"/anthropic/v1/messages", messagesBody(false), hdr))
	calls := fu.recorded()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d", len(calls))
	}
	got := calls[0].hdr
	if ae := got.Get("Accept-Encoding"); ae != "gzip" { // the transport's own, not the client's "br"
		t.Errorf("Accept-Encoding = %q", ae)
	}
	got.Del("Accept-Encoding")
	want := "Accept,Anthropic-Beta,Anthropic-Version,Authorization,Content-Length,Content-Type,Http-Referer,Openai-Beta,User-Agent,X-Api-Key,X-Title"
	if names := sortedNames(got); names != want {
		t.Errorf("upstream headers\n got  %s\n want %s", names, want)
	}
	if got.Get("User-Agent") != "nospy/1.2.3" {
		t.Errorf("User-Agent = %q", got.Get("User-Agent"))
	}
	if got.Get("X-Api-Key") != cliKey || got.Get("Authorization") != "Bearer "+cliKey {
		t.Errorf("both credential headers must pass on a passthrough route: %v", got)
	}
	if got.Get("Anthropic-Beta") != hdr["Anthropic-Beta"] || got.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("anthropic headers changed: %v", got)
	}
	if got.Get("Http-Referer") != "https://app.example" || got.Get("X-Title") != "My App" {
		t.Errorf("ExtraHeaders not forwarded: %v", got)
	}
	for _, n := range []string{"X-App", "X-Stainless-Os", "Openai-Organization", "X-Nospy-Token", PeerHeader, "Cookie"} {
		if got.Get(n) != "" {
			t.Errorf("%s reached upstream", n)
		}
	}
}

// Without the client's User-Agent or any WithUserAgent option, the upstream still never sees the
// client's (and never Go's default).
func TestOutboundUserAgentDefault(t *testing.T) {
	fu, px := setup(t, "")
	clientText(t, post(t, px.URL+"/"+testToken+"/anthropic/v1/messages", messagesBody(false),
		map[string]string{"User-Agent": "claude-cli/2.1.285"}))
	if ua := fu.recorded()[0].hdr.Get("User-Agent"); ua != "nospy" {
		t.Errorf("User-Agent = %q", ua)
	}
}

// Inject routes forward no client credential, and no identity header either.
func TestInjectRouteSendsOnlyTheInjectedCredential(t *testing.T) {
	e := newServeEnv(t)
	hdr := map[string]string{"X-Api-Key": tokA, "Authorization": "Bearer " + cliKey, "Anthropic-Version": "2023-06-01",
		"Accept": "application/json", "User-Agent": "claude-cli/2.1.285"}
	for k, v := range identityHeaders {
		hdr[k] = v
	}
	clientText(t, post(t, e.px.URL+"/anthropic/v1/messages", messagesBody(false), hdr))
	calls := e.anth.recorded()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d", len(calls))
	}
	got := calls[0].hdr
	if ae := got.Get("Accept-Encoding"); ae != "gzip" { // the transport's own, not the client's "br"
		t.Errorf("Accept-Encoding = %q", ae)
	}
	got.Del("Accept-Encoding")
	want := "Accept,Anthropic-Version,Content-Length,Content-Type,User-Agent,X-Api-Key"
	if names := sortedNames(got); names != want {
		t.Errorf("upstream headers\n got  %s\n want %s", names, want)
	}
	if got.Get("X-Api-Key") != realKey || !strings.HasPrefix(got.Get("User-Agent"), "nospy") {
		t.Errorf("headers: %v", got)
	}
}
