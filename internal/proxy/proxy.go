// Package proxy is the reverse proxy between an agent and an LLM API: it redacts request
// bodies before they go upstream and restores values in responses.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nospyai/internal/payload"
	"nospyai/internal/redact"
)

const maxBody = 32 << 20

// Route forwards requests under Prefix to Upstream.
type Route struct {
	Prefix   string // "/anthropic", "/openai"
	Upstream *url.URL
	// Dialect resolves an API path (route prefix stripped, e.g. "/v1/messages") to the
	// dialect its bodies are redacted with; false means the endpoint is unsupported.
	Dialect func(path string) (payload.Dialect, bool)

	// KeyMode is the route's key mode (serve mode only; the wrapper's routes are all passthrough).
	KeyMode KeyMode
	// KeyHeader, KeyScheme and Key describe the credential of a KeyInject route: the proxy token
	// arrives in header KeyHeader (as "<KeyScheme> <token>" when KeyScheme is set, e.g. "Bearer"),
	// and the real upstream key returned by Key() is sent in the same header.
	KeyHeader string
	KeyScheme string
	Key       func() string

	// ExtraHeaders names client request headers forwarded on this route in addition to the
	// header allowlist (headers.go), from the provider table.
	ExtraHeaders []string
}

// AnthropicDialect resolves Messages API paths.
func AnthropicDialect(path string) (payload.Dialect, bool) {
	switch path {
	case "/v1/messages", "/v1/messages/count_tokens":
		return payload.Anthropic, true
	}
	return payload.Dialect{}, false
}

// OpenAIDialect resolves the OpenAI API paths: Chat Completions, Responses and Embeddings
// (only "input" carries text, and the response is vectors, so the Chat rules fit).
func OpenAIDialect(path string) (payload.Dialect, bool) {
	switch path {
	case "/v1/chat/completions", "/v1/embeddings":
		return payload.OpenAIChat, true
	case "/v1/responses":
		return payload.OpenAIResponses, true
	}
	return payload.Dialect{}, false
}

type route struct {
	Route
	rp *httputil.ReverseProxy
}

type handler struct {
	token  []byte        // wrapper mode: the leading /<token> path segment; nil in serve mode
	auth   Authenticator // serve mode: identifies the client; nil in wrapper mode
	routes []route
	det    *redact.Detector
	log    *slog.Logger
	chains *ChainStore
	known  *KnownStore
	peers  *Peers                     // serve mode with replicas: forwards a request to its client's owner pod; nil otherwise
	client func(*http.Request) string // wrapper mode only; serve mode uses the authenticated client
	// userAgent replaces the client's User-Agent upstream (headers.go).
	userAgent string
	metrics   *Metrics // nil unless monitoring is enabled
}

// Option configures New.
type Option func(*handler)

// WithChainStore sets the store that carries Responses vaults across requests. The default is
// a store with the package defaults.
func WithChainStore(cs *ChainStore) Option { return func(h *handler) { h.chains = cs } }

// WithKnownStore sets the per-client store of values that were redacted before (layer 2 of
// plan/19-known-values.md). The default is a store with the package defaults.
func WithKnownStore(ks *KnownStore) Option { return func(h *handler) { h.known = ks } }

// WithPeers makes a serve-mode handler forward each authenticated request to the replica that owns
// its client (plan/21-client-affinity.md). The default is none: every request is served locally.
func WithPeers(p *Peers) Option { return func(h *handler) { h.peers = p } }

// WithClient names who sent a request; it scopes the chain store. The default is "local" for
// every request (wrapper mode, where there is one client). Serve mode ignores it: the client is
// whoever the Authenticator says.
func WithClient(f func(*http.Request) string) Option { return func(h *handler) { h.client = f } }

// WithUserAgent sets the User-Agent sent upstream in place of the client's, e.g. "nospy/1.2.3".
// The default is "nospy".
func WithUserAgent(ua string) Option { return func(h *handler) { h.userAgent = ua } }

// reqState travels in the request context from the redacting handler to ModifyResponse.
type reqState struct {
	dialect payload.Dialect
	vault   *redact.Vault
	record  func(id string) // stores the vault under the response id; nil unless the dialect chains
}

type ctxKey struct{}

// New returns the wrapper's handler, serving /<token>/<route prefix>/... The random path token is
// the wrapper's only credential (invariant 10) and every route is passthrough. Each request gets
// its own vault.
func New(routes []Route, token string, det *redact.Detector, log *slog.Logger, opts ...Option) (http.Handler, error) {
	if token == "" || strings.Contains(token, "/") {
		return nil, errors.New("proxy: token must be non-empty and contain no '/'")
	}
	h := newHandler(det, log, opts)
	h.token = []byte(token)
	for _, rt := range routes {
		if rt.KeyMode != KeyPassthrough {
			return nil, fmt.Errorf("proxy: route %s: the wrapper supports only passthrough routes", rt.Prefix)
		}
	}
	if err := h.addRoutes(routes, false); err != nil {
		return nil, err
	}
	return h, nil
}

// NewServer returns the serve-mode handler. Every request is authenticated by auth, with the
// credential its route's key mode designates, before its body is read; requests that fail get
// 401 and never reach an upstream. Clients name a route as /<prefix>/..., optionally behind a
// /t/<token> path prefix (passthrough routes only).
func NewServer(routes []Route, auth Authenticator, det *redact.Detector, log *slog.Logger, opts ...Option) (http.Handler, error) {
	if auth == nil {
		return nil, errors.New("proxy: an Authenticator is required")
	}
	h := newHandler(det, log, opts)
	h.auth = auth
	if err := h.addRoutes(routes, true); err != nil {
		return nil, err
	}
	return h, nil
}

func newHandler(det *redact.Detector, log *slog.Logger, opts []Option) *handler {
	h := &handler{det: det, log: log,
		chains: NewChainStore(0, 0), known: NewKnownStore(0, 0), userAgent: "nospy", client: func(*http.Request) string { return "local" }}
	for _, o := range opts {
		o(h)
	}
	return h
}

// reservedPrefixes can't be route prefixes in serve mode: they are the monitoring endpoints and
// the path-token prefix.
var reservedPrefixes = map[string]bool{"/t": true, "/healthz": true, "/readyz": true, "/metrics": true}

func (h *handler) addRoutes(routes []Route, serve bool) error {
	seen := map[string]bool{}
	for _, rt := range routes {
		if !strings.HasPrefix(rt.Prefix, "/") || strings.HasSuffix(rt.Prefix, "/") || strings.Count(rt.Prefix, "/") != 1 {
			return fmt.Errorf("proxy: route prefix %q must be a single path segment like /anthropic", rt.Prefix)
		}
		if serve && reservedPrefixes[rt.Prefix] {
			return fmt.Errorf("proxy: route prefix %q is reserved", rt.Prefix)
		}
		if u := rt.Upstream; u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("proxy: route %s: upstream must be an absolute http(s) URL", rt.Prefix)
		}
		if rt.KeyMode == KeyInject && (rt.KeyHeader == "" || rt.Key == nil) {
			return fmt.Errorf("proxy: route %s: key-mode inject needs a key header and a key", rt.Prefix)
		}
		if seen[rt.Prefix] {
			return fmt.Errorf("proxy: route prefix %q given twice", rt.Prefix)
		}
		seen[rt.Prefix] = true
		h.routes = append(h.routes, route{Route: rt, rp: h.reverseProxy(&rt)})
	}
	return nil
}

func (h *handler) reverseProxy(rt *Route) *httputil.ReverseProxy {
	up, userAgent := rt.Upstream, h.userAgent
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = up.Host
			pr.Out.Header = rt.outboundHeader(pr.In.Header, userAgent)
		},
		FlushInterval:  -1,
		ModifyResponse: modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err // drop the URL: its query is not ours to log
			}
			h.log.Warn("upstream error", "err", err)
			http.Error(w, "nospy: upstream request failed", http.StatusBadGateway)
		},
	}
}

func modifyResponse(resp *http.Response) error {
	st, ok := resp.Request.Context().Value(ctxKey{}).(*reqState)
	if !ok {
		return errors.New("proxy: request state missing")
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return nil // an encoding we didn't ask for: can't restore, placeholders pass through
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	// The ChatGPT Codex backend can omit Content-Type on Responses SSE replies.
	// Recognize its event prefix without consuming bytes or buffering the full stream.
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") == "" && st.dialect.Name == payload.OpenAIResponses.Name {
		const prefix = "event: response."
		br := bufio.NewReader(resp.Body)
		start, _ := br.Peek(len(prefix))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{br, resp.Body}
		if string(start) == prefix {
			mt = "text/event-stream"
			resp.Header.Set("Content-Type", mt)
		}
	}
	record := st.record
	if resp.StatusCode != http.StatusOK {
		record = nil // an error has no response to continue from
	}
	switch mt {
	case "text/event-stream":
		resp.Body = payload.NewSSERestorerWith(st.dialect, resp.Body, st.vault, record)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	case "application/json":
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if record != nil {
			if id := payload.ResponseID(body); id != "" {
				record(id)
			}
		}
		if out, err := payload.RestoreResponse(st.dialect, body, st.vault); err == nil {
			body = out
		} // invalid JSON: forward as is; placeholders reaching the client leak nothing
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return nil
}

// reqInfo is what one request may log: who, which route, the path without any token, and
// redaction counts per kind. Never values.
type reqInfo struct {
	client, route, path string
	counts              map[string]int
	peer                string // the owner's IP, while the request is forwarded
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.metrics != nil && r.URL.Path == "/metrics" {
		h.metrics.ServeHTTP(w, r)
		return
	}
	start := time.Now()
	h.metrics.begin()
	sw := &statusWriter{ResponseWriter: w}
	info := &reqInfo{client: "-", route: "-", path: "-"}
	defer func() {
		duration := time.Since(start)
		h.metrics.finish(info.route, r.Method, sw.status, info.peer != "", duration)
		attrs := []any{"client", info.client, "route", info.route, "method", r.Method, "path", info.path,
			"status", sw.status, "dur", duration.Round(time.Millisecond)}
		if info.peer != "" {
			attrs = append(attrs, "peer", info.peer) // the owner logs the counts
		} else {
			attrs = append(attrs, "redacted", info.counts)
		}
		h.log.Info("request", attrs...)
	}()
	h.serve(sw, w, r, info)
}

// serve handles one request. Nothing is forwarded unless every check passes, and nothing reads
// the body before the client is authenticated.
func (h *handler) serve(sw *statusWriter, w http.ResponseWriter, r *http.Request, info *reqInfo) {
	var rest, pathToken string
	if h.auth == nil { // wrapper: the leading path segment is the credential
		var ok bool
		if rest, ok = h.stripToken(r.URL.Path); !ok {
			http.NotFound(sw, r)
			return
		}
		info.client = h.client(r)
	} else {
		rest, pathToken = splitPathToken(r.URL.Path)
	}
	info.path = rest
	rt, apiPath, ok := h.match(rest)
	if !ok {
		// In serve mode an unknown path is 404 only for a client that could have been
		// authenticated, so unauthenticated probes learn nothing about the routes.
		if h.auth != nil && !h.anyCredentialWorks(r, pathToken) {
			unauthenticated(sw)
			return
		}
		http.NotFound(sw, r)
		return
	}
	info.route = rt.Prefix
	if h.auth != nil {
		client, err := h.authenticate(r, rt, pathToken)
		if err != nil {
			unauthenticated(sw)
			return
		}
		info.client = client
	}
	client := info.client
	if r.Header.Get("Upgrade") != "" || headerHasToken(r.Header, "Connection", "upgrade") {
		http.Error(sw, "nospy: protocol upgrades are not supported", http.StatusBadRequest)
		return
	}
	if ce := r.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		http.Error(sw, "nospy: compressed request bodies are not supported", http.StatusUnsupportedMediaType)
		return
	}
	// Affinity: the client's known values and Responses chains live in the owner replica, so hand
	// the request over before its body is read. A request that came from a peer is served here.
	if h.peers != nil && r.Header.Get(PeerHeader) == "" {
		if ip, ok := h.peers.Owner(client, rt.Prefix); ok {
			info.peer = ip
			if h.peers.forward(sw, r, ip) {
				return
			}
			info.peer = ""
		}
	}
	// w, not sw: MaxBytesReader closes the connection on overflow via the server's writer.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(sw, "nospy: request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(sw, "nospy: reading request body failed", http.StatusBadRequest)
		}
		return
	}

	// An unsupported endpoint gets the zero dialect: restoring its responses is a no-op
	// walk, and it can only be reached without a body.
	d, known := rt.Dialect(apiPath)
	st := &reqState{dialect: d, vault: redact.NewVault()}
	if len(body) > 0 {
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if !known || mt != "application/json" {
			http.Error(sw, "nospy: unsupported endpoint or content type", http.StatusUnsupportedMediaType)
			return
		}
		if d.ChainKey != "" {
			ref, err := payload.ChainRef(d, body)
			if err != nil {
				http.Error(sw, "nospy: request body is not valid JSON", http.StatusBadRequest)
				return
			}
			if ref != "" {
				prev, ok := h.chains.Get(client, rt.Prefix, ref)
				if !ok {
					// Continuing with a fresh vault would reuse placeholder numbers for different
					// values and restore the wrong one, so the conversation must restart.
					chainMissing(sw, d.ChainKey)
					return
				}
				st.vault = prev
			}
			vault, prefix := st.vault, rt.Prefix
			st.record = func(id string) { h.chains.Put(client, prefix, id, vault) }
		}
		red := redact.NewRedactor(h.det, st.vault).WithKnown(h.known.Matcher(client, rt.Prefix))
		body, info.counts, err = payload.RedactRequest(d, body, red)
		if err != nil {
			http.Error(sw, "nospy: request body is not valid JSON", http.StatusBadRequest)
			return
		}
		h.known.Add(client, rt.Prefix, red.Found())
		h.metrics.redacted(rt.Prefix, info.counts)
	}

	out := r.Clone(context.WithValue(r.Context(), ctxKey{}, st))
	out.URL.Path, out.URL.RawPath = forwardPath(rt.Upstream, apiPath), ""
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.TransferEncoding = nil
	out.Header.Set("Content-Length", strconv.Itoa(len(body)))
	if len(body) == 0 {
		out.Body = http.NoBody
		out.Header.Del("Content-Length")
	}
	rt.rp.ServeHTTP(sw, out)
}

// chainMissing answers a request that continues a conversation nospy has no state for, with an
// error shaped like OpenAI's so clients surface the message.
func chainMissing(w http.ResponseWriter, param string) {
	body, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": "nospy cannot continue this conversation: it has no redaction state for " + param +
			" (nospy restarted, the entry expired, or it belongs to another client). Restart the conversation without " + param + ".",
		"type":  "invalid_request_error",
		"param": param,
		"code":  "nospy_chain_not_found",
	}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_, _ = w.Write(body)
}

// stripToken removes the leading /<token> segment, comparing in constant time.
func (h *handler) stripToken(p string) (string, bool) {
	tok, rest, found := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if !found || subtle.ConstantTimeCompare([]byte(tok), h.token) != 1 {
		return "", false
	}
	return "/" + rest, true
}

func (h *handler) match(p string) (*route, string, bool) {
	for i := range h.routes {
		rt := &h.routes[i]
		if p == rt.Prefix || strings.HasPrefix(p, rt.Prefix+"/") {
			api := strings.TrimPrefix(p, rt.Prefix)
			if api == "" {
				api = "/"
			}
			return rt, api, true
		}
	}
	return nil, "", false
}

// forwardPath avoids /v1/v1 when both the upstream (https://api.openai.com/v1) and the
// client's path (/v1/chat/completions) carry the version. SetURL joins the rest.
func forwardPath(up *url.URL, api string) string {
	if strings.HasSuffix(strings.TrimSuffix(up.Path, "/"), "/v1") && (api == "/v1" || strings.HasPrefix(api, "/v1/")) {
		return strings.TrimPrefix(api, "/v1")
	}
	return api
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for t := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// statusWriter records the response status for the log line. Unwrap lets
// http.ResponseController reach the real writer's Flush for SSE.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
