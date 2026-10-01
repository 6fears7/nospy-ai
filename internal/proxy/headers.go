package proxy

import "net/http"

// Outbound header policy (invariant 11, plan/12-identity.md). Request headers fingerprint the
// user's machine and account: SDK, OS, architecture and runtime versions (x-stainless-*), the
// agent name, session and request ids, organization and project ids. So nothing is forwarded
// unless it is listed here; everything else is dropped, and User-Agent is nospy's own.

// forwardedHeaders pass through on every route, in canonical form.
var forwardedHeaders = []string{
	"Content-Type", "Accept", // the body's format; every API needs them
	"Anthropic-Version", // required by the Messages API
	"Anthropic-Beta",    // feature flags: Claude Code breaks without them (OAuth, interleaved thinking, ...)
	"Openai-Beta",       // feature flags, e.g. the Assistants/Realtime versions
}

// credentialHeaders are the headers a client puts its real API key in. A passthrough route
// forwards whichever the request carries; an inject route never forwards either, because it
// sets its own key header instead.
var credentialHeaders = []string{"X-Api-Key", "Authorization"}

// outboundHeader builds the upstream request's headers from the client's. The proxy token
// (TokenHeader), cookies, proxy credentials, tracing and every header not listed above are not
// copied, so there is nothing to strip and a new fingerprinting header is dropped by default.
// Content-Length is not copied either: the transport sets it from the request's ContentLength.
// Accept-Encoding is not copied, so the transport negotiates gzip itself and ModifyResponse
// always sees plaintext.
func (rt *Route) outboundHeader(in http.Header, userAgent string) http.Header {
	out := http.Header{"User-Agent": {userAgent}}
	copyHeaders := func(names []string) {
		for _, n := range names {
			if vs, ok := in[http.CanonicalHeaderKey(n)]; ok {
				out[http.CanonicalHeaderKey(n)] = append([]string(nil), vs...)
			}
		}
	}
	copyHeaders(forwardedHeaders)
	copyHeaders(rt.ExtraHeaders)
	if rt.KeyMode == KeyInject {
		// The client's credentials are never forwarded: the real key replaces them.
		v := rt.Key()
		if rt.KeyScheme != "" {
			v = rt.KeyScheme + " " + v
		}
		out.Set(rt.KeyHeader, v)
	} else {
		copyHeaders(credentialHeaders)
	}
	delete(out, TokenHeader) // even if a route lists it in ExtraHeaders
	delete(out, PeerHeader)  // likewise: it is for the next replica, never for an upstream
	return out
}
