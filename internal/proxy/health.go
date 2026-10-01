package proxy

import (
	"net/http"
	"sync/atomic"
)

// Health wraps next with the unauthenticated GET /healthz (liveness) and /readyz (readiness)
// endpoints. They read no body and never touch an upstream. /readyz answers 503 once SetReady(false)
// is called, so a draining instance leaves the Service's endpoints before it stops.
type Health struct {
	next  http.Handler
	ready atomic.Bool
}

// NewHealth returns the wrapper; it starts ready.
func NewHealth(next http.Handler) *Health {
	h := &Health{next: next}
	h.ready.Store(true)
	return h
}

// SetReady switches /readyz between 200 and 503.
func (h *Health) SetReady(ok bool) { h.ready.Store(ok) }

func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz", "/readyz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.URL.Path == "/readyz" && !h.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("shutting down\n"))
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	default:
		h.next.ServeHTTP(w, r)
	}
}
