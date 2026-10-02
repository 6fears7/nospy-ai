package proxy

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var durationBuckets = [...]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}

type requestLabels struct{ route, method, status, handling string }
type durationLabels struct{ route, handling string }
type redactionLabels struct{ route, kind string }
type durationMetric struct {
	count   uint64
	sum     float64
	buckets [len(durationBuckets)]uint64
}

// Metrics collects per-process proxy activity. Labels contain only configured routes,
// redaction kinds, bounded methods/statuses and whether this replica forwarded the request.
// It never retains request paths, clients, credentials or redacted values.
type Metrics struct {
	mu         sync.Mutex
	inFlight   uint64
	requests   map[requestLabels]uint64
	durations  map[durationLabels]durationMetric
	redactions map[redactionLabels]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{
		requests: make(map[requestLabels]uint64), durations: make(map[durationLabels]durationMetric),
		redactions: make(map[redactionLabels]uint64),
	}
}

// WithMetrics enables GET /metrics and instrumentation on the proxy handler.
func WithMetrics(m *Metrics) Option { return func(h *handler) { h.metrics = m } }

func (m *Metrics) begin() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.inFlight++
	m.mu.Unlock()
}

func (m *Metrics) finish(route, method string, status int, forwarded bool, elapsed time.Duration) {
	if m == nil {
		return
	}
	if route == "-" {
		route = "unmatched"
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
	default:
		method = "OTHER" // arbitrary client methods must not create new time series
	}
	if status == 0 {
		status = http.StatusOK
	}
	code := "OTHER"
	if status >= 100 && status <= 599 {
		code = strconv.Itoa(status)
	}
	handling := "local"
	if forwarded {
		handling = "forwarded"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlight--
	m.requests[requestLabels{route, method, code, handling}]++
	key := durationLabels{route, handling}
	d := m.durations[key]
	seconds := elapsed.Seconds()
	d.count++
	d.sum += seconds
	for i, bound := range durationBuckets {
		if seconds <= bound {
			d.buckets[i]++
		}
	}
	m.durations[key] = d
}

func (m *Metrics) redacted(route string, counts map[string]int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for kind, n := range counts {
		if n > 0 {
			m.redactions[redactionLabels{route, kind}] += uint64(n)
		}
	}
}

var metricEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func metricLabel(value string) string { return `"` + metricEscaper.Replace(value) + `"` }

// exposition uses Prometheus text format 0.0.4. A single snapshot keeps histogram
// buckets, count and sum consistent; network writes happen after releasing the lock.
func (m *Metrics) exposition() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out strings.Builder // Builder writes cannot fail
	_, _ = fmt.Fprintf(&out, "# HELP nospy_http_requests_in_flight Proxy requests currently being handled by this process.\n# TYPE nospy_http_requests_in_flight gauge\nnospy_http_requests_in_flight %d\n", m.inFlight)
	_, _ = fmt.Fprint(&out, "# HELP nospy_http_requests_total Completed proxy requests, including rejections and upstream errors.\n# TYPE nospy_http_requests_total counter\n")
	keys := make([]requestLabels, 0, len(m.requests))
	for key := range m.requests {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b requestLabels) int {
		return strings.Compare(a.route+"\x00"+a.method+"\x00"+a.status+"\x00"+a.handling, b.route+"\x00"+b.method+"\x00"+b.status+"\x00"+b.handling)
	})
	for _, key := range keys {
		_, _ = fmt.Fprintf(&out, "nospy_http_requests_total{route=%s,method=%s,status=%s,handling=%s} %d\n",
			metricLabel(key.route), metricLabel(key.method), metricLabel(key.status), metricLabel(key.handling), m.requests[key])
	}
	_, _ = fmt.Fprint(&out, "# HELP nospy_http_request_duration_seconds Total proxy request duration, including the entire response stream.\n# TYPE nospy_http_request_duration_seconds histogram\n")
	dkeys := make([]durationLabels, 0, len(m.durations))
	for key := range m.durations {
		dkeys = append(dkeys, key)
	}
	slices.SortFunc(dkeys, func(a, b durationLabels) int {
		return strings.Compare(a.route+"\x00"+a.handling, b.route+"\x00"+b.handling)
	})
	for _, key := range dkeys {
		d := m.durations[key]
		labels := "route=" + metricLabel(key.route) + ",handling=" + metricLabel(key.handling)
		for i, bound := range durationBuckets {
			_, _ = fmt.Fprintf(&out, "nospy_http_request_duration_seconds_bucket{%s,le=\"%g\"} %d\n", labels, bound, d.buckets[i])
		}
		_, _ = fmt.Fprintf(&out, "nospy_http_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\nnospy_http_request_duration_seconds_sum{%s} %g\nnospy_http_request_duration_seconds_count{%s} %d\n", labels, d.count, labels, d.sum, labels, d.count)
	}
	_, _ = fmt.Fprint(&out, "# HELP nospy_redactions_total Redaction replacements made while preparing requests, counted on the replica doing the redaction. A value repeated in resent conversation history is counted on every request.\n# TYPE nospy_redactions_total counter\n")
	rkeys := make([]redactionLabels, 0, len(m.redactions))
	for key := range m.redactions {
		rkeys = append(rkeys, key)
	}
	slices.SortFunc(rkeys, func(a, b redactionLabels) int {
		return strings.Compare(a.route+"\x00"+a.kind, b.route+"\x00"+b.kind)
	})
	for _, key := range rkeys {
		_, _ = fmt.Fprintf(&out, "nospy_redactions_total{route=%s,kind=%s} %d\n", metricLabel(key.route), metricLabel(key.kind), m.redactions[key])
	}
	return out.String()
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	// G705 is a false positive: the body is text/plain and label values are escaped by metricLabel.
	_, _ = fmt.Fprint(w, m.exposition()) //nolint:gosec
}
