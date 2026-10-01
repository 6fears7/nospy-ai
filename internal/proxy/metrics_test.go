package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nospyai/internal/redact"
)

func setupMetrics(t *testing.T, upstream http.Handler, enabled bool) (*Metrics, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewNoneAuth("127.0.0.1:8788")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMetrics()
	var opts []Option
	if enabled {
		opts = append(opts, WithMetrics(m))
	}
	h, err := NewServer([]Route{{Prefix: "/anthropic", Upstream: u, Dialect: AnthropicDialect}}, auth,
		redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler), opts...)
	if err != nil {
		t.Fatal(err)
	}
	px := httptest.NewServer(NewHealth(h))
	t.Cleanup(px.Close)
	return m, px
}

func scrapeMetrics(t *testing.T, base string) string {
	t.Helper()
	r, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("scrape: status %d, type %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	return string(body)
}

func TestMetricsEndpointIsolation(t *testing.T) {
	var calls atomic.Int64
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			_, px := setupMetrics(t, upstream, enabled)
			for _, method := range []string{"GET", "HEAD", "POST"} {
				req, err := http.NewRequest(method, px.URL+"/metrics", nil)
				if err != nil {
					t.Fatal(err)
				}
				r, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(r.Body)
				_ = r.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				want := http.StatusNotFound
				if enabled {
					want = http.StatusOK
					if method == "POST" {
						want = http.StatusMethodNotAllowed
					}
				}
				if r.StatusCode != want || (method == "HEAD" && len(body) != 0) {
					t.Fatalf("%s enabled=%v: status %d, body %q", method, enabled, r.StatusCode, body)
				}
			}
			if enabled {
				before := scrapeMetrics(t, px.URL)
				for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
					r, err := http.Get(px.URL + path)
					if err != nil {
						t.Fatal(err)
					}
					_ = r.Body.Close()
				}
				if got := scrapeMetrics(t, px.URL); got != before {
					t.Fatal("scrapes or health probes changed application metrics")
				}
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("monitoring request reached an LLM upstream")
	}
}

func TestMetricsCountWorkAndHideRequestData(t *testing.T) {
	_, px := setupMetrics(t, &fakeUpstream{}, true)
	clientText := post(t, px.URL+"/anthropic/v1/messages", messagesBody(false), nil)
	_, err := io.Copy(io.Discard, clientText.Body)
	_ = clientText.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	// A client-chosen path and method must never become metric labels.
	req, err := http.NewRequest("PRIVATECANARY", px.URL+"/PRIVATECANARY", nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	body := scrapeMetrics(t, px.URL)
	for _, want := range []string{
		`nospy_http_requests_total{route="/anthropic",method="POST",status="200",handling="local"} 1`,
		`nospy_http_requests_total{route="unmatched",method="OTHER",status="404",handling="local"} 1`,
		`nospy_http_request_duration_seconds_count{route="/anthropic",handling="local"} 1`,
		`nospy_http_requests_in_flight 0`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("missing %q in scrape:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `nospy_redactions_total{route="/anthropic",kind="EMAIL"}`) {
		t.Fatal("redaction work not counted")
	}
	for _, forbidden := range []string{"PRIVATECANARY", "alice@corp.io", "hunter22", "10.0.0.5", "[REDACTED_", "client=", "path="} {
		if strings.Contains(body, forbidden) {
			t.Errorf("request data %q appeared in metrics", forbidden)
		}
	}
}

func TestMetricsObserveOpenStream(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, ": stream open\n\n")
		w.(http.Flusher).Flush()
		<-release
	})
	_, px := setupMetrics(t, upstream, true)
	r := post(t, px.URL+"/anthropic/v1/messages", messagesBody(true), nil)
	defer func() { _ = r.Body.Close() }()
	body := scrapeMetrics(t, px.URL)
	if !strings.Contains(body, "nospy_http_requests_in_flight 1\n") ||
		!strings.Contains(body, `nospy_redactions_total{route="/anthropic",kind="EMAIL"}`) {
		t.Fatalf("open stream's work not visible:\n%s", body)
	}
	if strings.Contains(body, `nospy_http_requests_total{route="/anthropic"`) {
		t.Fatal("open stream counted as a completed request")
	}
	once.Do(func() { close(release) })
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		t.Fatal(err)
	}
	body = scrapeMetrics(t, px.URL)
	if !strings.Contains(body, "nospy_http_requests_in_flight 0\n") ||
		!strings.Contains(body, `nospy_http_request_duration_seconds_count{route="/anthropic",handling="local"} 1`) {
		t.Fatalf("completed stream's work not visible:\n%s", body)
	}
}

func TestMetricsHistogramAndConcurrency(t *testing.T) {
	m := NewMetrics()
	const workers = 100
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			m.begin()
			m.redacted("/openai", map[string]int{"EMAIL": 2})
			m.finish("/openai", "POST", 502, true, 250*time.Millisecond)
			_ = m.exposition()
		})
	}
	wg.Wait()
	body := m.exposition()
	for _, want := range []string{
		`nospy_http_requests_in_flight 0`,
		`nospy_http_requests_total{route="/openai",method="POST",status="502",handling="forwarded"} 100`,
		`nospy_http_request_duration_seconds_bucket{route="/openai",handling="forwarded",le="0.1"} 0`,
		`nospy_http_request_duration_seconds_bucket{route="/openai",handling="forwarded",le="0.25"} 100`,
		`nospy_http_request_duration_seconds_bucket{route="/openai",handling="forwarded",le="+Inf"} 100`,
		`nospy_http_request_duration_seconds_sum{route="/openai",handling="forwarded"} 25`,
		`nospy_http_request_duration_seconds_count{route="/openai",handling="forwarded"} 100`,
		`nospy_redactions_total{route="/openai",kind="EMAIL"} 200`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("missing %q in scrape", want)
		}
	}
	if got := metricLabel("a\"b\\c\nd"); got != `"a\"b\\c\nd"` {
		t.Fatalf("invalid label escaping: %s", got)
	}
}
