# Metrics

[Back to the README](../README.md)

Metrics are on by default. Turn them off with `--metrics=false`.

| Mode | Where |
|---|---|
| `serve` | `GET /metrics` on the same listener |
| Wrap | `http://127.0.0.1:9464/metrics`. The port is fixed, so only one session can have it. Any other session still runs, just without metrics at that address, and prints a warning on stderr |

The format is [Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/). The listener's TLS and network access rules still apply.

| Metric | Measurement |
|---|---|
| `nospy_http_requests_total` | Finished proxy requests, by configured route, HTTP method, status and handling (`local` or `forwarded`). Includes rejected requests and upstream errors |
| `nospy_http_requests_in_flight` | Requests this process is handling right now, including open streams and peer forwarding |
| `nospy_http_request_duration_seconds` | A histogram of total request time, by route and handling. For streams it covers the whole stream, not just the time to the first token |
| `nospy_redactions_total` | Replacements made while preparing requests, by route and kind. Counted as soon as redaction finishes, even if the upstream fails later |

- With multiple replicas, scrape each pod. Filter request and latency queries to `handling="local"` so a forwarding replica's relay isn't counted as a second client request. Redactions are counted only where the redaction happens.

## Prometheus and Grafana

When scraping from same host:

```sh
nospy serve --auth none --route /openai=https://api.openai.com/v1
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: nospy
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:8788"]
```

Useful dashboard queries:

```promql
# Requests per second
sum(rate(nospy_http_requests_total{handling="local"}[5m]))

# HTTP 5xx responses per second
sum(rate(nospy_http_requests_total{handling="local",status=~"5.."}[5m]))

# Redactions per second by category
sum by (kind) (rate(nospy_redactions_total[5m]))

# 95th-percentile total request duration, by route
histogram_quantile(0.95, sum by (le, route) (rate(nospy_http_request_duration_seconds_bucket{handling="local"}[5m])))
```

A Grafana dashboard of redactions by kind is in [deploy/grafana/nospy-redactions.json](../deploy/grafana/nospy-redactions.json). Import it from Dashboards > New > Import.

In Helm, metrics are on unless you set `metrics.enabled=false`. In Service mode, scrapers must be allowed by `allowedClients`. Use `scheme: https` and the right CA if the Service uses TLS. A sidecar listens on loopback, so the scraper **must** run in the same pod.
