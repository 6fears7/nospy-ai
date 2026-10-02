# nospy

![NoSpy logo with a ghost in place of the O](images/nospy-logo-ghost-o.svg)

`nospy` is a forward proxy that sits between an AI agent and its API. It swaps secrets and personal data in your requests for placeholders, and puts the values back in the response. 


## Architecture overview

### Wrap mode

![nospy wrapping an agent: the agent talks to nospy on 127.0.0.1, which replaces DB_PASSWORD=hunter2hunter2 with a placeholder before the request goes to the LLM API over HTTPS, and restores the value in the response](images/cli-flow.svg)

`nospy` starts a proxy on a random local port and runs your agent with its base URL pointed at the proxy. See [Wrap mode](docs/wrap.md).

```bash
nospy -- claude
```

### Serve mode

![nospy serve with two clients: each client sends requests with its unique token in X-Nospy-Token, nospy checks the token, redacts the request, routes by path prefix (/anthropic or /openai) and sends it to that LLM API over HTTPS, then restores placeholders in the response; routes and auth are set by flags at startup, and /healthz and /metrics are also served](images/serve-flow.svg)

`nospy serve` runs as a long-lived proxy for several clients, each authenticated by `--auth` and serving routes listed with `--route`. `Container` and `Kubernetes` modes run via `serve` . See [Serve mode](docs/serve.md).

```bash
nospy serve --auth none --listen 127.0.0.1:8788 --route /anthropic=https://api.anthropic.com
```

### Kubernetes sidecar

![nospy as a sidecar: inside one pod the app container talks to nospy on 127.0.0.1:8788, nospy sends redacted requests to the LLM API over HTTPS, an optional key Secret is mounted into nospy only, and other pods cannot reach the loopback port](images/k8s-sidecar.svg)

`nospy` runs next to your app in the same pod as a sidecar. See [Kubernetes](docs/kubernetes.md#sidecar).

### Kubernetes shared Service

![nospy as a shared Service with three replicas: client pods reach the ClusterIP Service through the NetworkPolicy, replica A authenticates the request and forwards it to the owner replica B, which redacts, calls the LLM API and streams the response back through A; a headless peers Service lists every ready replica](images/k8s-service.svg)

Each client is assigned to one replica (the "owner"), which holds its conversation state. If a request is sent to another replica, that replica checks and forwards it to the owner. See [Kubernetes](docs/kubernetes.md#shared-service) and [multiple replicas](docs/serve.md#multiple-replicas).

## Pick a mode

| Mode | Use it to | Example |
|---|---|---|
| [Wrap](docs/wrap.md) | Run one agent on your machine behind `nospy` | `nospy -- claude` |
| [Scan](docs/scan.md) | Redact a file or text and print the result | `nospy scan notes.md` |
| [Serve](docs/serve.md) | Run as proxy | `nospy serve --auth none --provider ollama` |
| [Container](docs/container.md) | Run `serve` in Podman | `podman run ... nospy:dev` |
| [Kubernetes](docs/kubernetes.md) | Run `serve` as a sidecar or shared Service | `helm install nospy deploy/helm/nospy` |


## Dashboard

![Grafana dashboard showing redactions by kind: totals, a bar gauge and donut chart per kind, redactions per second over time, a kind by route table, requests per second and 5xx rate](images/grafana-dashboard.png)

`nospy` exposes [Prometheus metrics](docs/metrics.md), including `nospy_redactions_total` by route and kind (`EMAIL`, `TOKEN`, etc...). 

Get the Grafana dashboard here: [nospy-redactions.json](deploy/grafana/nospy-redactions.json).

## Install

Download a binary from the [releases page](../../releases), and check it against `SHA256SUMS` (each file also has a build provenance attestation: `gh attestation verify <file> --repo 6fears7/nospy-ai`). 

### MacOS
The macOS binaries are not signed at this time. You will need to clear the quarantine flag after download to run the app: `xattr -d com.apple.quarantine nospy`. 

To pull the container image / Helm chart:

```
podman pull ghcr.io/6fears7/nospy-ai:<version>
helm install nospy oci://ghcr.io/6fears7/charts/nospy-ai --version <version>
```

To build from source, you need Go 1.27 (standard library only).

```
go build -o nospy ./cmd/nospy      # or: go install ./cmd/nospy
```



## More documentation

- [How it works](docs/how-it-works.md): placeholders, detection, remembered values
- [Custom terms](docs/custom-terms.md): adding personal words and patterns
- [Metrics](docs/metrics.md): Prometheus metrics
- [Commands](docs/commands.md): all `nospy` commands
- [Known limitations](docs/limitations.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
