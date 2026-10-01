# Serve mode: long-running proxy

[Back to the README](../README.md)

```
nospy serve [flags]
```

`serve` runs as an active listener. It differs from wrap mode in three ways:

- It serves only the routes you list. There is no implicit `/anthropic` or `/openai`.
- It ignores `*_BASE_URL` env vars.
- It is configured with flags only, no config file.

## Flags

| Flag | Meaning |
|---|---|
| `--listen HOST:PORT` | Address to listen on (default `127.0.0.1:8788`) |
| `--auth none\|static-tokens` | Required. `none` only works on loopback, and every client is named `local` |
| `--tokens-file FILE` | `name:sha256hex` lines for `static-tokens`. Reloaded when the file changes |
| `--tls-cert FILE`, `--tls-key FILE` | TLS certificate and key. Reloaded when the files change |
| `--insecure-plaintext` | Allow plain HTTP on a non-loopback address |
| `--route PREFIX=URL[,api=...][,key-mode=passthrough\|inject,key-file=FILE]` | Add a route. Repeatable |
| `--provider NAME` | Add a built-in provider as a passthrough route. Repeatable |
| `--terms FILE` | A [custom terms](custom-terms.md) file (read once at startup) |
| `--metrics=false` | Turn off [metrics](metrics.md) (on by default at `GET /metrics`) |
| `--chain-ttl DUR` | How long conversation and [remembered-value](how-it-works.md#remembered-values) state is kept |
| `--chain-max N` | Most conversations kept in memory |
| `--shutdown-timeout DUR` | Time to finish open requests on SIGTERM/SIGINT (default `30s`) |
| `--peers HOST:PORT` | DNS name that lists every ready replica (a headless Service) |
| `--peer-self IP` | This replica's own IP. Use it with `--peers` |

| Rule | What it needs |
|---|---|
| `--listen` on a non-loopback address | `--auth static-tokens` and TLS (or `--insecure-plaintext`) |
| `--auth none` | A loopback `--listen` address |
| `key-mode=inject` | `key-file=FILE`. Not allowed with `--auth none` on a non-loopback address |
| `--peers` and `--peer-self` | Use both. Also needs a non-loopback `--listen` with TLS or `--insecure-plaintext` |

## Supported APIs

A route name can be anything, such as `/myllm`. But a new route needs `api=anthropic` or `api=openai`. Those are the only two API families `nospy` understands, and each one only handles certain endpoints:

| `api=` | Endpoints | Key header |
|---|---|---|
| `anthropic` | `/v1/messages`, `/v1/messages/count_tokens` | `X-Api-Key` |
| `openai` | `/v1/chat/completions`, `/v1/embeddings`, `/v1/responses` | `Authorization: Bearer` |

- Any backend that speaks one of these APIs works, such as Ollama, vLLM or LiteLLM.
- A request with a body to any other endpoint is rejected with `415 unsupported endpoint or content type`. nospy can't safely redact a body format it doesn't know.
- The body must be `application/json`.
- APIs with their own format (such as Gemini's native API or Bedrock) don't work. If the backend also offers an OpenAI-compatible endpoint, use that with `api=openai`.

## Tokens

Create a token for each client:

```bash
$ nospy hash-token --name ci-runner
Token (shown once):
  nspy_k3J...
Tokens-file line (add it to the file passed to --tokens-file):
  ci-runner:5e88...
```

- **Format:** `nspy_<base64url>` (32 random bytes). Only the hash goes in the tokens file.
- **Client name:** `[a-z0-9][a-z0-9-]*`. It shows up in logs and scopes conversation state.
- **Existing token:** `hash-token --stdin` hashes a token you already have and prints only the file line.

## Key modes

Set per route with `key-mode`.

| `key-mode` | Client sends | `nospy` does |
|---|---|---|
| `passthrough` (default) | The real LLM key in its usual header, plus the proxy token in `X-Nospy-Token` or in the path as `/t/<token>/...` | Checks the token, removes it, forwards the client's key |
| `inject` | The proxy token in the key header (`x-api-key` for `api=anthropic`, `Authorization: Bearer` for `api=openai`) | Checks the token, deletes all client credential headers, and sets the real key from `key-file` |

A `key-file` holds one line, can't contain a comma and reloads on changes.

With `--auth none` and `inject` (a sidecar), ensure you've set appropriate Pod security standards.

## Examples

```bash
# sidecar: one loopback listener, the real key injected from a mounted Secret
nospy serve --auth none --route /anthropic=https://api.anthropic.com,key-mode=inject,key-file=/run/secrets/llm-key

# shared service: TLS, per-client tokens, clients keep their own keys
nospy serve --auth static-tokens --tokens-file /etc/nospy/tokens --listen :8443 \
            --tls-cert /etc/nospy/tls.crt --tls-key /etc/nospy/tls.key \
            --route /openai=https://api.openai.com/v1 --terms /etc/nospy/terms
```

To point an agent at a running `serve`, run `nospy env --addr URL [--token T] [--shell sh|fish]`. It prints shell exports for `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`.

## Check your config

`nospy check` takes the same flags as `serve` and exits without listening. It checks the flag combinations, the terms file, the tokens file, the key files, the TLS pair (parsing, cert/key match, expiration) and the upstream URLs. Use it in CI and before a Helm rollout.

```bash
$ nospy check --auth static-tokens --tokens-file tokens --listen :8443 --tls-cert tls.crt --tls-key tls.key \
              --route /anthropic=https://api.anthropic.com,key-mode=inject,key-file=key --route /openai=https://api.openai.com/v1
ok: routes anthropic(inject) openai(passthrough); auth static-tokens (3 tokens); terms 14 in 3 sections; tls expires 2026-12-01
```

| Security Warnings | Warning |
|---|---|
| `--insecure-plaintext` on a non-loopback `--listen` | Tokens, keys and prompts cross the network unencrypted |
| A TLS certificate that expires within 14 days | The expiry date and days left |
| An `inject` route to a plain `http://` upstream on a non-loopback host | The route sends its key over plain http |

## Server behavior

- **Health:** `GET /healthz` and `GET /readyz`. `/readyz` returns 503 as soon as shutdown starts. `nospy healthcheck` probes `/healthz` for you (see [Container](container.md)).
- **Shutdown:** on `SIGTERM` or `SIGINT`, `nospy` stops accepting connections and lets open requests and SSE streams finish, for up to `--shutdown-timeout` (default 30s). In Kubernetes, make `terminationGracePeriodSeconds` larger than that. Streams still open after the timeout are closed and `nospy` exits with code 1.
- **Timeouts:** `ReadHeaderTimeout` 10s, `IdleTimeout` 120s, no write timeout (streams can run for minutes).
- **TLS:** certificates are re-read when the files change (for example, cert-manager renewals). If a renewed certificate fails to load, `nospy` keeps the old one and logs a warning.
- **Logs:** JSON on stdout. First a startup line (routes, auth, and the *counts* of tokens and terms), then one line per request with `client`, `route`, `path` (token removed), `status`, `dur` and redaction counts per kind. Never values, tokens, keys or terms.
- **State:** conversation state and [remembered values](how-it-works.md#remembered-values) live in one process's memory and hold actual values until they expire. They are not shared between replicas. See below.

## Multiple replicas

State is kept in each replica's memory and is not shared. A follow-up request (one that sets `previous_response_id`) that lands on a different replica finds no state for the earlier turn and gets a `409` (`nospy_chain_not_found`). With `--peers`, each client is pinned to one replica, so follow-ups reach the replica that holds their state.

| Item | Detail |
|---|---|
| Setup | `--peers <headless-service>:<port> --peer-self <this pod's IP>` |
| Owner | A rendezvous hash of the client name and route prefix picks one replica. The list of replicas is refreshed every 10s |
| Forwarding | A replica that is not the owner checks the client, then forwards the request unchanged. It adds `X-Nospy-Peer: 1`, which is never forwarded twice and never sent upstream. The owner redacts and logs the counts |
| Trust | Replicas must present the same TLS certificate (same Secret on every replica). With `--insecure-plaintext`, they use plain HTTP |
| Fallback | If the owner is unreachable or its certificate doesn't match, the request is served locally with a warning. The failed replica is skipped for 10s |
| Limits | One client maps to one replica. Requests take an extra hop. Because there is no replication, a client who moves to another replica after the replica set changes starts with empty state |
