# Wrap mode: local agent

[Back to the README](../README.md)

```
nospy [flags] -- <command...>
```

`nospy` starts a proxy on a random local port and runs your command with its base URL pointed at the proxy. Each run has its own token in the URL path. API keys from agents are passed through unaltered.

```bash
nospy -- claude
nospy --log nospy.log -- claude -p "summarize this repo"
nospy --provider ollama -- my-openai-compatible-agent
nospy --route /openai=http://127.0.0.1:4000/v1 -- my-agent
```

## Flags

| Flag | Meaning |
|---|---|
| `--route PREFIX=URL[,api=anthropic\|openai]` | Change or add a route. Repeatable |
| `--provider NAME` | Use a built-in provider. Repeatable across API families |
| `--terms FILE` | A [custom terms](custom-terms.md) file |
| `--metrics=false` | Turn off the [metrics](metrics.md) endpoint (on by default at `127.0.0.1:9464`) |
| `--no-agent-config` | Don't inject proxy settings into a known agent |
| `--log FILE` | Append JSON logs to a file (off by default) |

## Routes and providers

| Route | API family | Env var set for the agent | Default upstream |
|---|---|---|---|
| `/anthropic` | `anthropic` (Messages) | `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` |
| `/openai` | `openai` (Chat Completions, Responses, Embeddings) | `OPENAI_BASE_URL` | `https://api.openai.com/v1` |

| Provider | API family | Upstream |
|---|---|---|
| `ollama` | `openai` | `http://127.0.0.1:11434/v1` |

- **Upstream order:** `--route`, then the env var from your shell, then the default.
- **Redaction:** the upstream host itself is never redacted.
- **Loops:** a route that points at another `nospy` is refused.

## Claude Code

```bash
nospy -- claude
```

When the command is `claude`, `nospy` writes the base URL to a private settings file (mode 0600) and adds `--settings <file>` to the command. The file is removed on exit, and the URL stays off the command line.

`nospy` skips this if you pass your own `--settings` (it prints a notice) or use `--no-agent-config`.

## OpenAI agents

```bash
nospy -- my-openai-agent
```

Any agent that reads `OPENAI_BASE_URL` needs no setup. The `/openai` route handles Chat Completions, Responses and Embeddings (`/openai/v1/...`).

- To use a gateway instead of `api.openai.com`, pass `--route /openai=<gateway URL>` or set `OPENAI_BASE_URL` in your shell.
- If an agent ignores `OPENAI_BASE_URL`, set the proxy URL in the agent's own settings. `nospy env` prints it for a running `serve` instance.

## Other backends

| Backend | Command |
|---|---|
| Built-in provider (see [Routes and providers](#routes-and-providers)) | `nospy --provider ollama -- my-agent` |
| Gateway for the OpenAI API | `nospy --route /openai=http://127.0.0.1:4000/v1 -- my-agent` |
| Gateway for the Anthropic API | `nospy --route /anthropic=https://gateway.example.com -- my-agent` |

`--provider` replaces the built-in route for its API family, so the agent's usual env var points at the provider. A new `--route` prefix needs `api=openai|anthropic` (the only two [supported APIs](serve.md#supported-apis)) and gets no env var. New prefixes are meant for `serve` mode, where clients set the base URL themselves.

## Debug

- Run with `--log FILE`. If the agent's settings point at a gateway, also pass `--route /anthropic=<gateway URL>` (or `/openai=...`).
- Or open `http://127.0.0.1:9464/metrics` while the session runs to see redactions counted by kind. See [Metrics](metrics.md).
