# Commands

[Back to the README](../README.md)

| Command | Purpose |
|---|---|
| `nospy [flags] -- <cmd...>` | [Wrap](wrap.md) a command behind the proxy |
| `nospy scan [--terms FILE] [--explain] [FILE...]` | [Redact](scan.md) files or stdin |
| `nospy serve [flags]` | [Serve a proxy](serve.md) for multiple consumers  |
| `nospy check [serve flags]` | [Validate](serve.md#check-your-config) configuration and exit |
| `nospy healthcheck [--listen ADDR] [--scheme http\|https] [--timeout DUR]` | Probe `GET /healthz` of a running  `nospy` in `serve` mode |
| `nospy hash-token --name NAME [--stdin]` | Create a [proxy token](serve.md#tokens) and its tokens-file line |
| `nospy env --addr URL [--token T] [--shell sh\|fish]` | Print shell exports that point an agent at a running `nospy` |
| `nospy providers` | List built-in providers |
| `nospy --help`, `nospy help [cmd]` | Usage |
| `nospy --version`, `nospy version` | Version |
