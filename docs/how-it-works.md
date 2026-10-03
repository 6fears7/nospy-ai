# How it works

[Back to the README](../README.md)

These rules apply in every mode.

- **Placeholders** look like `[REDACTED_<KIND>_<n>]`. The same value always gets the same placeholder to support prompt caching.
- **Kinds:** `PRIVATE_KEY`, `TOKEN`, `PASSWORD`, `SECRET`, `EMAIL`, `IPV4`, `IPV6`, `DOMAIN`, `USER`, `ADDRESS`, `TERM`, plus any you add with [custom terms](custom-terms.md).
- **Discovery** (regex based): private keys, known token formats, bearer tokens, URL passwords, `password=`-style keywords, high-entropy strings, emails, IP addresses, domains (real TLD list), usernames in home directories, postal addresses, and secret files (k8s Secrets, kubeconfig, dotenv, Terraform state).
- **Ignored:** thinking blocks, signatures, base64 data.
- **Restoration:** each request gets its own in-memory map of placeholder to value. This works for JSON and for SSE streams. If a stream splits a placeholder across two chunks, `nospy` rebuilds it before restoring.
- **System prompt note:** when something was redacted, `nospy` adds a short fixed note to the system prompt.
- **Identity scrubbing:** `nospy` drops the body keys `metadata` (Anthropic), `user`, `safety_identifier` and `metadata` (OpenAI). It forwards only these headers: `Content-Type`, `Accept`, `anthropic-version`, `anthropic-beta`, `OpenAI-Beta` and the API-key header. `User-Agent` becomes `nospy/<version>`.
- **Logs** count redactions per kind, ex:
```json
{"time":"2026-10-01T13:28:15.591446-04:00","level":"INFO","msg":"request","client":"local","route":"/anthropic","method":"POST","path":"/anthropic/v1/messages","status":200,"dur":8930000000,"redacted":{"DOMAIN":97,"EMAIL":29,"IPV4":1,"TOKEN":1,"USER":142}}
```

## Remembered values

Some secrets are only detected because of a clue next to them, such as password=. If the model later repeats that value without the clue, the pattern no longer matches. To catch those repeats, nospy remembers each value found this way and redacts it wherever it shows up again.

- **Defaults:** `PASSWORD`, `SECRET`, `TOKEN`, `PRIVATE_KEY`, `USER`, `ADDRESS` and custom terms.
- **Scope:** each client and route has its own list.
- **Lifetime:** 1 hour after the last time a value was seen. In `serve` mode you can change this with `--chain-ttl`.
- **Size:** at most 4096 values or 1 MiB per client. The oldest values are dropped first.
- **Storage:** memory only and emptied on restart.
