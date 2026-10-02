# Security policy

`nospy` sits between a tool and an LLM and decides what gets sent, so security reports are taken seriously.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Include the `nospy` version (`nospy version`), the command line or Helm values you ran, and, where you can, a minimal fake input that shows the problem. Use made-up secrets and addresses, never real ones.

You can expect an acknowledgement within a week. Fixes ship in a patch release, and the advisory credits you unless you ask otherwise.

## Important Issues

- A secret or personal value that `nospy` should redact but sends upstream in plaintext.
- A placeholder that is restored for the wrong client, route or request.
- values, request bodies, credentials or clients showing up in logs, errors or metrics.
- An authentication, TLS or peer-forwarding bypass in `serve` or the Helm chart.
- A way to make `nospy` leak a client's token or proxy credentials.

Detection that misses an unusual format is usually a normal bug rather than a vulnerability. Open an issue with a fake example, and see [known limitations](docs/limitations.md) first.

## Supported versions

Only the latest release gets fixes.

## Hardening a deployment

- Prefer the sidecar mode. The proxy is reachable only on the pod's loopback, so a compromise stays within one workload.
- In shared Service mode, use `--auth static-tokens` with TLS (`--tls-cert`, `--tls-key`, or cert-manager through the chart). Plain HTTP on a non-loopback address needs `--insecure-plaintext` and should not leave a trusted network.
- Give each client its own token (`nospy hash-token`) so it can be revoked on its own. Keep the tokens file and any key files in Kubernetes Secrets, mounted read-only and using PSS.
- Restrict egress with NetworkPolicy so that apps can reach the LLM API only through `nospy`. See `deploy/helm/nospy/examples/app-egress-lockdown.yaml`.
- Run the published image as shipped: distroless, uid 65532, read-only root filesystem, no capabilities, `no-new-privileges`.
- Verify downloads: check `SHA256SUMS`, and run `gh attestation verify <file> --repo <owner>/nospy-ai` for the build provenance.
- Treat `/metrics` as internal. It has no request content, but its labels show your routes and the kinds of data redacted.
