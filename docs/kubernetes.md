# Kubernetes mode (Helm)

[Back to the README](../README.md)

Chart: `deploy/helm/nospy` (Kubernetes 1.29+). Tests: `deploy/helm/test.sh`.

| Mode | Set with | What it creates |
|---|---|---|
| Sidecar (default) | Include the templates in your app chart | A native sidecar on `127.0.0.1:8788` with `--auth none` and exec startup/liveness probes |
| Shared Service | `--set mode=service` | A Deployment, ClusterIP Service, NetworkPolicy, ServiceAccount, and a PodDisruptionBudget. Needs `tls.secretName` and `auth.existingSecret` |

## Sidecar

Add the templates to your app chart:

```yaml
initContainers:
  {{- include "nospy.sidecar" (dict "Values" .Values.nospy "Release" .Release) | nindent 8 }}
containers:
  - name: app
    env:
      {{- include "nospy.sidecarEnv" .Values.nospy | nindent 12 }}  # ANTHROPIC_BASE_URL / OPENAI_BASE_URL -> 127.0.0.1
volumes:
  {{- include "nospy.sidecarVolumes" (dict "Values" .Values.nospy "Release" .Release) | nindent 8 }}
```

A plain-manifest version is in [sidecar-deployment.yaml](https://github.com/6fears7/nospy-ai/blob/main/deploy/helm/nospy/examples/sidecar-deployment.yaml).

## Shared Service

The chart uses two Secrets. Create them first:

```bash
kubectl create namespace nospy

# Tokens: hash-token prints the token once (shown on your terminal for the client) and the tokens-file
# line, which tail/tr write to ./tokens as `name:sha256hex`.
nospy hash-token --name ci-runner | tee /dev/stderr | tail -n1 | tr -d ' ' > tokens
kubectl -n nospy create secret generic nospy-tokens --from-file=tokens=./tokens   # key matches auth.key

# TLS: your own certificate (cert-manager users skip this and see below)
kubectl -n nospy create secret tls nospy-tls --cert=tls.crt --key=tls.key
```

With **cert-manager**, skip the TLS Secret and add `--set tls.certManager.issuerRef.name=<issuer>` to the install below. For a cluster-wide issuer, also set `tls.certManager.issuerRef.kind=ClusterIssuer`. The chart then creates a `Certificate` that cert-manager writes to `tls.secretName`. cert-manager handles issuing and renewing, and `nospy` reloads the files when they change. It is off by default and still needs `tls.secretName`. The certificate covers the Service name, `.<namespace>`, `.svc` and `.svc.cluster.local`, plus anything in `tls.certManager.dnsNames`.

Then install from a checkout. The cluster must be able to pull the image; use `--set image.repository=...` to change it.

```bash
helm install nospy deploy/helm/nospy --namespace nospy \
  --set mode=service \
  --set tls.secretName=nospy-tls \
  --set auth.existingSecret=nospy-tokens
```

| Item | Detail |
|---|---|
| Replicas | With `replicas > 1`, the chart adds a headless `<release>-peers` Service and starts pods with `--peers <release>-peers.<namespace>.svc:<port> --peer-self $(POD_IP)`. See [multiple replicas](serve.md#multiple-replicas) |
| NetworkPolicy egress | DNS as well as each route's port (the URL port, else 443 or 80; loopback upstreams add none), plus `networkPolicy.extraEgressPorts` (ex: `[3128]`) |
| Strict Egress example  | `examples/app-egress-lockdown.yaml` |

## Helm values

```yaml
routes:
  - {prefix: /anthropic, upstream: https://api.anthropic.com, api: anthropic}
  - prefix: /gpu
    upstream: https://inference.example.internal/v1
    api: openai
    keyMode: inject                      # the real key never reaches the workload
    keySecret: {name: gpu-key, key: key}
providers: [ollama]                      # adds routes from `nospy providers`
terms: {existingSecret: corp-terms}
```

The chart only references Secrets by name.

When a Secret changes:
- **Tokens, TLS and route keys** reload automatically
- **Terms** are read once at startup. After you update the terms Secret, restart the pods
