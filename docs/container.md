# Container mode

[Back to the README](../README.md)

The image runs `nospy serve`.

```bash
podman build --format docker -t nospy:dev .
podman run --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8788:8788 -v ./tokens:/run/tokens:ro nospy:dev \
  --listen 0.0.0.0:8788 --auth static-tokens --tokens-file /run/tokens --insecure-plaintext \
  --route /anthropic=https://api.anthropic.com
```

| Item | Detail |
|---|---|
| Image | Distroless, about 11 MB, runs as uid 65532 |
| Multi-arch | `podman build --format docker --platform linux/amd64,linux/arm64 --manifest nospy:multi .` |
| Published image | Pushing a `v*` tag (ex: `v0.1.0`) runs CI, then [release.yml](../.github/workflows/release.yml) pushes `linux/amd64` and `linux/arm64` to `ghcr.io/6fears7/nospy-ai:0.1.0` and `:0.1` (and `:latest` for a stable release). Set the Helm `image.repository` to it. The package is private until you make it public in the GitHub package settings |
| Smoke test | `scripts/container-smoke.sh [HOST_PORT]` |
| Healthcheck | `nospy healthcheck` is the image HEALTHCHECK. For a Kubernetes exec probe, use `/nospy healthcheck --listen 127.0.0.1:8788` |

`nospy healthcheck [--listen ADDR] [--scheme http|https] [--timeout DUR]` calls `GET /healthz` in `serve` mode. Defaults: `127.0.0.1:8788`, `http`, `2s`.
