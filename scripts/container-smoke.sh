#!/usr/bin/env bash
# Container smoke test: build the image with podman, run it the way the Helm chart does
# (read-only root, no capabilities, no-new-privileges) in front of a fake upstream on the host, and check
# health, redaction, authentication and the image's own healthcheck. Uses fake secrets only; the proxy
# token is generated at run time by `nospy hash-token` inside the image and never written anywhere
# but a temporary tokens file.
#
# usage: scripts/container-smoke.sh [HOST_PORT]     (default 18787, or $NOSPY_SMOKE_PORT)
#   IMAGE=nospy:dev   image to test      SKIP_BUILD=1   test IMAGE as it is, without building
set -euo pipefail

cd "$(dirname "$0")/.."
port="${1:-${NOSPY_SMOKE_PORT:-18787}}"
image="${IMAGE:-nospy:dev}"
name="nospy-smoke-$$"
work="$(mktemp -d)"
up_pid=""

cleanup() {
  podman rm -f "$name" >/dev/null 2>&1 || true
  if [ -n "$up_pid" ]; then kill "$up_pid" >/dev/null 2>&1 || true; wait "$up_pid" 2>/dev/null || true; fi
  rm -f "$work"/tokens "$work"/record.jsonl "$work"/port "$work"/fakeupstream "$work"/resp.json
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

fails=0
pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails + 1)); }
check() { # check DESCRIPTION COMMAND... : pass if the command succeeds
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}

# 1. Build. --format docker keeps the HEALTHCHECK, which the OCI format drops.
if [ -z "${SKIP_BUILD:-}" ]; then
  podman build --format docker -t "$image" . >/dev/null
fi
printf 'image %s: %s\n' "$image" "$(podman image inspect --format '{{.Size}}' "$image" | awk '{printf "%.1f MB", $1 / 1000000}')"

# 2. A proxy token, made by the image itself. The token is the first indented line of hash-token's
# output and the tokens-file line the second.
out="$(podman run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --entrypoint /nospy "$image" hash-token --name smoke | sed -n 's/^  //p')"
token="$(printf '%s\n' "$out" | sed -n 1p)"
printf '%s\n' "$out" | sed -n 2p >"$work/tokens"
chmod 644 "$work/tokens" # the container runs as uid 65532
case "$token" in nspy_*) pass "hash-token in the image printed a token" ;; *) fail "hash-token output"; exit 1 ;; esac

# 3. Fake upstream on the host, reachable from the container as host.containers.internal.
go build -o "$work/fakeupstream" ./scripts/fakeupstream
: >"$work/record.jsonl"
"$work/fakeupstream" --record "$work/record.jsonl" --port-file "$work/port" &
up_pid=$!
for _ in $(seq 50); do [ -s "$work/port" ] && break; sleep 0.1; done
[ -s "$work/port" ] || { fail "fake upstream did not start"; exit 1; }
up_port="$(cat "$work/port")"

# 4. Run the image with the chart's restrictions.
podman run -d --name "$name" --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p "127.0.0.1:$port:8788" -v "$work/tokens:/run/tokens:ro" "$image" \
  --listen 0.0.0.0:8788 --auth static-tokens --tokens-file /run/tokens --insecure-plaintext \
  --route "/anthropic=http://host.containers.internal:$up_port" >/dev/null

base="http://127.0.0.1:$port"
ready=""
for _ in $(seq 50); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/healthz" || true)" = 200 ]; then ready=1; break; fi
  sleep 0.2
done
if [ -z "$ready" ]; then fail "/healthz did not return 200"; podman logs "$name" >&2 || true; exit 1; fi
pass "/healthz returns 200 with no credentials"

# 5. Redaction through the container. The secret is fake.
secret="sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0123456789"
reqbody="{\"model\":\"m\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"my key is $secret ok\"}]}"
status="$(curl -s -o "$work/resp.json" -w '%{http_code}' "$base/anthropic/v1/messages" \
  -H "X-Nospy-Token: $token" -H 'x-api-key: fake-upstream-key' -H 'content-type: application/json' -d "$reqbody")"
[ "$status" = 200 ] && pass "authenticated request returns 200" || fail "authenticated request returned $status"
check "fake upstream received the request (as a placeholder)" grep -q 'REDACTED_TOKEN' "$work/record.jsonl"
if grep -qF "$secret" "$work/record.jsonl"; then fail "the upstream saw the secret"; else pass "the upstream never saw the secret"; fi
check "the client got the secret restored" grep -qF "$secret" "$work/resp.json"
if grep -q 'REDACTED' "$work/resp.json"; then fail "a placeholder leaked into the response"; else pass "no placeholder in the client's response"; fi
if grep -q 'x-nospy-token' "$work/record.jsonl"; then fail "the proxy token went upstream"; else pass "the proxy token was stripped before the upstream"; fi
check "the client's own key header went upstream (passthrough)" grep -q '"x-api-key"' "$work/record.jsonl"

# 6. Authentication: no token, no forwarding.
before="$(wc -l <"$work/record.jsonl")"
status="$(curl -s -o /dev/null -w '%{http_code}' "$base/anthropic/v1/messages" -H 'content-type: application/json' -d "$reqbody")"
[ "$status" = 401 ] && pass "no token gets 401" || fail "no token returned $status, want 401"
[ "$(wc -l <"$work/record.jsonl")" = "$before" ] && pass "the 401 request never reached the upstream" || fail "a 401 request reached the upstream"

# 7. The image's healthcheck.
check "podman healthcheck run succeeds" podman healthcheck run "$name"
check "the Helm probe command works (exec /nospy healthcheck --listen 127.0.0.1:8788)" \
  podman exec "$name" /nospy healthcheck --listen 127.0.0.1:8788
health=""
for _ in $(seq 40); do
  health="$(podman inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null || true)"
  [ "$health" = healthy ] && break
  sleep 1
done
[ "$health" = healthy ] && pass "podman inspect reports healthy" || fail "podman inspect reports '$health', want healthy"

# 8. The restrictions really applied, and it still runs.
# Podman expands --cap-drop=ALL into the individual capability names.
hc="$(podman inspect --format '{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapDrop}}|{{.HostConfig.SecurityOpt}}|{{.Config.User}}' "$name")"
case "$hc" in
  true\|*CAP_NET_BIND_SERVICE*\|*no-new-privileges*\|65532) pass "running read-only, all capabilities dropped, no-new-privileges, uid 65532" ;;
  *) fail "restrictions not applied: $hc" ;;
esac
check "container is still running" test "$(podman inspect --format '{{.State.Running}}' "$name")" = true

if [ "$fails" -gt 0 ]; then printf '\n%d check(s) failed\n' "$fails" >&2; exit 1; fi
printf '\nsmoke test passed\n'
