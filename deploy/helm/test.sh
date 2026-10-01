#!/usr/bin/env bash
# Chart tests: helm lint, helm template for every mode, the install-time guards, and assertions on
# the rendered output. No cluster needed. Optionally set NOSPY=/path/to/nospy to also run
# `nospy check` on the rendered args (files under /etc/nospy are faked in a temp dir).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -R "$here/nospy" "$here/test" "$tmp/"
(cd "$tmp/test/app" && helm dependency update . >/dev/null)
chart="$tmp/nospy"
app="$tmp/test/app"

fails=0
ok()   { echo "ok   $1"; }
bad()  { echo "FAIL $1"; fails=$((fails + 1)); }
# has NAME TEXT OUTPUT: fixed-string match; lacks: no match.
has()   { if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (missing: $2)"; fi; }
lacks() { if grep -qF -- "$2" <<<"$3"; then bad "$1 (found: $2)"; else ok "$1"; fi; }
hasre() { if grep -qE -- "$2" <<<"$3"; then ok "$1"; else bad "$1 (no match: $2)"; fi; }
lacksre() { if grep -qE -- "$2" <<<"$3"; then bad "$1 (matched: $2)"; else ok "$1"; fi; }

svc()    { helm template r "$chart" --set mode=service "$@"; }
sidecar() { helm template a "$app" "$@"; }
SVC=(--set auth.existingSecret=tokens --set tls.secretName=nospy-tls)

# guard NAME EXPECTED_MESSAGE cmd...: the command must exit non-zero and print the message.
guard() {
  local name=$1 msg=$2 out; shift 2
  if out=$("$@" 2>&1); then bad "guard: $name (rendered without error)"; return; fi
  has "guard: $name" "$msg" "$out"
}

echo "== lint"
helm lint "$chart" >/dev/null && ok "lint defaults" || bad "lint defaults"
helm lint "$chart" --set mode=service "${SVC[@]}" >/dev/null && ok "lint service" || bad "lint service"
(cd "$app" && helm lint . >/dev/null) && ok "lint app fixture" || bad "lint app fixture"

echo "== chart metadata"
appver=$(sed -n 's/^appVersion: "\(.*\)"/\1/p' "$chart/Chart.yaml")
has "nospy.appVersion matches Chart.yaml appVersion" "define \"nospy.appVersion\" -}}$appver{{" "$(cat "$chart/templates/_helpers.tpl")"
has "kubeVersion" 'kubeVersion: ">=1.29.0-0"' "$(cat "$chart/Chart.yaml")"

echo "== default values: sidecar mode renders no resources by itself"
out=$(helm template r "$chart")
[ -z "$(tr -d '[:space:]' <<<"$out")" ] && ok "default render is empty" || bad "default render is not empty"

echo "== sidecar (app chart fixture)"
out=$(sidecar)
has "native sidecar" "restartPolicy: Always" "$out"
has "loopback bind" '"127.0.0.1:8788"' "$out"
has "auth none" '- "none"' "$out"
has "default anthropic route" '"/anthropic=https://api.anthropic.com,api=anthropic"' "$out"
has "default openai route" '"/openai=https://api.openai.com/v1,api=openai"' "$out"
has "ANTHROPIC_BASE_URL" 'value: "http://127.0.0.1:8788/anthropic"' "$out"
has "OPENAI_BASE_URL" 'value: "http://127.0.0.1:8788/openai/v1"' "$out"
# Kubelet httpGet probes can't reach loopback, so the sidecar probes by exec (nospy healthcheck).
has "sidecar startupProbe is exec nospy healthcheck" 'startupProbe:
            exec:
              command: ["/nospy","healthcheck","--listen","127.0.0.1:8788"]
            periodSeconds: 1
            failureThreshold: 30' "$out"
has "sidecar livenessProbe is exec nospy healthcheck" 'livenessProbe:
            exec:
              command: ["/nospy","healthcheck","--listen","127.0.0.1:8788"]
            periodSeconds: 10
            failureThreshold: 3' "$out"
lacks "sidecar has no httpGet probe" "httpGet" "$out"
lacks "sidecar has no readinessProbe" "readinessProbe" "$out"
has "sidecar probes follow port" '"--listen","127.0.0.1:9000"]' "$(sidecar --set nospy.port=9000)"
lacks "no volumes by default" "volumes:" "$out"
lacks "metrics on by default in sidecar" "--metrics=false" "$out"
has "sidecar metrics disabled" "--metrics=false" "$(sidecar --set nospy.metrics.enabled=false)"
for want in "runAsNonRoot: true" "readOnlyRootFilesystem: true" "allowPrivilegeEscalation: false" "drop: [ALL]" "type: RuntimeDefault"; do
  has "sidecar securityContext: $want" "$want" "$out"
done
example=$(grep -vE '^(#|---)' "$here/nospy/examples/sidecar-deployment.yaml" | sed '/^$/d')
rendered=$(grep -vE '^(#|---)' <<<"$out" | sed '/^$/d')
[ "$example" = "$rendered" ] && ok "examples/sidecar-deployment.yaml matches the render" || bad "examples/sidecar-deployment.yaml is stale (regenerate: see its header)"

echo "== sidecar with routes, providers, inject key, terms"
vals="$tmp/sidecar-values.yaml"
cat >"$vals" <<'YAML'
nospy:
  routes:
    - {prefix: /gpu, upstream: "https://inference.example.internal/v1", api: openai, keyMode: inject, keySecret: {name: gpu-key, key: key}}
    - {prefix: /anthropic, upstream: "https://api.anthropic.com", api: anthropic}
  providers: [ollama]
  terms: {existingSecret: corp-terms}
  sidecar: {envRoutes: {openai: /gpu}}
YAML
out=$(sidecar -f "$vals")
has "inject route arg" '"/gpu=https://inference.example.internal/v1,api=openai,key-mode=inject,key-file=/etc/nospy/keys/gpu/key"' "$out"
has "provider arg" '- --provider' "$out"
has "provider value" '- "ollama"' "$out"
has "terms arg" '/etc/nospy/terms/terms' "$out"
has "envRoutes override" 'value: "http://127.0.0.1:8788/gpu/v1"' "$out"
has "key secret volume" 'secretName: "gpu-key"' "$out"
has "terms secret volume" 'secretName: "corp-terms"' "$out"
has "key mounted read-only into sidecar" 'mountPath: /etc/nospy/keys/gpu' "$out"
lacks "no Secret objects" "kind: Secret" "$out"
lacksre "no vendor-named flags" '^ *- --[a-z-]*(anthropic|openai|claude|gpt)' "$out"
guard "inject without keySecret (sidecar)" "keyMode inject needs keySecret" \
  sidecar --set 'nospy.routes[0].prefix=/x' --set 'nospy.routes[0].upstream=https://x.example' --set 'nospy.routes[0].api=openai' --set 'nospy.routes[0].keyMode=inject'

echo "== service mode"
out=$(svc "${SVC[@]}")
for k in Deployment Service NetworkPolicy ServiceAccount; do has "renders $k" "kind: $k" "$out"; done
lacks "no PodDisruptionBudget with 1 replica" "PodDisruptionBudget" "$out"
lacks "no sessionAffinity with 1 replica" "sessionAffinity" "$out"
lacks "no headless peers Service with 1 replica" "clusterIP: None" "$out"
lacks "no peer args with 1 replica" "--peer" "$out"
lacks "no POD_IP env with 1 replica" "POD_IP" "$out"
has "no ingress without allowedClients or peers" "ingress: []" "$out"
np_ingress() { sed -n '/^  ingress:/,/^  egress:/p' <<<"$(awk '/^kind: NetworkPolicy/{f=1} f&&/^---/{f=0} f' <<<"$1")"; }
np_egress()  { sed -n '/^  egress:/,$p' <<<"$(awk '/^kind: NetworkPolicy/{f=1} f&&/^---/{f=0} f' <<<"$1")"; }
lacks "NetworkPolicy has no peer ingress rule with 1 replica" "podSelector" "$(np_ingress "$out")"
lacks "NetworkPolicy has no peer egress rule with 1 replica" "podSelector" "$(np_egress "$out")"
has "listens on all interfaces" '"0.0.0.0:8788"' "$out"
has "static-tokens auth" '- "static-tokens"' "$out"
has "tokens file" "--tokens-file" "$out"
has "tls cert/key" "--tls-key" "$out"
lacks "no --insecure-plaintext with TLS" "--insecure-plaintext" "$out"
has "liveness probe" "path: /healthz" "$out"
has "readiness probe" "path: /readyz" "$out"
lacks "metrics on by default in service" "--metrics=false" "$out"
has "service metrics disabled" "--metrics=false" "$(svc "${SVC[@]}" --set metrics.enabled=false)"
has "startup probe is HTTPS with TLS" "scheme: HTTPS" "$out"
has "grace period = shutdown + 10" "terminationGracePeriodSeconds: 40" "$out"
has "service account token not mounted" "automountServiceAccountToken: false" "$out"
for want in "runAsNonRoot: true" "readOnlyRootFilesystem: true" "allowPrivilegeEscalation: false" "drop: [ALL]" "type: RuntimeDefault"; do
  has "service securityContext: $want" "$want" "$out"
done
has "egress TCP 443" "{protocol: TCP, port: 443}" "$out"
has "egress lists upstream hosts" "#   /anthropic: api.anthropic.com" "$out"
egress_ports() { grep -oE '\{protocol: TCP, port: [0-9]+\}' <<<"$1" | grep -v 'port: 53}' | sed 's/.*port: \([0-9]*\)}/\1/' | tr '\n' ' '; }
[ "$(egress_ports "$out")" = "443 " ] && ok "default routes derive TCP 443 only" || bad "default routes derive TCP 443 only (got: $(egress_ports "$out"))"
lacks "service mode keeps httpGet probes (no exec probe)" "exec:" "$out"
lacks "no Secret objects" "kind: Secret" "$out"
lacksre "no secret data fields" '^ *(data|stringData):' "$out"
lacksre "no vendor-named flags" '^ *- --[a-z-]*(anthropic|openai|claude|gpt)' "$out"
if grep -qi trust <<<"$out"; then bad "no trust settings"; else ok "no trust settings"; fi

out=$(svc "${SVC[@]}" --set replicas=3 --set shutdownTimeoutSeconds=60 --set 'allowedClients[0].namespaceSelector.matchLabels.team=apps')
lacks "no sessionAffinity with replicas > 1 (nospy does the affinity)" "sessionAffinity" "$out"
has "headless peers Service with replicas > 1" "name: r-peers" "$out"
has "peers Service is headless" "clusterIP: None" "$out"
has "peers Service leaves out not-ready pods" "publishNotReadyAddresses: false" "$out"
has "--peers names the headless Service, namespace and port" '- "r-peers.default.svc:8788"' "$out"
has "--peer-self is the pod IP" '- "$(POD_IP)"' "$out"
has "POD_IP from the downward API" "fieldPath: status.podIP" "$out"
has "peer ingress rule: nospy's own pods on the port" "podSelector" "$(np_ingress "$out")"
has "peer egress rule: nospy's own pods on the port" "podSelector" "$(np_egress "$out")"
for dir in ingress egress; do
  rule=$(np_$dir "$out" | sed -n '/podSelector/,$p')
  has "peer $dir rule uses nospy's selector labels" "app.kubernetes.io/instance: r" "$rule"
  has "peer $dir rule is TCP 8788" "port: 8788" "$rule"
done
has "allowedClients still in ingress with peers" "team: apps" "$(np_ingress "$out")"
lacksre "no vendor-named peer flags" '^ *- --[a-z-]*(anthropic|openai|claude|gpt)' "$out"
has "PodDisruptionBudget with replicas > 1" "kind: PodDisruptionBudget" "$out"
has "replicas" "replicas: 3" "$out"
has "grace period follows shutdownTimeoutSeconds" "terminationGracePeriodSeconds: 70" "$out"
has "--shutdown-timeout" '- "60s"' "$out"
has "allowedClients in ingress" "team: apps" "$out"

out=$(svc "${SVC[@]}" --set replicas=3)
has "peers ingress without allowedClients" "podSelector" "$(np_ingress "$out")"
lacks "peers ingress alone is not empty" "ingress: []" "$out"
out=$(svc --set auth.existingSecret=tokens --set tls.insecure=true --set replicas=2)
has "peers work with tls.insecure" '- --insecure-plaintext' "$out"
has "tls.insecure peers args" '- "r-peers.default.svc:8788"' "$out"
out=$(svc --set auth.existingSecret=tokens --set tls.insecure=true)
has "tls.insecure renders --insecure-plaintext" "--insecure-plaintext" "$out"
has "tls.insecure probes use HTTP" "scheme: HTTP" "$out"
lacks "tls.insecure mounts no tls volume" "nospy-tls" "$out"

out=$(svc "${SVC[@]}" -f "$tmp/sidecar-values.yaml" --set-json 'routes=[{"prefix":"/gpu","upstream":"https://inference.example.internal/v1","api":"openai","keyMode":"inject","keySecret":{"name":"gpu-key","key":"key"}}]' --set 'providers={ollama}' --set terms.existingSecret=corp-terms)
has "service inject route" 'key-mode=inject,key-file=/etc/nospy/keys/gpu/key' "$out"
has "service key secret volume" 'secretName: "gpu-key"' "$out"
has "service provider" '- "ollama"' "$out"
has "service terms" 'secretName: "corp-terms"' "$out"
has "service egress comment for provider" "/ollama: built-in provider" "$out"

echo "== egress ports derived from the routes (service mode)"
egress_case() {
  local name=$1 want=$2 got; shift 2
  got=$(egress_ports "$(svc "${SVC[@]}" "$@")")
  [ "$got" = "$want " ] && ok "egress ports: $name" || bad "egress ports: $name (want: $want, got: $got)"
}
ports_vals="$tmp/ports-values.yaml"
cat >"$ports_vals" <<'YAML'
routes:
  - {prefix: /a, upstream: "https://a.example", api: openai}
  - {prefix: /b, upstream: "https://b.example:11434/v1", api: openai}
  - {prefix: /c, upstream: "http://c.example", api: openai}
  - {prefix: /d, upstream: "http://127.0.0.1:9999", api: openai}
  - {prefix: /e, upstream: "http://localhost:9998", api: openai}
  - {prefix: /f, upstream: "http://[::1]:9997", api: openai}
  - {prefix: /g, upstream: "https://a.example:443", api: openai}
  - {prefix: /h, upstream: "https://[2001:db8::1]:8443", api: openai}
  - {prefix: /i, upstream: "https://[2001:db8::2]", api: openai}
YAML
egress_case "https default, explicit port, http default, IPv6, deduped, sorted; loopback skipped" "80 443 8443 11434" -f "$ports_vals"
egress_case "explicit :11434" "11434" --set-json 'routes=[{"prefix":"/gpu","upstream":"http://gpu.example:11434","api":"openai"}]'
egress_case "http default" "80" --set-json 'routes=[{"prefix":"/gpu","upstream":"http://gpu.example","api":"openai"}]'
egress_case "extraEgressPorts merged, deduped, sorted" "443 3128 8080" --set 'networkPolicy.extraEgressPorts={8080,3128,443}'
out=$(svc "${SVC[@]}" --set-json 'routes=[{"prefix":"/local","upstream":"http://127.0.0.1:11434","api":"openai"}]')
has "all-loopback routes still render a policy" "kind: NetworkPolicy" "$out"
lacks "all-loopback routes add no TCP upstream rule" "protocol: TCP, port: 11434" "$out"
[ -z "$(egress_ports "$out")" ] && ok "all-loopback routes: no TCP upstream rule" || bad "all-loopback routes: no TCP upstream rule (got: $(egress_ports "$out"))"
has "all-loopback routes keep DNS egress" "{protocol: UDP, port: 53}" "$out"
egress_case "all-loopback plus extra port (egress proxy)" "3128" --set 'networkPolicy.extraEgressPorts={3128}' \
  --set-json 'routes=[{"prefix":"/local","upstream":"http://localhost:11434","api":"openai"}]'

echo "== cert-manager Certificate"
out=$(svc "${SVC[@]}")
lacks "no Certificate by default" "kind: Certificate" "$out"
out=$(svc "${SVC[@]}" --set tls.certManager.issuerRef.name=corp-ca --set 'tls.certManager.dnsNames={nospy.example.com}')
has "Certificate rendered" "kind: Certificate" "$out"
has "Certificate writes tls.secretName" 'secretName: "nospy-tls"' "$out"
has "Certificate issuerRef name" "name: corp-ca" "$out"
has "Certificate issuerRef kind default" "kind: Issuer" "$out"
has "Certificate service dns name" "r.default.svc.cluster.local" "$out"
has "Certificate extra dns name" 'nospy.example.com' "$out"
out=$(svc "${SVC[@]}" --set tls.certManager.issuerRef.name=corp-ca --set tls.certManager.issuerRef.kind=ClusterIssuer)
has "Certificate ClusterIssuer" "kind: ClusterIssuer" "$out"

echo "== install-time guards"
guard "cert-manager without secretName" "issuerRef.name needs tls.secretName" \
  svc --set auth.existingSecret=tokens --set tls.insecure=true --set tls.certManager.issuerRef.name=corp-ca
guard "service without TLS" "mode service needs tls.secretName" svc --set auth.existingSecret=tokens
guard "service with auth none" "refuses auth.type none" svc "${SVC[@]}" --set auth.type=none
guard "service without tokens secret" "needs auth.existingSecret" svc --set tls.secretName=nospy-tls
guard "inject without keySecret (service)" "keyMode inject needs keySecret" \
  svc "${SVC[@]}" --set-json 'routes=[{"prefix":"/x","upstream":"https://x.example","api":"openai","keyMode":"inject"}]'
for bad_port in 0 65536 -1; do
  guard "extraEgressPorts $bad_port" "extraEgressPorts entries must be integers 1-65535" \
    svc "${SVC[@]}" --set "networkPolicy.extraEgressPorts={$bad_port}"
done
guard "extraEgressPorts string" "extraEgressPorts entries must be integers 1-65535" \
  svc "${SVC[@]}" --set-json 'networkPolicy.extraEgressPorts=["3128"]'
guard "extraEgressPorts fraction" "extraEgressPorts entries must be integers 1-65535" \
  svc "${SVC[@]}" --set-json 'networkPolicy.extraEgressPorts=[3.5]'
guard "extraEgressPorts (sidecar)" "extraEgressPorts entries must be integers 1-65535" \
  sidecar --set-json 'nospy.networkPolicy.extraEgressPorts=[70000]'
guard "unknown mode" "mode must be sidecar or service" helm template r "$chart" --set mode=daemon

echo "== nospy check on the rendered args (optional)"
if [ -n "${NOSPY:-}" ] && [ -x "$NOSPY" ]; then
  fake="$tmp/fake"; mkdir -p "$fake/tokens" "$fake/tls" "$fake/keys/gpu"
  printf 'ci:%s\n' "$(printf 'x' | shasum -a 256 | cut -d' ' -f1)" >"$fake/tokens/tokens"
  printf 'sk-test-key\n' >"$fake/keys/gpu/key"
  openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj /CN=nospy -keyout "$fake/tls/tls.key" -out "$fake/tls/tls.crt" 2>/dev/null
  extract() { awk '/^ +args:/{f=1;next} f&&/^ +- /{sub(/^ +- /,"");gsub(/^"|"$/,"");print;next} f{exit}' | sed -e "s#/etc/nospy#$fake#g" -e 's#\$(POD_IP)#10.0.3.7#'; }
  run_check() {
    local name=$1 args; args=$(extract)
    local -a a=(); while IFS= read -r l; do a+=("$l"); done <<<"$args"
    if "$NOSPY" check "${a[@]}" >"$tmp/check.out" 2>&1; then ok "nospy check: $name"; else bad "nospy check: $name: $(cat "$tmp/check.out")"; fi
  }
  sidecar | run_check "sidecar defaults"
  sidecar --set nospy.metrics.enabled=false | run_check "sidecar metrics off"
  sidecar --set 'nospy.routes[0].prefix=/gpu' --set 'nospy.routes[0].upstream=https://inference.example.internal/v1' \
    --set 'nospy.routes[0].api=openai' --set 'nospy.routes[0].keyMode=inject' \
    --set 'nospy.routes[0].keySecret.name=gpu-key' --set 'nospy.routes[0].keySecret.key=key' --set 'nospy.providers={ollama}' | run_check "sidecar inject + provider"
  svc "${SVC[@]}" | run_check "service TLS + static-tokens"
  svc "${SVC[@]}" --set metrics.enabled=false | run_check "service metrics off"
  svc "${SVC[@]}" --set replicas=3 | run_check "service TLS + static-tokens, 3 replicas (peers)"
else
  echo "skip (set NOSPY=/path/to/nospy)"
fi

echo
if [ "$fails" -eq 0 ]; then echo "all chart tests passed"; else echo "$fails chart test(s) FAILED"; exit 1; fi
