{{/*
Named templates below take a dict with .Values (this chart's values; from an app chart that is
.Values.nospy) and, for the sidecar ones, .Release. Nothing here reads .Chart, because
an app chart includes them with its own context.
*/}}

{{/* Generated from the root VERSION file (deploy/helm/sync-version.sh). */}}
{{- define "nospy.appVersion" -}}0.2.0{{- end -}}

{{- define "nospy.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default (include "nospy.appVersion" .) }}
{{- end -}}

{{/* A route prefix as a DNS-label-safe name. */}}
{{- define "nospy.slug" -}}
{{- . | trimPrefix "/" | lower | regexReplaceAll "[^a-z0-9]+" "-" | trimAll "-" | trunc 40 | trimSuffix "-" -}}
{{- end -}}

{{- define "nospy.validate" -}}
{{- if not (has .Values.mode (list "sidecar" "service")) -}}
{{- fail (printf "mode must be sidecar or service, got %q" (toString .Values.mode)) -}}
{{- end -}}
{{- range .Values.routes -}}
{{- if eq (.keyMode | default "passthrough") "inject" -}}
{{- if not (and .keySecret .keySecret.name .keySecret.key) -}}
{{- fail (printf "route %s: keyMode inject needs keySecret {name, key}" .prefix) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Extra checks for mode: service. */}}
{{- define "nospy.validateService" -}}
{{- if not .Values.tls.secretName -}}
{{- if not .Values.tls.insecure -}}
{{- fail "mode service needs tls.secretName (a kubernetes.io/tls Secret), or tls.insecure=true to accept plaintext on the network" -}}
{{- end -}}
{{- end -}}
{{- if and ((.Values.tls.certManager).issuerRef).name (not .Values.tls.secretName) -}}
{{- fail "tls.certManager.issuerRef.name needs tls.secretName: the Secret cert-manager writes the certificate to" -}}
{{- end -}}
{{- if eq .Values.auth.type "none" -}}
{{- fail "mode service refuses auth.type none: anyone who can reach the Service could use it (and any injected key). Use static-tokens" -}}
{{- end -}}
{{- if ne .Values.auth.type "static-tokens" -}}
{{- fail (printf "auth.type must be static-tokens, got %q" (toString .Values.auth.type)) -}}
{{- end -}}
{{- if not .Values.auth.existingSecret -}}
{{- fail "auth.type static-tokens needs auth.existingSecret (a Secret with a name:sha256hex tokens file, see `nospy hash-token`)" -}}
{{- end -}}
{{- end -}}

{{/*
Per-client affinity (plan/21): with more than one replica, nospy forwards each request to the replica
that owns its client, found through a headless Service. Renders "true" or nothing. ctx: dict "Values" v.
Callers gate on service mode themselves.
*/}}
{{- define "nospy.peers" -}}
{{- if gt (int .Values.replicas) 1 -}}true{{- end -}}
{{- end -}}

{{/* Name of the headless Service the replicas find each other through (the 63-character limit applies). ctx: root or a dict with .Release. */}}
{{- define "nospy.peersName" -}}
{{- printf "%s-peers" (.Release.Name | trunc 57 | trimSuffix "-") -}}
{{- end -}}

{{/* serve args as a YAML list. ctx: dict "Values" v "sidecar" bool, plus "Release" for service mode */}}
{{- define "nospy.args" -}}
{{- include "nospy.validate" . -}}
{{- $v := .Values -}}
- --listen
- {{ printf "%s:%d" (ternary "127.0.0.1" "0.0.0.0" .sidecar) (int $v.port) | quote }}
- --auth
- {{ ternary "none" $v.auth.type .sidecar | quote }}
{{- if not $v.metrics.enabled }}
- --metrics=false
{{- end }}
{{- if not .sidecar }}
- --tokens-file
- /etc/nospy/tokens/tokens
{{- if $v.tls.secretName }}
- --tls-cert
- /etc/nospy/tls/tls.crt
- --tls-key
- /etc/nospy/tls/tls.key
{{- else if $v.tls.insecure }}
- --insecure-plaintext
{{- end }}
- --shutdown-timeout
- {{ printf "%ds" (int $v.shutdownTimeoutSeconds) | quote }}
{{- if include "nospy.peers" . }}
- --peers
- {{ printf "%s.%s.svc:%d" (include "nospy.peersName" .) .Release.Namespace (int $v.port) | quote }}
- --peer-self
- "$(POD_IP)"
{{- end }}
{{- end }}
{{- range $v.routes }}
{{- $s := printf "%s=%s" .prefix .upstream }}
{{- if .api }}{{ $s = printf "%s,api=%s" $s .api }}{{ end }}
{{- if eq (.keyMode | default "passthrough") "inject" }}
{{- $s = printf "%s,key-mode=inject,key-file=/etc/nospy/keys/%s/key" $s (include "nospy.slug" .prefix) }}
{{- end }}
- --route
- {{ $s | quote }}
{{- end }}
{{- range $v.providers }}
- --provider
- {{ . | quote }}
{{- end }}
{{- if $v.terms.existingSecret }}
- --terms
- /etc/nospy/terms/terms
{{- end }}
{{- end -}}

{{/* ctx: dict "Values" v "sidecar" bool. Mounts are read-only. */}}
{{- define "nospy.volumeMounts" -}}
{{- $v := .Values -}}
{{- range $v.routes }}
{{- if eq (.keyMode | default "passthrough") "inject" }}
- name: nospy-key-{{ include "nospy.slug" .prefix }}
  mountPath: /etc/nospy/keys/{{ include "nospy.slug" .prefix }}
  readOnly: true
{{- end }}
{{- end }}
{{- if $v.terms.existingSecret }}
- name: nospy-terms
  mountPath: /etc/nospy/terms
  readOnly: true
{{- end }}
{{- if not .sidecar }}
- name: nospy-tokens
  mountPath: /etc/nospy/tokens
  readOnly: true
{{- if $v.tls.secretName }}
- name: nospy-tls
  mountPath: /etc/nospy/tls
  readOnly: true
{{- end }}
{{- end }}
{{- end -}}

{{/* Secret volumes, same ctx. Mode 0444: the files are only mounted into the nospy container. */}}
{{- define "nospy.volumes" -}}
{{- $v := .Values -}}
{{- range $v.routes }}
{{- if eq (.keyMode | default "passthrough") "inject" }}
- name: nospy-key-{{ include "nospy.slug" .prefix }}
  secret:
    secretName: {{ .keySecret.name | quote }}
    defaultMode: 0444
    items:
      - key: {{ .keySecret.key | quote }}
        path: key
{{- end }}
{{- end }}
{{- if $v.terms.existingSecret }}
- name: nospy-terms
  secret:
    secretName: {{ $v.terms.existingSecret | quote }}
    defaultMode: 0444
    items:
      - key: {{ $v.terms.key | quote }}
        path: terms
{{- end }}
{{- if not .sidecar }}
- name: nospy-tokens
  secret:
    secretName: {{ $v.auth.existingSecret | quote }}
    defaultMode: 0444
    items:
      - key: {{ $v.auth.key | quote }}
        path: tokens
{{- if $v.tls.secretName }}
- name: nospy-tls
  secret:
    secretName: {{ $v.tls.secretName | quote }}
    defaultMode: 0444
{{- end }}
{{- end }}
{{- end -}}

{{/* nospy healthcheck as a flow-style exec command, against the sidecar's loopback listener. ctx: dict "Values" v. */}}
{{- define "nospy.healthcheckCommand" -}}
{{- list "/nospy" "healthcheck" "--listen" (printf "127.0.0.1:%d" (int .Values.port)) | toJson -}}
{{- end -}}

{{/*
TCP egress ports the routes need, as a JSON list of ints (sorted, de-duplicated): each route upstream's
explicit port, else 443 for https and 80 for http. Loopback upstreams add none (a NetworkPolicy does not
govern loopback). networkPolicy.extraEgressPorts is merged in. Providers from the built-in table are not
known to the chart, so their ports are not derived. ctx: dict "Values" v.
*/}}
{{- define "nospy.egressPorts" -}}
{{- $ports := list -}}
{{- range .Values.routes -}}
{{- $u := urlParse .upstream -}}
{{- if not (has $u.hostname (list "127.0.0.1" "localhost" "::1")) -}}
{{- /* u.host keeps the brackets of an IPv6 literal, so a trailing :digits is always the port. */}}
{{- $port := regexReplaceAll "^0+" (regexFind ":[0-9]+$" $u.host | trimPrefix ":") "" -}}
{{- $ports = append $ports (ternary (int $port) (ternary 80 443 (eq $u.scheme "http")) (ne $port "")) -}}
{{- end -}}
{{- end -}}
{{- range (.Values.networkPolicy).extraEgressPorts -}}
{{- $ports = append $ports (int .) -}}
{{- end -}}
{{- /* %05d so the alphabetical sort is numeric. */}}
{{- $keys := list -}}
{{- range $ports -}}{{- $keys = append $keys (printf "%05d" (int .)) -}}{{- end -}}
{{- $out := list -}}
{{- range $keys | uniq | sortAlpha -}}{{- $out = append $out (int (regexReplaceAll "^0+" . "")) -}}{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/* The container, for both modes. ctx: dict "Values" v "sidecar" bool. */}}
{{- define "nospy.container" -}}
- name: nospy
  image: {{ include "nospy.image" . | quote }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  {{- if .sidecar }}
  restartPolicy: Always
  {{- end }}
  args:
    {{- include "nospy.args" . | nindent 4 }}
  {{- if and (not .sidecar) (include "nospy.peers" .) }}
  env:
    - name: POD_IP
      valueFrom:
        fieldRef:
          fieldPath: status.podIP
  {{- end }}
  {{- if not .sidecar }}
  ports:
    - name: {{ ternary "https" "http" (not (empty .Values.tls.secretName)) }}
      containerPort: {{ int .Values.port }}
  startupProbe:
    httpGet:
      path: /healthz
      port: {{ ternary "https" "http" (not (empty .Values.tls.secretName)) }}
      scheme: {{ ternary "HTTPS" "HTTP" (not (empty .Values.tls.secretName)) }}
    periodSeconds: 2
    failureThreshold: 30
  livenessProbe:
    httpGet:
      path: /healthz
      port: {{ ternary "https" "http" (not (empty .Values.tls.secretName)) }}
      scheme: {{ ternary "HTTPS" "HTTP" (not (empty .Values.tls.secretName)) }}
    periodSeconds: 10
  readinessProbe:
    httpGet:
      path: /readyz
      port: {{ ternary "https" "http" (not (empty .Values.tls.secretName)) }}
      scheme: {{ ternary "HTTPS" "HTTP" (not (empty .Values.tls.secretName)) }}
    periodSeconds: 5
  {{- else }}
  {{- /* Kubelet probes go to the pod IP and the sidecar listens on loopback, so probe by exec. */}}
  {{- /* The native sidecar is not "started" (the app does not start) until startupProbe passes. */}}
  {{- /* timeoutSeconds covers nospy healthcheck's own 2s default timeout. */}}
  startupProbe:
    exec:
      command: {{ include "nospy.healthcheckCommand" . }}
    periodSeconds: 1
    failureThreshold: 30
    timeoutSeconds: 3
  livenessProbe:
    exec:
      command: {{ include "nospy.healthcheckCommand" . }}
    periodSeconds: 10
    failureThreshold: 3
    timeoutSeconds: 3
  {{- end }}
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
    seccompProfile:
      type: RuntimeDefault
  resources:
    {{- toYaml .Values.resources | nindent 4 }}
  {{- $m := include "nospy.volumeMounts" . | trim }}
  {{- if $m }}
  volumeMounts:
    {{- $m | nindent 4 }}
  {{- end }}
{{- end -}}

{{/*
Native sidecar (initContainers entry with restartPolicy: Always) for an app chart's pod.
  initContainers:
    {{- include "nospy.sidecar" (dict "Values" .Values.nospy "Release" .Release) | nindent 8 }}
Probes are exec (`nospy healthcheck`), since the sidecar listens on loopback, which kubelet httpGet probes (they go to the pod IP) cannot reach.
*/}}
{{- define "nospy.sidecar" -}}
{{- include "nospy.container" (dict "Values" .Values "sidecar" true) -}}
{{- end -}}

{{/* Pod volumes the sidecar needs (key and terms Secrets), same dict as nospy.sidecar. Empty when there are none. */}}
{{- define "nospy.sidecarVolumes" -}}
{{- include "nospy.volumes" (dict "Values" .Values "sidecar" true) | trim -}}
{{- end -}}

{{/* Base-URL env vars for the app container, pointing at the sidecar. Takes the values themselves: .Values.nospy. */}}
{{- define "nospy.sidecarEnv" -}}
{{- include "nospy.sidecarEnvList" . | trim -}}
{{- end -}}

{{- define "nospy.sidecarEnvList" -}}
{{- $v := . -}}
{{- $fams := list (dict "api" "anthropic" "env" "ANTHROPIC_BASE_URL" "suffix" "") (dict "api" "openai" "env" "OPENAI_BASE_URL" "suffix" "/v1") -}}
{{- range $f := $fams }}
{{- $prefix := get ($v.sidecar.envRoutes | default dict) $f.api | default "" }}
{{- if not $prefix }}
{{- range $v.routes }}{{ if and (not $prefix) (eq (.api | default "") $f.api) }}{{ $prefix = .prefix }}{{ end }}{{ end }}
{{- end }}
{{- if $prefix }}
- name: {{ $f.env }}
  value: {{ printf "http://127.0.0.1:%d%s%s" (int $v.port) $prefix $f.suffix | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "nospy.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nospy.labels" -}}
app.kubernetes.io/name: nospy
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "nospy.selectorLabels" -}}
app.kubernetes.io/name: nospy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
