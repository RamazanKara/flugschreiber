{{/*
Name helpers, following the conventions every other chart uses so that
`kubectl get all -l app.kubernetes.io/name=flugschreiber` behaves the way an
operator expects.
*/}}
{{- define "flugschreiber.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "flugschreiber.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "flugschreiber.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "flugschreiber.labels" -}}
helm.sh/chart: {{ include "flugschreiber.chart" . }}
{{ include "flugschreiber.selectorLabels" . }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: flugschreiber
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "flugschreiber.selectorLabels" -}}
app.kubernetes.io/name: {{ include "flugschreiber.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector for the proxy pod alone. The verify CronJob's pods carry the same
name and instance labels, so anything that must mean "the proxy pod" and not
"any pod this release owns" has to include the component.
*/}}
{{- define "flugschreiber.proxySelectorLabels" -}}
{{ include "flugschreiber.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end }}

{{- define "flugschreiber.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "flugschreiber.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding the upstream API key and any S3 credentials.
Empty when there is no Secret in play at all.
*/}}
{{- define "flugschreiber.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else if .Values.secret.create }}
{{- include "flugschreiber.fullname" . }}
{{- end }}
{{- end }}

{{- define "flugschreiber.claimName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-evidence" (include "flugschreiber.fullname" .) }}
{{- end }}
{{- end }}

{{- define "flugschreiber.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
The container port, taken from config.listen so the probes, the Service and the
NetworkPolicy cannot drift away from what the process actually binds.
*/}}
{{- define "flugschreiber.port" -}}
{{- $listen := .Values.config.listen | toString -}}
{{- $parts := splitList ":" $listen -}}
{{- $port := last $parts -}}
{{- if not (regexMatch "^[0-9]+$" $port) -}}
{{- fail (printf "config.listen is %q, which has no numeric port. Use \":8080\" or \"0.0.0.0:8080\"." $listen) -}}
{{- end -}}
{{- $port -}}
{{- end }}

{{/*
The FLUGSCHREIBER_* environment. The image already sets LISTEN and DATA_DIR, and
the environment wins over the config file, so both are always set explicitly
here. Otherwise a config file value for either would be silently overridden by
the image's own defaults.

Call with (dict "root" $ "listen" "<addr>").
*/}}
{{- define "flugschreiber.env" -}}
{{- $root := .root -}}
{{- $v := $root.Values -}}
{{- $secret := include "flugschreiber.secretName" $root -}}
{{- $optional := ne $v.secret.existingSecret "" -}}
- name: FLUGSCHREIBER_LISTEN
  value: {{ .listen | quote }}
- name: FLUGSCHREIBER_DATA_DIR
  value: {{ $v.config.dataDir | quote }}
{{- if $v.config.mockUpstream }}
- name: FLUGSCHREIBER_MOCK_UPSTREAM
  value: "true"
{{- else }}
- name: FLUGSCHREIBER_UPSTREAM
  value: {{ $v.config.upstream | quote }}
{{- end }}
- name: FLUGSCHREIBER_CONTENT_MODE
  value: {{ $v.config.contentMode | quote }}
{{- with $v.config.redactPatterns }}
- name: FLUGSCHREIBER_REDACT_PATTERNS
  value: {{ join "," . | quote }}
{{- end }}
- name: FLUGSCHREIBER_RETENTION_DAYS
  value: {{ $v.config.retentionDays | quote }}
{{- if gt (int $v.config.segmentMaxBytes) 0 }}
- name: FLUGSCHREIBER_SEGMENT_MAX_BYTES
  value: {{ $v.config.segmentMaxBytes | quote }}
{{- end }}
- name: FLUGSCHREIBER_LOG_LEVEL
  value: {{ $v.config.logLevel | quote }}
{{- with $v.config.signer }}
- name: FLUGSCHREIBER_SIGNER
  value: {{ . | quote }}
- name: FLUGSCHREIBER_SIGNER_PUBLIC_KEY
  value: {{ $v.config.signerPublicKey | quote }}
{{- end }}
{{- with $v.config.tsaUrl }}
- name: FLUGSCHREIBER_TSA_URL
  value: {{ . | quote }}
{{- end }}
{{- with $v.config.tsaInterval }}
- name: FLUGSCHREIBER_TSA_INTERVAL
  value: {{ . | quote }}
{{- end }}
{{- if gt (int $v.config.retentionMaxBytes) 0 }}
- name: FLUGSCHREIBER_RETENTION_MAX_BYTES
  value: {{ $v.config.retentionMaxBytes | quote }}
{{- end }}
{{- if $v.config.contentEncryption }}
- name: FLUGSCHREIBER_CONTENT_ENCRYPTION
  value: "true"
{{- end }}
{{- /*
Both booleans are always emitted rather than only when true. They decide how
much the log is worth and whether an endpoint is open, so `kubectl describe
pod` should answer both questions without anyone having to know what the
binary's defaults are this release.
*/}}
- name: FLUGSCHREIBER_SIGNING_DISABLED
  value: {{ $v.config.signingDisabled | quote }}
- name: FLUGSCHREIBER_METRICS_ENABLED
  value: {{ $v.metrics.enabled | quote }}
{{- if $v.tls.enabled }}
- name: FLUGSCHREIBER_TLS_CERT_FILE
  value: {{ printf "%s/tls.crt" (trimSuffix "/" $v.tls.mountPath) | quote }}
- name: FLUGSCHREIBER_TLS_KEY_FILE
  value: {{ printf "%s/tls.key" (trimSuffix "/" $v.tls.mountPath) | quote }}
{{- end }}
{{- range $key, $env := dict "organisation" "ORGANISATION" "systemName" "SYSTEM_NAME" "purpose" "PURPOSE" "contact" "CONTACT" "role" "ROLE" "environment" "ENVIRONMENT" }}
{{- $value := index $v.config.deployment $key }}
{{- if $value }}
- name: FLUGSCHREIBER_{{ $env }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}
{{- if $secret }}
{{- if or $v.secret.upstreamApiKey $v.secret.existingSecret }}
- name: FLUGSCHREIBER_UPSTREAM_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $v.secret.keys.upstreamApiKey }}
      optional: {{ $optional }}
{{- end }}
{{- /*
The events token authorises writing human-oversight records into the chain, so
it takes the same route as the upstream key and never the ConfigMap. With an
existingSecret the key is optional and the endpoint is on only if the key is
actually in the Secret, which is why the NOTES cannot promise either way.
*/}}
{{- if or $v.secret.eventsToken $v.secret.existingSecret }}
- name: FLUGSCHREIBER_EVENTS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $v.secret.keys.eventsToken }}
      optional: {{ $optional }}
{{- end }}
{{- if $v.secret.s3.enabled }}
- name: {{ $v.secret.s3EnvNames.accessKeyId }}
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $v.secret.keys.s3AccessKeyId }}
      optional: {{ $optional }}
- name: {{ $v.secret.s3EnvNames.secretAccessKey }}
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $v.secret.keys.s3SecretAccessKey }}
      optional: {{ $optional }}
- name: {{ $v.secret.s3EnvNames.sessionToken }}
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ $v.secret.keys.s3SessionToken }}
      optional: true
{{- end }}
{{- end }}
{{- with $v.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
The rendered JSON config file. The upstream API key and the events token are
deliberately absent: both arrive through the environment from a Secret, because
a ConfigMap is readable by anyone with get on the namespace and is not a place
for a credential. The events token is the sharper of the two, since holding it
means being able to write oversight records into the evidence chain.
*/}}
{{- define "flugschreiber.configJSON" -}}
{{- $v := .Values -}}
{{- $c := dict
      "listen" $v.config.listen
      "data_dir" $v.config.dataDir
      "content_mode" $v.config.contentMode
      "retention_days" (int $v.config.retentionDays)
      "log_level" $v.config.logLevel
      "signing_disabled" $v.config.signingDisabled
      "metrics_enabled" $v.metrics.enabled
      "mock_upstream" $v.config.mockUpstream -}}
{{- with $v.config.checkpointInterval -}}
{{- $_ := set $c "checkpoint_interval" . -}}
{{- end -}}
{{- if not $v.config.mockUpstream -}}
{{- $_ := set $c "upstream" $v.config.upstream -}}
{{- end -}}
{{- with $v.config.upstreamCaFile -}}
{{- $_ := set $c "upstream_ca_file" . -}}
{{- end -}}
{{- if $v.config.upstreamTlsSkipVerify -}}
{{- $_ := set $c "upstream_tls_skip_verify" true -}}
{{- end -}}
{{- with $v.config.redactPatterns -}}
{{- $_ := set $c "redact_patterns" . -}}
{{- end -}}
{{- if gt (int $v.config.segmentMaxBytes) 0 -}}
{{- $_ := set $c "segment_max_bytes" (int64 $v.config.segmentMaxBytes) -}}
{{- end -}}
{{- with $v.config.requestTimeout -}}
{{- $_ := set $c "request_timeout" . -}}
{{- end -}}
{{- with $v.config.shutdownTimeout -}}
{{- $_ := set $c "shutdown_timeout" . -}}
{{- end -}}
{{- if $v.tls.enabled -}}
{{- $_ := set $c "tls_cert_file" (printf "%s/tls.crt" (trimSuffix "/" $v.tls.mountPath)) -}}
{{- $_ := set $c "tls_key_file" (printf "%s/tls.key" (trimSuffix "/" $v.tls.mountPath)) -}}
{{- end -}}
{{- $d := dict -}}
{{- range $key, $field := dict "organisation" "organisation" "systemName" "system_name" "purpose" "purpose" "contact" "contact" "role" "role" "environment" "environment" -}}
{{- $value := index $v.config.deployment $key -}}
{{- if $value -}}
{{- $_ := set $d $field $value -}}
{{- end -}}
{{- end -}}
{{- if $d -}}
{{- $_ := set $c "deployment" $d -}}
{{- end -}}
{{- if and $v.config.archive $v.config.archive.backend (ne $v.config.archive.backend "none") -}}
{{- $a := dict "backend" $v.config.archive.backend -}}
{{- range $key, $field := dict "dir" "dir" "prefix" "prefix" "bucket" "bucket" "region" "region" "endpoint" "endpoint" "addressing" "addressing" "storageClass" "storage_class" "sse" "sse" "sseKmsKeyId" "sse_kms_key_id" "objectLockMode" "object_lock_mode" "objectLockRetainFor" "object_lock_retain_for" -}}
{{- $value := index $v.config.archive $key -}}
{{- if $value -}}
{{- $_ := set $a $field $value -}}
{{- end -}}
{{- end -}}
{{- $_ := set $c "archive" $a -}}
{{- end -}}
{{- toPrettyJson $c }}
{{- end }}

{{/*
The evidence volume, shared by the Deployment and the verify CronJob.
*/}}
{{- define "flugschreiber.evidenceVolume" -}}
{{- if .Values.persistence.enabled -}}
persistentVolumeClaim:
  claimName: {{ include "flugschreiber.claimName" . }}
{{- else -}}
emptyDir: {}
{{- end -}}
{{- end }}

{{/*
Everything that is cheaper to catch at `helm install` than at pod start.
Included from the Deployment in central mode and from the sidecar container
template in sidecar mode, so it runs in both topologies.
*/}}
{{- define "flugschreiber.validate" -}}
{{- $v := .Values -}}
{{- $central := eq $v.mode "central" -}}

{{- if and $central (ne (int $v.replicas) 1) -}}
{{- fail (printf "\n\nreplicas is %v and Flugschreiber runs exactly one writer.\n\nEvery evidence record carries the hash of the record before it, which needs a\nsingle total order over one directory. A Deployment mounts the same claim into\nevery replica, so a second pod appends to the same files with its own sequence\nnumbers and its own head hash. The chain then fails to verify from the first\nconcurrent append onwards, and the failure is indistinguishable from tampering.\n\nIf one pod is not enough throughput, install this chart several times with a\nseparate claim each and verify each chain independently. Multi-writer support\nis not planned, because a single total order is what makes the sequence numbers\nmean anything.\n" $v.replicas)  -}}
{{- end -}}

{{- if and $central (regexMatch "^(127\\.|localhost:|\\[::1\\]:)" ($v.config.listen | toString)) -}}
{{- fail (printf "config.listen is %q, a loopback address. Nothing outside the pod could reach the proxy, and the kubelet probes the pod IP from outside the pod, so the container would fail its liveness probe and restart forever. Use \":8080\" or \"0.0.0.0:8080\". Loopback belongs to the sidecar topology, where sidecar.listen is the value to set." $v.config.listen) -}}
{{- end -}}

{{- if and $v.config.archive $v.config.archive.backend (ne $v.config.archive.backend "none") (not $v.config.file.enabled) -}}
{{- fail (printf "config.archive.backend is %q but config.file.enabled is false. The archive settings reach the binary only through the rendered config file, so this combination would install cleanly and archive nothing. Set config.file.enabled=true." $v.config.archive.backend) -}}
{{- end -}}

{{- if and (eq ($v.config.archive).backend "s3" | default false) (not ($v.config.archive).bucket) -}}
{{- fail "config.archive.backend is s3 but config.archive.bucket is empty. The binary would refuse to start with the same complaint; failing here is just earlier." -}}
{{- end -}}

{{- if and (not $v.config.mockUpstream) (not $v.config.upstream) -}}
{{- fail "config.upstream is required, for example http://vllm:8000. Set config.mockUpstream=true instead only if you are smoke testing the chart with the built-in fake model server." -}}
{{- end -}}

{{- if lt (int $v.config.retentionDays) 180 -}}
{{- fail (printf "config.retentionDays is %v, below the 180 day floor. Article 19 expects at least six months of automatically generated logs where they are under the provider's control, and the binary refuses to start below the floor, so this would be a CrashLoopBackOff rather than a running proxy." $v.config.retentionDays) -}}
{{- end -}}

{{- if and $v.secret.create $v.secret.existingSecret -}}
{{- fail "secret.create and secret.existingSecret are both set. Pick one: existingSecret uses a Secret you manage, create renders one from these values." -}}
{{- end -}}

{{- $s3Data := and $v.secret.s3.enabled (or $v.secret.s3.accessKeyId $v.secret.s3.secretAccessKey $v.secret.s3.sessionToken) -}}
{{- if and $v.secret.create (not (or $v.secret.upstreamApiKey $v.secret.eventsToken $s3Data)) -}}
{{- fail "secret.create is true but no credential would be written, which would render a Secret with no data. Set secret.upstreamApiKey or secret.eventsToken, or set secret.s3.enabled=true alongside the s3 values (they are only written when s3.enabled is true), or leave secret.create=false." -}}
{{- end -}}

{{- if and $v.secret.s3.enabled (not (include "flugschreiber.secretName" .)) -}}
{{- fail "secret.s3.enabled is true but there is no Secret to read from. Set secret.create=true with the s3 values, or point secret.existingSecret at a Secret you manage." -}}
{{- end -}}

{{- if and $v.secret.s3.enabled $v.secret.create (not (and $v.secret.s3.accessKeyId $v.secret.s3.secretAccessKey)) -}}
{{- fail "secret.s3.enabled is true and the chart is creating the Secret, but secret.s3.accessKeyId or secret.s3.secretAccessKey is empty. The container would reference a key that does not exist and never start. Set both, or use secret.existingSecret, where missing keys are tolerated." -}}
{{- end -}}

{{- if and $v.tls.enabled $v.config.file.enabled (hasPrefix (printf "%s/" (trimSuffix "/" $v.config.file.mountPath)) (trimSuffix "/" $v.tls.mountPath)) -}}
{{- fail (printf "tls.mountPath (%s) is inside config.file.mountPath (%s). The kubelet cannot create a mount point inside the read-only ConfigMap volume, so the container would never start. Put the certificate somewhere else, for example /etc/flugschreiber-tls." $v.tls.mountPath $v.config.file.mountPath) -}}
{{- end -}}

{{- if and $v.tls.enabled (not $v.tls.existingSecret) -}}
{{- fail "tls.enabled is true but tls.existingSecret is empty. This chart does not generate certificates; point it at a kubernetes.io/tls Secret." -}}
{{- end -}}

{{- if and (or $v.config.requestTimeout $v.config.shutdownTimeout) (not $v.config.file.enabled) -}}
{{- fail "config.requestTimeout and config.shutdownTimeout have no environment variable, so they are only read from the rendered config file. Set config.file.enabled=true or unset them, rather than shipping a value that does nothing." -}}
{{- end -}}

{{- if and $v.config.checkpointInterval $v.config.signingDisabled -}}
{{- fail (printf "config.checkpointInterval is %q and config.signingDisabled is true. Nothing signs the chain head, so the interval has no effect. Unset one: signingDisabled=false to get the checkpoints, or unset checkpointInterval to say plainly that there are none." $v.config.checkpointInterval) -}}
{{- end -}}

{{- if regexMatch "^0+(ns|us|ms|s|m|h)?$" ($v.config.checkpointInterval | toString) -}}
{{- fail (printf "config.checkpointInterval is %q. Zero does not mean \"never sign\": the binary reads it as unset and falls back to five minutes, so you would get checkpoints you thought you had turned off. Set config.signingDisabled=true if that is what you meant." $v.config.checkpointInterval) -}}
{{- end -}}

{{- if and $central (ne ($v.metrics.path | toString) "/metrics") -}}
{{- fail (printf "metrics.path is %q. The proxy serves the Prometheus exposition on /metrics and has no option to move it, so a monitor pointed anywhere else scrapes an unmatched path, which this proxy forwards upstream rather than refusing. Leave metrics.path at /metrics." $v.metrics.path) -}}
{{- end -}}

{{- if and $central $v.networkPolicy.enabled $v.networkPolicy.monitoring.enabled (not $v.metrics.enabled) -}}
{{- fail "networkPolicy.monitoring.enabled is true but metrics.enabled is false, so the policy opens a path from the monitoring namespace to a proxy that serves no exposition. An unmatched path is proxied upstream rather than refused, which turns that hole into a route to the model server. Set metrics.enabled=true, or turn the monitoring rule off." -}}
{{- end -}}

{{- if and $central $v.verify.enabled (not $v.persistence.enabled) -}}
{{- fail "verify.enabled is true but persistence.enabled is false. The CronJob would get its own empty emptyDir rather than the directory the proxy writes to, verify an empty chain, and report success every hour. Set persistence.enabled=true, or verify.enabled=false if you are only smoke testing." -}}
{{- end -}}

{{- /*
In sidecar mode the evidence lives on the application pod's own volume, which
this chart neither creates nor can name. A scheduled verify or retention Job
therefore has nothing to mount unless it is told the claim explicitly, so an
enabled CronJob without persistence.existingClaim is refused here rather than
installed to run against an empty emptyDir every hour.
*/ -}}
{{- if and (not $central) (or $v.verify.enabled $v.retention.enabled) (not $v.persistence.existingClaim) -}}
{{- fail (printf "mode is sidecar and a scheduled Job is enabled (verify.enabled=%v, retention.enabled=%v), but persistence.existingClaim is empty. In sidecar mode the evidence is written to the application pod's volume, which this chart did not create and cannot guess, so the CronJob has nothing to mount and would verify or prune an empty emptyDir. Set persistence.existingClaim to the claim your application pod uses for the evidence directory, or set verify.enabled=false and retention.enabled=false to run no scheduled Jobs." $v.verify.enabled $v.retention.enabled) -}}
{{- end -}}

{{- if and $central $v.networkPolicy.enabled (not $v.networkPolicy.ingressFrom) -}}
{{- fail "networkPolicy.enabled is true but networkPolicy.ingressFrom is empty, which denies all ingress to the proxy and takes your applications with it. List the namespaces or pods that are allowed to call the proxy." -}}
{{- end -}}

{{- if and $central $v.modelServer.networkPolicy.enabled -}}
{{- $sel := $v.modelServer.networkPolicy.podSelector -}}
{{- if not (or $sel.matchLabels $sel.matchExpressions) -}}
{{- fail "modelServer.networkPolicy.enabled is true but modelServer.networkPolicy.podSelector is empty, which would select every pod in the namespace and cut off far more than the model server. Set the labels of your model server pods, for example matchLabels: {app: vllm}." -}}
{{- end -}}
{{- if not $v.modelServer.networkPolicy.ports -}}
{{- fail "modelServer.networkPolicy.ports is empty, which would allow the proxy to reach the model server on every port and defeat the point of the policy." -}}
{{- end -}}
{{- end -}}

{{- if and $central $v.metrics.serviceMonitor.enabled $v.metrics.podMonitor.enabled -}}
{{- fail "metrics.serviceMonitor.enabled and metrics.podMonitor.enabled are both true, which scrapes the same endpoint twice and doubles every counter you look at. Use one." -}}
{{- end -}}

{{- if and $central (or $v.metrics.serviceMonitor.enabled $v.metrics.podMonitor.enabled) (not $v.metrics.enabled) -}}
{{- fail "a monitor is enabled but metrics.enabled is false. Set metrics.enabled=true so the scrape target exists." -}}
{{- end -}}

{{- if and $v.prometheusRule.enabled (not $v.metrics.enabled) -}}
{{- fail "prometheusRule.enabled is true but metrics.enabled is false. Every alert reads a metric this proxy would not be serving, so the rules would sit on absent data and never fire. Set metrics.enabled=true, or prometheusRule.enabled=false." -}}
{{- end -}}

{{- if and $central $v.podDisruptionBudget.enabled $v.podDisruptionBudget.maxUnavailable $v.podDisruptionBudget.minAvailable -}}
{{- fail "podDisruptionBudget.minAvailable and podDisruptionBudget.maxUnavailable are mutually exclusive. Set one and null the other." -}}
{{- end -}}
{{- end }}
