{{/*
Named templates for the sidecar topology.

Nothing in this file is rendered by this chart. They exist so that a chart you
own can put a Flugschreiber container into its own pod, using the same values
and the same defaults as the central Deployment, without copying YAML that will
then drift.

Usage. Add this chart as a dependency in your Chart.yaml:

    dependencies:
      - name: flugschreiber
        version: 0.1.x
        repository: https://flugschreiber.github.io/charts

Set `flugschreiber.mode: sidecar` in your values so the subchart renders no
resources of its own, then include the templates in your pod spec:

    {{- $fs := .Subcharts.flugschreiber }}
    spec:
      containers:
        - name: app
          image: your-app:latest
          env:
            {{- include "flugschreiber.sidecar.appEnv" $fs | nindent 12 }}
        {{- include "flugschreiber.sidecar.container" $fs | nindent 8 }}
      volumes:
        - name: flugschreiber-evidence
          persistentVolumeClaim:
            claimName: your-claim

Named templates do not re-scope themselves to the subchart, so they have to be
handed the subchart's context. `.Subcharts.flugschreiber` is that context: the
subchart's own values, its Chart.yaml (which is where the default image tag
comes from) and your release. Passing `.` instead gives the sidecar your
chart's values and an empty image tag.

What you give up by choosing this topology, stated plainly because it is easy
to miss: a NetworkPolicy can no longer prove the proxy was not bypassed. Policy
selects pods, and the sidecar shares the application's pod and IP, so no rule
can allow the recorder while denying the application next to it. The
application can dial the model server directly and nothing will report that it
did. The sidecar records what the application chose to send through it. Each
pod also owns its own chain, so a scaled deployment produces one log per
replica, verified separately, with sequence numbers that mean nothing across
pods.
*/}}

{{/*
The Flugschreiber container, as one item of a `containers` list.
Call with (dict "Values" <subchart values> "Chart" .Chart "Release" .Release).
*/}}
{{- define "flugschreiber.sidecar.container" -}}
{{- include "flugschreiber.validate" . -}}
{{- $v := .Values -}}
{{- $listen := $v.sidecar.listen -}}
- name: {{ $v.sidecar.containerName }}
  image: {{ include "flugschreiber.image" . }}
  imagePullPolicy: {{ $v.image.pullPolicy }}
  {{- if $v.sidecar.nativeSidecar }}
  # A native sidecar starts before the application containers and is stopped
  # after them, so the recorder is running for the whole life of the thing it
  # records. Put this item in `initContainers`, not `containers`.
  restartPolicy: Always
  {{- end }}
  args:
    - serve
    {{- if $v.config.file.enabled }}
    - --config
    - {{ printf "%s/config.json" (trimSuffix "/" $v.config.file.mountPath) }}
    {{- end }}
    {{- with $v.config.checkpointInterval }}
    - --checkpoint-interval
    - {{ . | quote }}
    {{- end }}
    {{- with $v.extraArgs }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  env:
    {{- include "flugschreiber.env" (dict "root" . "listen" $listen) | nindent 4 }}
  {{- with $v.extraEnvFrom }}
  envFrom:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  # No port name, because port names are unique across the whole pod and an
  # application container that already has a port called http would make the
  # pod invalid.
  #
  # No httpGet probe either. The kubelet runs HTTP probes from outside the pod
  # against the pod IP, and this listener is bound to loopback on purpose, so
  # every probe would be refused and the container would restart forever. The
  # image is distroless, so there is no shell for an exec probe. A sidecar that
  # fails to bind exits, which is what the pod sees.
  ports:
    - containerPort: {{ include "flugschreiber.sidecar.port" . }}
      protocol: TCP
  resources:
    {{- toYaml $v.resources | nindent 4 }}
  securityContext:
    {{- toYaml $v.containerSecurityContext | nindent 4 }}
  volumeMounts:
    {{- include "flugschreiber.sidecar.volumeMounts" . | nindent 4 }}
{{- end }}

{{/*
The volume mounts the sidecar needs. The volume itself is yours to declare: a
StatefulSet volumeClaimTemplate keeps the chain across restarts, an emptyDir
throws the evidence away with the pod.
*/}}
{{- define "flugschreiber.sidecar.volumeMounts" -}}
{{- $v := .Values -}}
- name: {{ $v.sidecar.volumeName }}
  mountPath: {{ $v.config.dataDir }}
{{- if $v.config.file.enabled }}
- name: {{ $v.sidecar.volumeName }}-config
  mountPath: {{ $v.config.file.mountPath }}
  readOnly: true
{{- end }}
{{- with $v.extraVolumeMounts }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
The environment an application container needs in order to talk to the sidecar
rather than to the model server. Two variables, no SDK, no application change.
*/}}
{{- define "flugschreiber.sidecar.appEnv" -}}
{{- $v := .Values -}}
{{- $scheme := ternary "https" "http" $v.tls.enabled -}}
{{- $url := printf "%s://%s:%s/v1" $scheme (include "flugschreiber.sidecar.host" .) (include "flugschreiber.sidecar.port" .) -}}
- name: OPENAI_BASE_URL
  value: {{ $url | quote }}
- name: OPENAI_API_BASE
  value: {{ $url | quote }}
{{- end }}

{{/*
The host an application dials to reach the recorder, read back out of
sidecar.listen rather than assumed. The schema allows localhost and the IPv6
loopback as well as 127.0.0.1, and an application pointed at 127.0.0.1 while
the recorder is bound to [::1] gets connection refused on every model call,
which on a pod with no other route to the model server is an outage and on a
pod that has one is silent non-coverage.
*/}}
{{- define "flugschreiber.sidecar.host" -}}
{{- $listen := .Values.sidecar.listen | toString -}}
{{- $host := trimSuffix (printf ":%s" (include "flugschreiber.sidecar.port" .)) $listen -}}
{{- if or (eq $host "") (eq $host "0.0.0.0") (eq $host "[::]") -}}
{{- fail (printf "sidecar.listen is %q, which binds every interface on the pod. A per-pod recorder belongs on loopback, where only its own pod can reach it. Use \"127.0.0.1:8080\" or \"[::1]:8080\"." $listen) -}}
{{- end -}}
{{- $host -}}
{{- end }}

{{- define "flugschreiber.sidecar.port" -}}
{{- $listen := .Values.sidecar.listen | toString -}}
{{- $port := last (splitList ":" $listen) -}}
{{- if not (regexMatch "^[0-9]+$" $port) -}}
{{- fail (printf "sidecar.listen is %q, which has no numeric port. Use \"127.0.0.1:8080\"." $listen) -}}
{{- end -}}
{{- $port -}}
{{- end }}
