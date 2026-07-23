#!/usr/bin/env sh
#
# Lint and render the chart across the value combinations that behave
# differently, and validate the result against the Kubernetes schemas.
#
# Nothing here needs a cluster. `helm template` is a pure function of the chart
# and the values, and kubeconform reads JSON schemas, so this runs the same way
# on a laptop and in CI.
#
# The chart is where the honest defaults live, so it is worth as much as the
# Go code and rots faster: a value renamed in values.yaml and not in a template
# produces a chart that installs and a proxy that quietly runs on defaults.
#
# Usage: deploy/helm/check.sh [chart-directory]
#
# Needs helm 3.16 or later for --skip-schema-validation, which is how the
# checks below reach the template's own validation with values the schema
# would have rejected first.

set -eu

chart=${1:-deploy/helm/flugschreiber}
examples=$(dirname "$chart")/../examples

if [ ! -f "$chart/Chart.yaml" ]; then
  echo "no chart at $chart. Run this from the repository root, or pass the chart directory." >&2
  exit 1
fi

if ! command -v helm >/dev/null 2>&1; then
  echo "SKIP: helm is not installed, so the chart was not checked."
  echo "      Install it from https://helm.sh/docs/intro/install/ and run this again."
  exit 0
fi

echo "helm: $(helm version --short 2>/dev/null || helm version)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out="$work/rendered"
mkdir -p "$out"

fail=0
render() {
  name=$1
  shift
  if helm template check "$chart" "$@" >"$out/$name.yaml" 2>"$out/$name.err"; then
    printf '  ok    %s\n' "$name"
  else
    printf '  FAIL  %s\n' "$name"
    sed 's/^/        /' "$out/$name.err"
    rm -f "$out/$name.yaml"
    fail=1
  fi
}

# Rendering must also fail when it is supposed to. Every check in
# flugschreiber.validate exists because the mistake it catches is expensive at
# runtime, and a check that has stopped firing looks exactly like a chart with
# no problems.
refuse() {
  name=$1
  expect=$2
  shift 2
  if helm template check "$chart" "$@" >/dev/null 2>"$out/$name.err"; then
    printf '  FAIL  %s rendered, and it should have been refused\n' "$name"
    fail=1
  elif grep -q "$expect" "$out/$name.err"; then
    printf '  ok    %s refused\n' "$name"
  else
    printf '  FAIL  %s was refused for the wrong reason (wanted %s)\n' "$name" "$expect"
    sed 's/^/        /' "$out/$name.err"
    fail=1
  fi
}

echo
echo "helm lint"
helm lint "$chart" --set config.upstream=http://vllm.models.svc:8000 --quiet || fail=1
helm lint "$chart" --set config.mockUpstream=true --quiet || fail=1

echo
echo "helm template"

render minimal \
  --set config.upstream=http://vllm.models.svc:8000

render smoke -f "$examples/values/smoke-test.yaml"

# --api-versions instead of skipCRDCheck, so the Capabilities branch that the
# monitors gate on is the one exercised.
render production \
  -f "$examples/values/central-production.yaml" \
  --api-versions monitoring.coreos.com/v1

render skip-crd-check \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set metrics.podMonitor.enabled=true \
  --set metrics.podMonitor.skipCRDCheck=true

# Everything the chart can render at once, including the paths that only exist
# when a Secret, a ConfigMap and a certificate are all in play.
render full \
  --set config.upstream=https://vllm.models.svc:8443 \
  --set config.contentMode=redact \
  --set 'config.redactPatterns={email,iban}' \
  --set config.retentionDays=365 \
  --set config.checkpointInterval=1m \
  --set config.segmentMaxBytes=67108864 \
  --set config.file.enabled=true \
  --set config.requestTimeout=10m \
  --set config.shutdownTimeout=15s \
  --set config.deployment.organisation="Muster GmbH" \
  --set secret.create=true \
  --set secret.upstreamApiKey=sk-not-a-real-key \
  --set secret.eventsToken=not-a-real-token \
  --set secret.s3.enabled=true \
  --set secret.s3.accessKeyId=AKIAEXAMPLE \
  --set secret.s3.secretAccessKey=example \
  --set tls.enabled=true \
  --set tls.existingSecret=flugschreiber-tls \
  --set podDisruptionBudget.enabled=true \
  --set networkPolicy.enabled=true \
  --set 'networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=apps' \
  --set networkPolicy.monitoring.enabled=true \
  --set networkPolicy.egress.enabled=true \
  --set modelServer.networkPolicy.enabled=true \
  --set modelServer.networkPolicy.podSelector.matchLabels.app=vllm \
  --set metrics.serviceMonitor.enabled=true \
  --api-versions monitoring.coreos.com/v1

# An existing Secret takes a different branch: the keys become optional, so the
# events endpoint is live only if the key is really there.
render existing-secret \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set secret.existingSecret=flugschreiber-credentials

render signing-off \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set config.signingDisabled=true \
  --set metrics.enabled=false

echo
echo "helm template, sidecar topology"

# `mode: sidecar` renders no objects, which is the point of it and also means
# the named templates in _sidecar.tpl are never reached by a plain render. They
# are the part of the chart another team's chart depends on, so a copy of the
# chart gets one throwaway template that calls all three.
sidecar_chart="$work/sidecar-chart"
cp -R "$chart" "$sidecar_chart"
cat >"$sidecar_chart/templates/zz-sidecar-render.yaml" <<'PROBE'
{{- if eq .Values.mode "sidecar" }}
apiVersion: v1
kind: Pod
metadata:
  name: sidecar-render-check
spec:
  volumes:
    - name: {{ .Values.sidecar.volumeName }}
      emptyDir: {}
  initContainers:
    {{- include "flugschreiber.sidecar.container" . | nindent 4 }}
  containers:
    - name: app
      image: example.invalid/app:latest
      env:
        {{- include "flugschreiber.sidecar.appEnv" . | nindent 8 }}
      volumeMounts:
        {{- include "flugschreiber.sidecar.volumeMounts" . | nindent 8 }}
{{- end }}
PROBE

for listen in 127.0.0.1:8080 localhost:8080 '[::1]:8080'; do
  name=$(echo "sidecar-$listen" | tr -c 'a-zA-Z0-9-' '-')
  if helm template check "$sidecar_chart" \
      --set mode=sidecar \
      --set config.upstream=http://vllm.models.svc:8000 \
      --set sidecar.nativeSidecar=true \
      --set "sidecar.listen=$listen" >"$out/$name.yaml" 2>"$out/$name.err"; then
    # The URL the application is told to use has to name the address the
    # recorder actually bound. Anything else is a pod whose model calls fail,
    # or worse, a pod that falls back to the model server and is not recorded.
    if grep -Fq "http://$listen/v1" "$out/$name.yaml"; then
      printf '  ok    %s\n' "$name"
    else
      printf '  FAIL  %s: appEnv does not point at %s\n' "$name" "$listen"
      grep -i 'OPENAI_BASE_URL' -A1 "$out/$name.yaml" | sed 's/^/        /'
      fail=1
    fi
  else
    printf '  FAIL  %s\n' "$name"
    sed 's/^/        /' "$out/$name.err"
    fail=1
  fi
done

echo
echo "renders that must be refused"

refuse two-writers 'one writer' \
  --set config.upstream=http://vllm.models.svc:8000 --set replicas=2

refuse retention-below-floor '180 day floor' \
  --set config.upstream=http://vllm.models.svc:8000 --set config.retentionDays=30 \
  --skip-schema-validation

refuse no-upstream 'config.upstream is required' \
  --set config.retentionDays=180

refuse checkpoint-without-signing 'no effect' \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set config.checkpointInterval=1m --set config.signingDisabled=true

refuse zero-checkpoint-interval 'Zero does not mean' \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set config.checkpointInterval=0s

refuse metrics-path-moved 'metrics.path' \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set metrics.path=/telemetry --skip-schema-validation

refuse monitoring-hole-without-metrics 'serves no exposition' \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set metrics.enabled=false \
  --set networkPolicy.enabled=true \
  --set 'networkPolicy.ingressFrom[0].podSelector.matchLabels.app=caller' \
  --set networkPolicy.monitoring.enabled=true

refuse empty-secret 'no credential would be written' \
  --set config.upstream=http://vllm.models.svc:8000 --set secret.create=true

refuse verify-without-persistence 'verify an empty chain' \
  --set config.upstream=http://vllm.models.svc:8000 --set persistence.enabled=false

echo
echo "credentials stay out of the ConfigMap"

# The events token authorises appending oversight records to the chain, so a
# copy of it in a ConfigMap is readable by anyone with get on the namespace.
leaked=0
for f in "$out"/*.yaml; do
  [ -f "$f" ] || continue
  hits=$(awk '/^kind: ConfigMap$/{c=1} /^---$/{c=0} c && /not-a-real-token|sk-not-a-real-key/' "$f")
  if [ -n "$hits" ]; then
    printf '  FAIL  a credential appears in a ConfigMap in %s\n' "$(basename "$f")"
    printf '%s\n' "$hits" | sed 's/^/        /'
    leaked=1
    fail=1
  fi
done
[ "$leaked" -eq 0 ] && echo "  ok    no credential in any rendered ConfigMap"

echo
echo "the settings reach the container"

# A knob that is documented in values.yaml but never read by a template is the
# failure this whole file exists to catch: the chart installs, the schema is
# happy, and the proxy runs on the binary's defaults. Refusing bad values does
# not prove the good ones are passed on, so each one is asserted where it has
# to appear.
present() {
  file=$1
  what=$2
  pattern=$3
  if grep -Fq -e "$pattern" "$out/$file.yaml" 2>/dev/null; then
    printf '  ok    %s\n' "$what"
  else
    printf '  FAIL  %s: %s is not in %s.yaml\n' "$what" "$pattern" "$file"
    fail=1
  fi
}

present full 'events token as a secretKeyRef' 'name: FLUGSCHREIBER_EVENTS_TOKEN'
present full 'events token reads secret key events-token' 'key: events-token'
present full 'checkpoint interval as a flag' '- --checkpoint-interval'
present full 'signing state is stated on the pod' 'name: FLUGSCHREIBER_SIGNING_DISABLED'
present full 'metrics state is stated on the pod' 'name: FLUGSCHREIBER_METRICS_ENABLED'
present full 'checkpoint interval in the config file' '"checkpoint_interval": "1m"'

# The name alone would pass with any value, and the value is the whole point.
env_is() {
  file=$1
  name=$2
  want=$3
  got=$(awk -v n="name: $name" '$0 ~ n {found=1; next} found {print; exit}' "$out/$file.yaml" 2>/dev/null)
  case $got in
    *"value: \"$want\""*)
      printf '  ok    %s is %s in %s\n' "$name" "$want" "$file" ;;
    *)
      printf '  FAIL  %s in %s.yaml: wanted %s, got %s\n' "$name" "$file" "$want" "${got:-nothing}"
      fail=1 ;;
  esac
}

env_is signing-off FLUGSCHREIBER_SIGNING_DISABLED true
env_is signing-off FLUGSCHREIBER_METRICS_ENABLED false
env_is minimal FLUGSCHREIBER_SIGNING_DISABLED false
env_is minimal FLUGSCHREIBER_METRICS_ENABLED true

echo
echo "kubeconform"

if ! command -v kubeconform >/dev/null 2>&1; then
  echo "  SKIP: kubeconform is not installed, so the rendered manifests were not"
  echo "        schema checked. https://github.com/yannh/kubeconform"
else
  # kubeconform reads its schemas over the network. A build should not go red
  # because a schema host was briefly unreachable, so reachability is probed
  # first and an unreachable host is a skip rather than a failure.
  probe=$(printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\n')
  if ! printf '%s' "$probe" | kubeconform -strict - >/dev/null 2>&1; then
    echo "  SKIP: kubeconform cannot reach its schemas. Not failing the build for that."
  else
    for f in "$out"/*.yaml; do
      [ -f "$f" ] || continue
      # CustomResourceDefinitions this chart does not own, ServiceMonitor and
      # PodMonitor, have no schema here. Skipping them beats vendoring a copy
      # of the Prometheus Operator's CRDs that then goes stale.
      if kubeconform -strict -ignore-missing-schemas -summary "$f" >"$out/kubeconform.log" 2>&1; then
        printf '  ok    %s\n' "$(basename "$f")"
      else
        printf '  FAIL  %s\n' "$(basename "$f")"
        sed 's/^/        /' "$out/kubeconform.log"
        fail=1
      fi
    done

    echo
    echo "kubeconform, raw example manifests"
    for f in "$examples"/central/*.yaml "$examples"/sidecar/*.yaml; do
      [ -f "$f" ] || continue
      if kubeconform -strict -ignore-missing-schemas "$f" >"$out/kubeconform.log" 2>&1; then
        printf '  ok    %s\n' "$(basename "$f")"
      else
        printf '  FAIL  %s\n' "$(basename "$f")"
        sed 's/^/        /' "$out/kubeconform.log"
        fail=1
      fi
    done
  fi
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "chart check failed"
  exit 1
fi
echo "chart check passed"
