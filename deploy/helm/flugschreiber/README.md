# Flugschreiber Helm chart

Runs the recording proxy in front of an OpenAI-compatible model server, keeps
its evidence on a volume, re-verifies the hash chain on a schedule, and can
make the proxy the only route to the model server.

It produces evidence and documentation inputs. It does not make anyone
compliant with anything.

```bash
helm install flugschreiber ./deploy/helm/flugschreiber \
  -n ai --create-namespace \
  --set config.upstream=http://vllm.models.svc:8000 \
  --set config.retentionDays=365
```

Then point applications at the Service:

```
OPENAI_BASE_URL=http://flugschreiber.ai.svc.cluster.local:8080/v1
```

## Read these three things first

**Replicas is 1 and the chart will not render anything else.** Every record
carries the hash of the record before it, which needs a single total order over
one directory. A Deployment mounts the same claim into every replica, so a
second pod appends to the same files with its own sequence numbers and its own
head hash, and the chain fails to verify from the first concurrent append
onwards. The failure looks exactly like tampering. If one pod is not enough
throughput, install the chart several times with a separate claim each and
verify each chain independently. `helm install --set replicas=2` fails with
that explanation rather than with a schema error.

**`modelServer.networkPolicy` is what makes coverage a claim you can defend.**
It is off by default, because the chart cannot guess how your model server is
labelled. Until it is on, an application with the old base URL in a ConfigMap
reaches the model directly, is not recorded, and nothing reports that it
happened.

```yaml
modelServer:
  networkPolicy:
    enabled: true
    namespace: models
    podSelector:
      matchLabels: {app: vllm}
    ports:
      - {protocol: TCP, port: 8000}
```

Then check that your CNI enforces NetworkPolicy. Several do not by default, and
an unenforced policy is worse than none, because you will believe it. Test it
by reaching the model server from an unrelated pod and watching it fail.

**Retention has a floor of 180 days**, enforced by `values.schema.json` as well
as by the binary. Article 19 expects at least six months of automatically
generated logs where they are under the provider's control. Failing at
`helm install` is kinder than a CrashLoopBackOff, so both checks exist.

## What gets created

| Object | When |
| --- | --- |
| Deployment | `mode: central`, always. One replica, `Recreate` strategy |
| Service | `mode: central`. ClusterIP on `service.port` |
| ServiceAccount | `serviceAccount.create`. No API token mounted |
| PersistentVolumeClaim | `persistence.enabled` and no `existingClaim`. Annotated `helm.sh/resource-policy: keep` |
| CronJob | `verify.enabled`. Runs `flugschreiber verify` on a read-only mount |
| ConfigMap | `config.file.enabled`. The rendered JSON config, never a credential |
| Secret | `secret.create`. Upstream API key, events token, S3 credentials |
| NetworkPolicy (proxy) | `networkPolicy.enabled` |
| NetworkPolicy (model server) | `modelServer.networkPolicy.enabled` |
| PodDisruptionBudget | `podDisruptionBudget.enabled` |
| ServiceMonitor / PodMonitor | `metrics.*.enabled`, guarded on the CRD |

In `mode: sidecar` none of it is created. See "Sidecar topology" below.

## Values

### Top level

| Key | Default | Description |
| --- | --- | --- |
| `mode` | `central` | `central` renders the Deployment and everything around it. `sidecar` renders nothing and exposes only the named templates |
| `replicas` | `1` | Must be 1. Anything else fails the render with an explanation |
| `nameOverride` | `""` | Override the chart name in resource names |
| `fullnameOverride` | `""` | Override the full resource name |
| `commonLabels` | `{}` | Labels added to every object |
| `commonAnnotations` | `{}` | Annotations added to every object |

### Image

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/ramazankara/flugschreiber` | Image repository |
| `image.tag` | `""` | Empty means the chart's `appVersion`, so the chart version is what moves the image |
| `image.digest` | `""` | `sha256:...`, wins over the tag |
| `image.pullPolicy` | `IfNotPresent` | |
| `image.pullSecrets` | `[]` | e.g. `[{name: ghcr-credentials}]` |

### Proxy configuration

Every value here is passed as a `FLUGSCHREIBER_*` environment variable, and
also written into the ConfigMap when `config.file.enabled` is true. The
environment wins over the file, which is why both are rendered from the same
values and cannot disagree.

| Key | Default | Description |
| --- | --- | --- |
| `config.listen` | `":8080"` | Listen address. The port is read back out to set the container port, the probes and the policies |
| `config.upstream` | `""` | Upstream base URL. Required unless `config.mockUpstream` |
| `config.mockUpstream` | `false` | Built-in fake model server, for a smoke test with no GPU |
| `config.dataDir` | `/var/lib/flugschreiber` | Evidence directory, the only writable path |
| `config.contentMode` | `hash` | `hash`, `store` or `redact`. See below |
| `config.redactPatterns` | `[]` | `email`, `iban`, `credit_card`, `ipv4`, `phone`, or `label=regexp` |
| `config.retentionDays` | `180` | Minimum retention. Hard floor of 180 |
| `config.segmentMaxBytes` | `0` | Segment rotation size. 0 uses the binary's default |
| `config.checkpointInterval` | `""` | How often the chain head is signed, e.g. `1m`. Empty uses the binary's five minutes. Passed as `--checkpoint-interval` |
| `config.signingDisabled` | `false` | Stop signing checkpoints. See below before you touch it |
| `config.logLevel` | `info` | `debug`, `info`, `warn`, `error`. JSON on stderr |
| `config.requestTimeout` | `""` | e.g. `10m`. Needs `config.file.enabled`, there is no environment variable for it |
| `config.shutdownTimeout` | `""` | e.g. `15s`. Same. Keep below `terminationGracePeriodSeconds` |
| `config.deployment.organisation` | `""` | Pre-fills generated documentation. Changes nothing at runtime |
| `config.deployment.systemName` | `""` | |
| `config.deployment.purpose` | `""` | |
| `config.deployment.contact` | `""` | A role address, not a person |
| `config.deployment.role` | `deployer` | `provider` or `deployer` |
| `config.deployment.environment` | `production` | Free text |
| `config.file.enabled` | `false` | Render the config as JSON into a ConfigMap and pass `--config` |
| `config.file.mountPath` | `/etc/flugschreiber` | Where it is mounted, read-only |

`contentMode: hash` keeps a SHA-256 of the exact request and response bytes and
no prompt or completion text at rest. `store` keeps the text verbatim, which
turns the evidence volume into a system holding personal data, with the record
of processing activities, retention policy, access controls and subject access
answers that follow. `redact` is best effort by construction. Decide before you
switch, not after.

#### Signing

Signing is on by default, and the two settings above are the only way to change
that from the chart.

With it on, the proxy generates an Ed25519 key at
`<dataDir>/signing-key.pem` on first start and signs the chain head on a timer,
on every segment rotation and on clean shutdown. Altering the log then means
holding that key as well as the volume, because every checkpoint over a head
hash you changed stops verifying.

With `signingDisabled: true` you keep the hash chain, which detects any edit
that is not a rewrite of everything after it. A rewrite of everything after it
is precisely what somebody with write access to the evidence volume can do. So
the difference is between "this log was not edited" and "this log was not
edited by anyone who does not hold the key". Neither of them proves who wrote
the log in the first place; that is a property of what the proxy observed, not
of the chain.

`checkpointInterval` is the size of the window that a holder of the volume but
not the key can still rewrite: everything appended since the last checkpoint. A
checkpoint is one short line, so a shorter interval is cheap. Setting it while
`signingDisabled` is true fails the render, because nothing would sign, and
setting it to zero fails too, because the binary reads zero as unset and falls
back to five minutes.

### Credentials

Anything set here ends up in the release's stored values, which live in a
Secret in the cluster and in whatever ran the install. Prefer
`secret.existingSecret` and a real secret manager.

| Key | Default | Description |
| --- | --- | --- |
| `secret.create` | `false` | Create a Secret from the values below |
| `secret.existingSecret` | `""` | Use a Secret you manage. Keys are read optionally, so a partial Secret is fine |
| `secret.upstreamApiKey` | `""` | Injected upstream only when the caller sent no `Authorization` header |
| `secret.eventsToken` | `""` | Bearer token for the oversight events endpoint. Empty leaves it returning 404 |
| `secret.s3.enabled` | `false` | Expose S3 credentials as environment variables |
| `secret.s3.accessKeyId` | `""` | |
| `secret.s3.secretAccessKey` | `""` | |
| `secret.s3.sessionToken` | `""` | |
| `secret.keys.*` | see values.yaml | Key names inside the Secret |
| `secret.s3EnvNames.*` | `AWS_ACCESS_KEY_ID` and friends | Environment variable names for the S3 keys |

Configure the archive itself under `config.archive` (backend, bucket, region,
endpoint, object lock). Only the credentials live here: they reach the pod as
the conventional AWS environment variables, which is exactly where the built-in
S3 client looks for them when `config.archive` names no explicit key.

#### Scheduled retention enforcement

`retention.enabled=true` adds a CronJob that runs
`retention --enforce --confirm` daily against a writable evidence mount. It is
off by default because it deletes evidence: whole segments only, oldest first,
only when every record in them is beyond `config.retentionDays`, never while a
`LEGAL_HOLD` file exists, and always leaving `pruned.json` behind so the
surviving chain verifies as pruned rather than broken.

#### The events token

`POST /flugschreiber/v1/events` records what a human did about a model output:
approve, override, reject, escalate, halt or annotate. The record goes into the
same chain as the inference records and is signed with them.

The endpoint returns 404 until `secret.eventsToken` is set, or until the key
named by `secret.keys.eventsToken` appears in `secret.existingSecret`. That
default is deliberate. A writer to the evidence chain that anything reachable
could call would let anyone fabricate "reviewed and approved by Alice", and a
forged record inside a tamper-evident log is worse than no record, because the
chain makes it look authoritative. Setting the token is the decision about who
may make statements about human oversight.

It is a credential and the chart treats it as one. It reaches the container
only as a `secretKeyRef` environment variable, never through the ConfigMap,
whatever `config.file.enabled` is set to. The rendered check in
`deploy/helm/check.sh` greps every ConfigMap the chart can produce for a
sentinel token, so that stays true rather than merely being intended.

Generate one with `openssl rand -hex 32`, put it in a Secret you manage, and
give it only to the systems your reviewers actually use:

```bash
kubectl create secret generic flugschreiber-credentials -n ai \
  --from-literal=upstream-api-key=sk-... \
  --from-literal=events-token=$(openssl rand -hex 32)
```

```yaml
secret:
  existingSecret: flugschreiber-credentials
```

With `existingSecret` both keys are optional, so a Secret holding only one of
them is fine and the events endpoint is live only if the key is really there.
The endpoint refuses `event_type: inference` whatever token you hold: the only
honest source for a record of what a model did is traffic the proxy observed.

### TLS

| Key | Default | Description |
| --- | --- | --- |
| `tls.enabled` | `false` | Serve HTTPS. The chart does not generate certificates |
| `tls.existingSecret` | `""` | A `kubernetes.io/tls` Secret. Required when enabled |
| `tls.mountPath` | `/etc/flugschreiber-tls` | Where it is mounted, read-only. Must not sit inside `config.file.mountPath` |

### Storage

| Key | Default | Description |
| --- | --- | --- |
| `persistence.enabled` | `true` | False means an emptyDir, which deletes the evidence with the pod |
| `persistence.existingClaim` | `""` | Use a claim you created yourself |
| `persistence.storageClass` | `""` | Empty uses the cluster default, `-` disables dynamic provisioning |
| `persistence.accessModes` | `[ReadWriteOnce]` | One writer by construction |
| `persistence.size` | `10Gi` | In `hash` mode a record is around 600 bytes. In `store` mode, measure first |
| `persistence.annotations` | `{}` | |
| `persistence.labels` | `{}` | |
| `persistence.keepOnUninstall` | `true` | Adds `helm.sh/resource-policy: keep`, so `helm uninstall` does not delete evidence you are retaining |

The claim is where this arrangement is weakest. Anyone who can write to it can
recompute the chain from scratch and produce a log that verifies perfectly.
Keep the set of humans who can write to it smaller than the set who can deploy
the application.

### Resources and scheduling

| Key | Default | Description |
| --- | --- | --- |
| `resources.requests.cpu` | `100m` | |
| `resources.requests.memory` | `64Mi` | |
| `resources.limits.memory` | `256Mi` | |
| `terminationGracePeriodSeconds` | `30` | Time to finish streamed responses, drain the queue and fsync |
| `nodeSelector` | `{}` | |
| `tolerations` | `[]` | |
| `affinity` | `{}` | |
| `priorityClassName` | `""` | |
| `dnsPolicy`, `dnsConfig` | `""`, `{}` | Passed through |
| `hostAliases` | `[]` | e.g. a model server outside the cluster |

There is no CPU limit and that is deliberate. Every model call in the cluster
passes through this process, so throttling it adds latency to all of them, and
a process that copies bytes between two sockets is not the workload a CPU limit
protects you from. Set one only if you have measured a reason to.

With a `ReadWriteOnce` claim the verify CronJob has to land on the same node as
the proxy. On most clusters it does, because the volume is already attached
there. If a verify Job sits `Pending` forever, that is why: give it the same
`nodeSelector`, or use a claim that supports it.

### Security context

| Key | Default |
| --- | --- |
| `podSecurityContext.runAsNonRoot` | `true` |
| `podSecurityContext.runAsUser` | `65532` |
| `podSecurityContext.runAsGroup` | `65532` |
| `podSecurityContext.fsGroup` | `65532` |
| `podSecurityContext.fsGroupChangePolicy` | `OnRootMismatch` |
| `podSecurityContext.seccompProfile.type` | `RuntimeDefault` |
| `containerSecurityContext.allowPrivilegeEscalation` | `false` |
| `containerSecurityContext.readOnlyRootFilesystem` | `true` |
| `containerSecurityContext.privileged` | `false` |
| `containerSecurityContext.capabilities.drop` | `[ALL]` |

The image is distroless static: no shell, no package manager, no libc. None of
this costs anything, and `values.schema.json` rejects turning off
`runAsNonRoot`, `readOnlyRootFilesystem` or the privilege escalation settings.

`fsGroup` is the one that bites. Without it the mounted volume is root-owned
and the process cannot write, which surfaces as `permission denied` on the
first request rather than at startup. Segments are written `0640` and the
directory `0750`, so group ownership is also what lets the verify CronJob read
the evidence. `fsGroupChangePolicy: OnRootMismatch` stops the kubelet walking
and chowning months of segments on every pod start.

### Service, account, probes

| Key | Default | Description |
| --- | --- | --- |
| `service.type` | `ClusterIP` | |
| `service.port` | `8080` | |
| `service.nodePort` | `null` | Only for `type: NodePort` |
| `service.annotations`, `service.labels` | `{}` | |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` | |
| `serviceAccount.annotations` | `{}` | e.g. IRSA or Workload Identity for archiving |
| `serviceAccount.automountServiceAccountToken` | `false` | The proxy never calls the Kubernetes API |
| `livenessProbe.enabled` | `true` | `GET /healthz` |
| `readinessProbe.enabled` | `true` | `GET /readyz` |
| `startupProbe.enabled` | `false` | The process listens in milliseconds |
| `*Probe.initialDelaySeconds`, `periodSeconds`, `timeoutSeconds`, `failureThreshold`, `successThreshold` | see values.yaml | |

No Ingress template ships with this chart. Exposing an evidence proxy outside
the cluster is a decision the chart should not make easy.

### Extension points

| Key | Default | Description |
| --- | --- | --- |
| `extraArgs` | `[]` | Appended after `serve` |
| `extraEnv` | `[]` | Never put a credential here |
| `extraEnvFrom` | `[]` | e.g. `[{secretRef: {name: my-secret}}]` |
| `extraVolumes`, `extraVolumeMounts` | `[]` | |
| `podAnnotations`, `podLabels` | `{}` | |

### Scheduled verification

| Key | Default | Description |
| --- | --- | --- |
| `verify.enabled` | `true` | |
| `verify.schedule` | `"0 * * * *"` | |
| `verify.timeZone` | `""` | e.g. `Europe/Berlin`. Kubernetes 1.27 or later |
| `verify.json` | `true` | Emit JSON so the pod log can be scraped for `head_hash` |
| `verify.restartPolicy` | `Never` | |
| `verify.backoffLimit` | `0` | |
| `verify.concurrencyPolicy` | `Forbid` | |
| `verify.startingDeadlineSeconds` | `300` | |
| `verify.activeDeadlineSeconds` | `3600` | |
| `verify.failedJobsHistoryLimit` | `5` | A failed Job is the alert; keep it |
| `verify.successfulJobsHistoryLimit` | `1` | |
| `verify.suspend` | `false` | |
| `verify.resources` | see values.yaml | |
| `verify.podAnnotations`, `verify.podLabels`, `verify.nodeSelector`, `verify.tolerations`, `verify.affinity` | | |
| `verify.extraArgs`, `verify.extraEnv` | `[]` | |

The Job exits non-zero when the chain is broken, so it alerts through whatever
already watches for failed Jobs. The mount is read-only, and not negotiable in
this chart: a verifier that can write to what it verifies is not a verifier.

`restartPolicy: Never` and `backoffLimit: 0` are deliberate. `verify` is a
deterministic function of the files on disk, so a retry cannot produce a
different answer, and a retry that passed after a failure would hide the
failure. Raise `verify.backoffLimit` only if the Jobs you see failing are
failing on volume attachment or image pulls rather than on the chain.

With `--json` the pod log contains `head_hash`. Shipping that to somewhere
append-only outside the cluster pins what the log said at a known time, which
is the cheapest thing you can do about the fact that whoever can write to the
volume can rewrite the chain.

### Network policy

| Key | Default | Description |
| --- | --- | --- |
| `networkPolicy.enabled` | `false` | Restrict who may reach the proxy |
| `networkPolicy.ingressFrom` | `[]` | Peers in the NetworkPolicy `from` schema. Required when enabled |
| `networkPolicy.extraIngressPorts` | `[]` | |
| `networkPolicy.monitoring.enabled` | `false` | Let a Prometheus namespace scrape `/metrics` |
| `networkPolicy.monitoring.namespaceSelector` | `{matchLabels: {kubernetes.io/metadata.name: monitoring}}` | |
| `networkPolicy.monitoring.podSelector` | `{}` | |
| `networkPolicy.egress.enabled` | `false` | Restrict where the proxy may connect |
| `networkPolicy.egress.dns` | `true` | UDP and TCP 53 to `kube-system`. Without it nothing resolves |
| `networkPolicy.egress.rules` | `[]` | Peers in the `to` schema, with their own ports |
| `modelServer.networkPolicy.enabled` | `false` | **The one that matters.** Only the proxy may reach the model server |
| `modelServer.networkPolicy.namespace` | `""` | Empty means the release namespace |
| `modelServer.networkPolicy.podSelector` | `{matchLabels: {}}` | Required when enabled. An empty selector is refused |
| `modelServer.networkPolicy.ports` | `[{protocol: TCP, port: 8000}]` | |
| `modelServer.networkPolicy.additionalIngressFrom` | `[]` | Every entry is a path around the proxy. Keep it short and know why each one is there |

### Metrics

| Key | Default | Description |
| --- | --- | --- |
| `metrics.enabled` | `true` | Sets `FLUGSCHREIBER_METRICS_ENABLED`. Serves the Prometheus exposition on the proxy port |
| `metrics.path` | `/metrics` | The only value that works. The proxy has no setting to move it, so the chart refuses any other |
| `metrics.serviceMonitor.enabled` | `false` | |
| `metrics.podMonitor.enabled` | `false` | Use one or the other, not both |
| `metrics.*.namespace` | `""` | Empty means the release namespace |
| `metrics.*.interval` | `30s` | |
| `metrics.*.scrapeTimeout` | `10s` | |
| `metrics.*.labels`, `annotations` | `{}` | e.g. the `release` label your Prometheus selects on |
| `metrics.*.honorLabels` | `false` | |
| `metrics.*.relabelings`, `metricRelabelings` | `[]` | |
| `metrics.*.skipCRDCheck` | `false` | Render without checking for the CRD, for offline `helm template` |

`metrics.enabled` defaults to true because the binary does, and a chart that
silently turned off an endpoint the same image serves under `docker run` would
be its own kind of surprise. The counters are collected either way; the value
decides whether anything can read them. There is no separate metrics listener,
so the exposition is readable by everything that can reach the proxy. Narrow
that with `networkPolicy.ingressFrom` if it is wider than you want.

Nothing in the exposition carries a prompt, a completion, a client hash or a
session id. The model name is a label, which is worth a thought if your model
names are themselves informative.

Turning `metrics.enabled` off while a scrape is still pointed at the proxy is
worth avoiding. An unmatched path is proxied upstream rather than refused, so
the scrape arrives at the model server, and vLLM serves `/metrics` too. What
you get then is the model server's numbers carrying the proxy's labels, which
is worse than an empty graph because it looks like it is working. The chart
refuses the combination of `networkPolicy.monitoring.enabled` with
`metrics.enabled: false` for that reason.

Enabling a monitor without the Prometheus Operator CRDs fails the render with
an explanation, rather than quietly producing nothing and leaving you to work
out why no metrics arrived. `helm template --api-versions
monitoring.coreos.com/v1` renders them offline; `skipCRDCheck` is the blunter
way.

### Disruption

| Key | Default | Description |
| --- | --- | --- |
| `podDisruptionBudget.enabled` | `false` | |
| `podDisruptionBudget.minAvailable` | `1` | |
| `podDisruptionBudget.maxUnavailable` | `null` | Set this instead of `minAvailable`, not as well |
| `podDisruptionBudget.labels`, `annotations` | `{}` | |

Off by default because with a single replica this is a sharp tool.
`minAvailable: 1` means the pod can never be evicted voluntarily and a node
drain blocks until somebody intervenes. That is right when the NetworkPolicy
has made the proxy the only route to the model server and losing it is an
outage, and wrong when it wedges your cluster maintenance. There is no default
that is right for both.

### Sidecar

| Key | Default | Description |
| --- | --- | --- |
| `sidecar.listen` | `127.0.0.1:8080` | Loopback only, enforced by the schema. `localhost` and `[::1]` are allowed too, and `appEnv` reads the host back out of this value so the application dials whatever the recorder bound |
| `sidecar.containerName` | `flugschreiber` | |
| `sidecar.volumeName` | `flugschreiber-evidence` | The volume itself is yours to declare |
| `sidecar.nativeSidecar` | `false` | Emit `restartPolicy: Always` for an init container. Kubernetes 1.29 or later |

## Sidecar topology

The chart deploys the central topology. For the sidecar topology it exposes
named templates that put a Flugschreiber container into a pod your own chart
owns, so that the two topologies share defaults instead of drifting.

```yaml
# Chart.yaml
dependencies:
  - name: flugschreiber
    version: 0.1.x
    repository: https://flugschreiber.github.io/charts
```

```yaml
# values.yaml
flugschreiber:
  mode: sidecar          # renders no resources of its own
  config:
    upstream: http://vllm.models.svc:8000
    retentionDays: 365
  sidecar:
    volumeName: evidence
    nativeSidecar: true
```

```yaml
# templates/statefulset.yaml
{{- $fs := .Subcharts.flugschreiber }}
spec:
  template:
    spec:
      initContainers:
        {{- include "flugschreiber.sidecar.container" $fs | nindent 8 }}
      containers:
        - name: app
          image: your-app:latest
          env:
            {{- include "flugschreiber.sidecar.appEnv" $fs | nindent 12 }}
  volumeClaimTemplates:
    - metadata: {name: evidence}
      spec:
        accessModes: [ReadWriteOnce]
        resources: {requests: {storage: 10Gi}}
```

| Template | Emits |
| --- | --- |
| `flugschreiber.sidecar.container` | One item of a `containers` or `initContainers` list |
| `flugschreiber.sidecar.volumeMounts` | The mounts the recorder needs, if you build the container yourself |
| `flugschreiber.sidecar.appEnv` | `OPENAI_BASE_URL` and `OPENAI_API_BASE` for the application container |

The sidecar container carries no probes and no port name, unlike the central
Deployment. The kubelet runs HTTP probes against the pod IP from outside the
pod, and this listener is on loopback, so a probe would be refused every time
and restart the container forever. Port names are unique across a pod, so
`http` would collide with the application container beside it.

`.Subcharts.flugschreiber` is the subchart's context: its own values, its
`Chart.yaml` (which is where the default image tag comes from) and your
release. Passing `.` gives the recorder your chart's values and an empty image
tag.

A worked example is in `deploy/examples/sidecar`.

Two properties of this topology, stated plainly because they are easy to miss.
A NetworkPolicy can no longer prove the proxy was not bypassed: policy selects
pods, the recorder shares the application's pod and IP, and no rule can allow
one container while denying the one beside it. And each pod owns its own chain,
so a scaled deployment produces one log per replica, verified separately, whose
sequence numbers mean nothing across pods. Use a StatefulSet with a
`volumeClaimTemplate` so each replica keeps its chain across restarts.

## Upgrading

The strategy is `Recreate`, so an upgrade is a few seconds of downtime while
the old pod releases the volume. That is the price of never having two writers.
Applications get connection errors during the gap, so upgrade the way you would
upgrade the model server itself.

`helm uninstall` leaves the PersistentVolumeClaim behind while
`persistence.keepOnUninstall` is true. Deleting evidence should be a deliberate
act.

## Checking a change to the chart

```bash
make helm            # or ./deploy/helm/check.sh
```

That lints, renders the chart across the value combinations that take different
branches, checks the results against the Kubernetes schemas with kubeconform,
and asserts that the renders which are supposed to be refused still are. It
needs no cluster. A missing helm or kubeconform is reported and skipped rather
than failing, so the message you get is the real one.

The same script runs in CI, which is what stops the chart drifting away from
the binary. Two of its checks are worth knowing about, because they encode
promises rather than syntax: no rendered ConfigMap may contain a credential,
and the sidecar `appEnv` must name the address `sidecar.listen` actually binds.

## Things to check yourself

- Your CNI enforces NetworkPolicy. Test the bypass, do not assume it.
- The verify CronJob can schedule alongside the proxy pod given your claim's
  access mode.
- Something alerts on failed Jobs. The CronJob is only useful if a failure
  reaches a person.
- The evidence volume has a backup or replication story that does not run with
  the same credentials as the proxy.
