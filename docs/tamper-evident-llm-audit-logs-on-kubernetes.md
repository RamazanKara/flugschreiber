# Tamper-evident LLM audit logs on Kubernetes

Running a recording proxy on Kubernetes raises three questions that do not come
up on a single host: where the evidence lives, how you stop traffic going around
the proxy, and who can read what it wrote.

There is a Helm chart in `deploy/helm/flugschreiber`. It answers all three
questions with defaults, refuses the arrangements that quietly break the chain,
and explains itself when it does. The raw manifests are still in
`deploy/examples`, for people who do not use Helm and for reading, because a
templated chart is a poor way to understand what actually gets created.

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

That gets you a Deployment, a Service, a claim, an hourly verification CronJob
and a set of pod and container security settings that cost nothing on a
distroless image. It does not get you coverage. Coverage is the NetworkPolicy,
and it is off by default because the chart cannot guess how your model server is
labelled.

## Two topologies

**Central deployment, in front of the model server.** One Flugschreiber
Deployment, every application points at its Service, a NetworkPolicy stops
anything else reaching the model server. This is `mode: central`, the default.

Use this when you have a small number of model servers and many callers. One
evidence log, one retention policy, one place to look. It is also the only
arrangement where a NetworkPolicy can actually make the proxy unavoidable, which
is the property that matters most.

**Sidecar, next to each application.** Flugschreiber runs in the application
pod, the application talks to loopback.

Use this when applications belong to different teams with different retention or
content-mode requirements, or when you need per-application isolation of the
evidence. The cost is one evidence log per application and a NetworkPolicy that
can no longer prove the proxy was not bypassed, because the application could
always dial the model server directly.

Most teams should start central.

## One writer, always

The chart renders `replicas: 1` and refuses to render anything else.

Every record carries the hash of the record before it, which needs a single
total order over one directory. A Deployment mounts the same claim into every
replica, so a second pod appends to the same files with its own sequence numbers
and its own head hash. The chain then fails to verify from the first concurrent
append onwards, and it fails in a way that is indistinguishable from tampering.

`--set replicas=2` fails at install time with that paragraph rather than at
three in the morning with a verification error. The strategy is `Recreate` for
the same reason: a rolling update would briefly have two pods holding the same
volume.

If one pod is not enough throughput, install the chart several times with a
separate claim each, point different applications at different releases, and
verify each chain on its own. `verify` takes a directory, so several chains cost
operational effort rather than correctness. Multi-writer support is not planned,
because a single total order is what makes the sequence numbers mean anything.

## Making the proxy unavoidable

This is the part that turns a nice log into evidence.

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

Which renders the policy you would otherwise write by hand:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vllm-ingress-only-from-flugschreiber
spec:
  podSelector:
    matchLabels: { app: vllm }
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: flugschreiber }
      ports:
        - protocol: TCP
          port: 8000
```

Without this, an application with the old base URL in a ConfigMap bypasses the
proxy silently, and nothing anywhere reports that it did. Coverage is a network
property, not a proxy feature. The chart says so in its install notes every time
the policy is off, because it is the single easiest thing to leave for later and
the single most expensive thing to have left for later.

The chart refuses an empty `podSelector` here, which would select every pod in
the namespace and cut off far more than the model server, and it refuses an
empty `ports` list, which would allow the proxy to reach the model server on
every port and defeat the point.

Then check your CNI actually enforces NetworkPolicy. Several do not by default,
and a policy that is not enforced is worse than no policy, because you will
believe it. Test it by reaching the model server from an unrelated pod and
watching it fail.

`modelServer.networkPolicy.additionalIngressFrom` exists for the peers that
genuinely need to bypass the proxy, a monitoring namespace scraping the model
server's own metrics being the usual honest example. Every entry in that list is
a path around the recording proxy. Keep it short and know why each one is there.

## Where the evidence lives

The claim is the weak point. Anyone who can write to it can rewrite the chain
from scratch, and the chain will verify.

Signing narrows that, and it is on by default. The proxy generates an Ed25519
key at `<dataDir>/signing-key.pem` on first start and signs the chain head on a
timer, on segment rotation and on clean shutdown. Rewriting the log then means
holding the key as well as the volume. `config.checkpointInterval` is the size
of the window still open to somebody holding only the volume: everything
appended since the last checkpoint. A checkpoint is one short line, so a shorter
interval is cheap.

What none of this proves is authorship. The chain and the signatures say that
these records have not been altered since they were written, by anyone without
the key. They do not say that the records describe every interaction that
happened, and they do not say who produced the text inside them. The first is
what the NetworkPolicy is for. The second is a property of what the proxy
observed, which is why the transparency documents state the content mode rather
than implying the log is a transcript.

In rough order of how much they help:

**Object storage with a retention lock.** The S3 archive backend (`config.archive`) ships sealed segments to
a bucket with Object Lock in compliance mode. The proxy can write new segments
and cannot alter old ones, which closes the gap the hash chain leaves open.

**Off-host replication as segments close.** A sidecar that copies each rotated
segment to a second system with different credentials. An attacker now needs
both.

**External head hash recording.** The chart's CronJob runs `verify --json` on a
read-only mount, hourly by default:

```yaml
verify:
  enabled: true
  schedule: "0 * * * *"
  timeZone: Europe/Berlin
  json: true
```

Ship the `head_hash` from that pod log somewhere append-only outside the
cluster. It is cheap, and it pins what the log said at a known time, which is
the only real answer to "the person who can write to the volume can rewrite the
chain".

Retention has its own CronJob, off by default because it deletes evidence:

```yaml
retention:
  enabled: true
  schedule: "0 3 * * *"
```

It runs `retention --enforce --confirm` against a writable mount, removes whole
segments only when every record in them is beyond `config.retentionDays`,
records the deletion in `pruned.json` so the surviving chain still verifies,
and does nothing at all while a `LEGAL_HOLD` file exists. Turning it on is the
moment the retention policy in your documentation becomes something the
cluster actually does.

The Job exits non-zero when the chain is broken, so it alerts through whatever
already watches for failed Jobs. It runs once with no retry: `verify` is a
deterministic function of files on disk, so a retry cannot produce a different
answer, and a retry that passed after a failure would hide the failure. The
mount is read-only and not negotiable in the chart, because a verifier that can
write to what it verifies is not a verifier.

Make sure something actually watches for failed Jobs. A CronJob nobody alerts on
is a CronJob that proves nothing.

**Restricted access.** Whatever else you do, the set of humans who can write to
this claim should be smaller than the set who can deploy the application. The
chart annotates the claim `helm.sh/resource-policy: keep`, so `helm uninstall`
leaves the evidence behind. Deleting a release should not delete a log you are
retaining for 180 days.

## Who can read it

In `hash` mode the evidence contains no prompt text, which makes access control
a governance question rather than a data protection one. In `store` or `redact`
mode it contains conversations, and the claim becomes a system holding personal
data, with everything that implies: a record of processing activities, a
retention policy, an answer for subject access requests.

Decide this before you turn on `store`, not after. The install notes say it back
to you when you do.

Two credentials go into the pod, and both take the Secret path rather than the
ConfigMap. The upstream API key is the obvious one. The other is
`secret.eventsToken`, which authorises `POST /flugschreiber/v1/events`, the
endpoint that writes human oversight records into the chain. It returns 404
until a token is set, and that default is deliberate: an unauthenticated writer
to the evidence chain would let anyone who can reach the proxy fabricate
"reviewed and approved by Alice", and a forged record inside a tamper-evident
log is worse than no record, because the chain makes it look authoritative.

```bash
kubectl create secret generic flugschreiber-credentials -n ai \
  --from-literal=upstream-api-key=sk-... \
  --from-literal=events-token=$(openssl rand -hex 32)
```

```yaml
secret:
  existingSecret: flugschreiber-credentials
```

Both keys are read optionally, so a Secret holding only one of them is fine.

## Sidecar pattern

The chart renders no objects in `mode: sidecar`. It exposes named templates
instead, so a chart your team owns can put the recorder into its own pod without
copying YAML that will then drift:

```yaml
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

By hand it is two containers and two environment variables:

```yaml
      containers:
        - name: app
          image: your-app:latest
          env:
            - name: OPENAI_BASE_URL
              value: http://127.0.0.1:8080/v1
        - name: flugschreiber
          image: ghcr.io/ramazankara/flugschreiber:latest
          args: ["serve", "--listen", "127.0.0.1:8080"]
          env:
            - name: FLUGSCHREIBER_UPSTREAM
              value: http://vllm:8000
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          volumeMounts:
            - name: evidence
              mountPath: /var/lib/flugschreiber
```

Bind to loopback so the recorder is reachable only from inside the pod, and make
sure the URL you hand the application names the address the recorder actually
bound. `127.0.0.1` and `[::1]` are not the same address, and an application
pointed at the wrong one gets connection refused on every model call. The chart
reads the host back out of `sidecar.listen` so the two cannot disagree.

A native sidecar (`sidecar.nativeSidecar: true`, Kubernetes 1.29 or later) puts
the recorder in `initContainers` with `restartPolicy: Always`, so it starts
before the application and is not killed while the application is still
finishing. That is worth having: a recorder that dies first turns the tail of
every shutdown into unrecorded traffic.

Two things to know. The application can still reach the model server directly,
so this arrangement records what the application chose to send through it. And
each pod produces its own chain, so a horizontally scaled deployment produces
one log per replica, which you verify separately and which do not share sequence
numbers. Use a StatefulSet with a `volumeClaimTemplate` so each replica keeps
its chain across restarts.

## Verifying from outside the cluster

The point of `verify` reading only files is that it does not need the cluster:

```bash
kubectl cp ai/flugschreiber-0:/var/lib/flugschreiber ./evidence-copy
flugschreiber verify --dir ./evidence-copy
```

Hand that directory and the binary to an auditor and they can run the same
command on their own laptop, with no access to your infrastructure and no reason
to take your word for anything.

Note what does not get copied: `client-salt` stays in the pod. Without it the
recipient can tell two callers apart but cannot map an identifier back to a
credential.

## Metrics

The proxy serves Prometheus text exposition on `/metrics` of its own port, on by
default. The chart creates a ServiceMonitor or a PodMonitor when you ask for
one, and fails the render if the Prometheus Operator CRDs are not there rather
than producing nothing and leaving you to work out why no metrics arrived.

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack
```

There is no separate metrics listener, so the exposition is readable by anything
that can reach the proxy. Narrow that with `networkPolicy.ingressFrom` if that
set is wider than you want. No metric carries a prompt, a completion, a client
hash or a session id. The model name is a label, which is worth a thought if
your model names are themselves informative.

## Resources

The proxy is I/O bound and holds almost nothing in memory, because bodies are
teed rather than buffered.

```yaml
resources:
  requests: { cpu: 100m, memory: 64Mi }
  limits:   { memory: 256Mi }
```

Leave the CPU limit off, which is what the chart does. A CPU-throttled proxy
adds latency to every model call in the cluster, and a process that copies bytes
between two sockets is not the workload a limit protects you from.

`fsGroup: 65532` matters and the chart sets it. Without it the mounted volume is
root-owned and the process cannot write, which surfaces as `permission denied`
on the first request rather than at startup. Segments are written `0640` and the
directory `0750`, so group ownership is also what lets the verify CronJob read
the evidence.

Evidence volume sizing depends on the content mode. In `hash` mode a record is
around 600 bytes, so a million interactions is well under a gigabyte. In `store`
mode the volume scales with your prompt sizes; measure for a day before
committing to a size.

## Before you call it done

- Your CNI enforces NetworkPolicy. Test the bypass from an unrelated pod rather
  than assuming.
- The verify CronJob can schedule alongside the proxy pod. With a
  `ReadWriteOnce` claim both have to land on the same node, and a verify Job
  that sits `Pending` forever is why.
- Something alerts on failed Jobs.
- The evidence volume has a backup or replication story that does not run with
  the same credentials as the proxy.
- The head hash goes somewhere outside the cluster on a schedule.

None of this makes anyone compliant with anything. It produces evidence and the
inputs to documentation, which is a different and more defensible claim.
