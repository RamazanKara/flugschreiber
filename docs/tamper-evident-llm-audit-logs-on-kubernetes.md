# Tamper-evident LLM audit logs on Kubernetes

Running a recording proxy on Kubernetes raises three questions that do not come
up on a single host: where the evidence lives, how you stop traffic going around
the proxy, and who can read what it wrote.

The Helm chart lands in M2. Everything here works today with plain manifests.

## Two topologies

**Central deployment, in front of the model server.** One Flugschreiber
Deployment, every application points at its Service, a NetworkPolicy stops
anything else reaching the model server.

Use this when you have a small number of model servers and many callers. One
evidence log, one retention policy, one place to look. It is also the only
arrangement where a NetworkPolicy can actually make the proxy unavoidable, which
is the property that matters most.

**Sidecar, next to each application.** Flugschreiber runs in the application
pod, the application talks to `localhost:8080`.

Use this when applications belong to different teams with different retention or
content-mode requirements, or when you need per-application isolation of the
evidence. The cost is one evidence log per application and a NetworkPolicy that
can no longer prove the proxy was not bypassed, because the application could
always dial the model server directly.

Most teams should start central.

## Central deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: flugschreiber
spec:
  replicas: 1
  selector:
    matchLabels: { app: flugschreiber }
  template:
    metadata:
      labels: { app: flugschreiber }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: flugschreiber
          image: ghcr.io/flugschreiber/flugschreiber:latest
          args: ["serve"]
          env:
            - name: FLUGSCHREIBER_UPSTREAM
              value: http://vllm:8000
            - name: FLUGSCHREIBER_DATA_DIR
              value: /var/lib/flugschreiber
            - name: FLUGSCHREIBER_CONTENT_MODE
              value: hash
            - name: FLUGSCHREIBER_RETENTION_DAYS
              value: "365"
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          livenessProbe:
            httpGet: { path: /healthz, port: 8080 }
          readinessProbe:
            httpGet: { path: /readyz, port: 8080 }
          volumeMounts:
            - name: evidence
              mountPath: /var/lib/flugschreiber
      volumes:
        - name: evidence
          persistentVolumeClaim:
            claimName: flugschreiber-evidence
```

The container has no shell and no package manager, so `readOnlyRootFilesystem`
costs nothing. The evidence volume is the only writable path.

`fsGroup: 65532` matters. Without it the mounted volume is root-owned and the
process cannot write, which surfaces as `permission denied` on the first
request rather than at startup.

### Replicas

Run one. Each replica owns its own evidence directory and its own chain, so two
replicas writing to the same ReadWriteMany volume would interleave records and
break the chain immediately.

If one replica is not enough throughput, run several with separate volumes and
verify each chain independently. `verify` takes a directory, so several chains
is an operational inconvenience rather than a correctness problem. Multi-writer
support is not planned, because a single total order is what makes the sequence
numbers mean anything.

### Rolling updates

Use `strategy: type: Recreate`, or accept that a rolling update briefly has two
pods holding the same volume. On shutdown the proxy drains its queue and fsyncs,
so a clean termination loses nothing. Give it enough
`terminationGracePeriodSeconds` (30 is plenty) to finish in-flight streamed
responses.

## Making the proxy unavoidable

This is the part that turns a nice log into evidence.

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
property, not a proxy feature.

Check your CNI actually enforces NetworkPolicy. Several do not by default, and a
policy that is not enforced is worse than no policy, because you will believe it.

## Where the evidence lives

The PVC is the weak point. Anyone who can write to it can rewrite the chain from
scratch, and the chain will verify.

In rough order of how much they help:

**Object storage with a retention lock.** The S3 backend (M2) writes segments to
a bucket with Object Lock in compliance mode. The proxy can write new segments
and cannot alter old ones, which closes the gap the hash chain leaves open.

**Off-host replication as segments close.** A sidecar that copies each rotated
segment to a second system with different credentials. An attacker now needs
both.

**External head hash recording.** A CronJob that runs `verify --json`, extracts
`head_hash`, and posts it somewhere append-only. Cheap, and it pins what the log
said at a known time:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: flugschreiber-verify
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
          containers:
            - name: verify
              image: ghcr.io/flugschreiber/flugschreiber:latest
              args: ["verify", "--dir", "/var/lib/flugschreiber", "--json"]
              volumeMounts:
                - name: evidence
                  mountPath: /var/lib/flugschreiber
                  readOnly: true
          volumes:
            - name: evidence
              persistentVolumeClaim:
                claimName: flugschreiber-evidence
```

The job exits non-zero when the chain is broken, so it alerts through whatever
already watches for failed Jobs. Mount it read-only. A verifier that can write
to what it verifies is not a verifier.

**Restricted access.** Whatever else you do, the set of humans who can write to
this PVC should be smaller than the set who can deploy the application.

## Who can read it

In `hash` mode the evidence contains no prompt text, which makes access control
a governance question rather than a data protection one. In `store` or `redact`
mode it contains conversations, and the PVC becomes a system holding personal
data, with everything that implies: a record of processing activities, a
retention policy, an answer for subject access requests.

Decide this before you turn on `store`, not after.

## Sidecar pattern

```yaml
      containers:
        - name: app
          image: your-app:latest
          env:
            - name: OPENAI_BASE_URL
              value: http://localhost:8080/v1
        - name: flugschreiber
          image: ghcr.io/flugschreiber/flugschreiber:latest
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

Bind to `127.0.0.1` so the sidecar is reachable only from inside the pod.

Two things to know. The application can still reach the model server directly,
so this arrangement records what the application chose to send through it. And
each pod produces its own chain, so a horizontally scaled deployment produces
one log per replica, which you verify separately and which do not share sequence
numbers.

## Verifying from outside the cluster

The point of `verify` reading only files is that it does not need the cluster:

```bash
kubectl cp flugschreiber-0:/var/lib/flugschreiber ./evidence-copy
flugschreiber verify --dir ./evidence-copy
```

Hand that directory and the binary to an auditor and they can run the same
command on their own laptop, with no access to your infrastructure and no reason
to take your word for anything.

Note what does not get copied: `client-salt` stays in the pod. Without it the
recipient can tell two callers apart but cannot map an identifier back to a
credential.

## Resources

The proxy is I/O bound and holds almost nothing in memory, because bodies are
teed rather than buffered.

```yaml
resources:
  requests: { cpu: 100m, memory: 64Mi }
  limits:   { memory: 256Mi }
```

Leave the CPU limit off. A CPU-throttled proxy adds latency to every model call
in the cluster, and the thing you are protecting against with a limit here is
not a real risk.

Evidence volume sizing depends on the content mode. In `hash` mode a record is
around 600 bytes, so a million interactions is well under a gigabyte. In `store`
mode it depends entirely on your prompt sizes; measure for a day before
committing to a PVC size.
