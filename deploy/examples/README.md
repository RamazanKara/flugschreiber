# Raw manifests

For people who do not use Helm, and for reading. Everything here is what the
chart in `../helm/flugschreiber` renders, with the templating taken out.

```
central/    one Deployment in front of the model server. Start here.
sidecar/    one recorder per application pod.
values/     example values files for the Helm chart.
```

## Central

```bash
kubectl apply -n ai -f central/
```

Then point applications at `http://flugschreiber.ai.svc.cluster.local:8080/v1`
instead of at the model server.

Read `central/networkpolicy-model-server.yaml` before you decide you are
finished. Everything else in this directory produces a log. That file is what
makes the log evidence, because it is what stops an application with the old
base URL in a ConfigMap from going around the proxy without anyone noticing.

Two things to change before applying:

- `central/deployment.yaml` points `FLUGSCHREIBER_UPSTREAM` at
  `http://vllm.ai.svc.cluster.local:8000`.
- `central/networkpolicy-model-server.yaml` selects pods labelled `app: vllm`
  on port 8000.

## Sidecar

```bash
kubectl apply -n apps -f sidecar/
```

The application talks to `127.0.0.1:8080` and needs no code change, only two
environment variables.

Know what you are choosing. A NetworkPolicy cannot prove the recorder was not
bypassed here, because policy selects pods and the recorder shares the
application's pod and IP. The application can dial the model server directly
and nothing will report that it did. Each replica also owns its own chain, so
a StatefulSet with three replicas produces three logs, verified separately,
whose sequence numbers have nothing to do with each other.

Choose it when applications belong to different teams with different retention
or content-mode requirements, or when the evidence has to stay per-application.
Otherwise start central.

Verification is per pod, because the chains are per pod:

```bash
for i in 0 1 2; do
  kubectl exec -n apps support-assistant-$i -c flugschreiber -- \
    flugschreiber verify --dir /var/lib/flugschreiber
done
```

## Verifying from outside the cluster

```bash
kubectl cp ai/flugschreiber-0:/var/lib/flugschreiber ./evidence-copy
flugschreiber verify --dir ./evidence-copy
```

That directory plus the binary is everything an auditor needs. No cluster
access, no running server, and no reason to take your word for anything.

`client-salt` stays in the pod. Without it a recipient can distinguish two
callers but cannot map an identifier back to a credential.
