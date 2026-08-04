# Flugschreiber with Docker Compose

This runs the recording proxy in front of a model server, using a config file
rather than flags. It is the shortest path from nothing to a verifiable evidence
log outside Kubernetes.

## Run it

```bash
docker compose up -d
```

Point an application at `http://localhost:8080` in place of your model server.
Every call it makes is recorded. To try it without an application:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"hello"}]}'
```

## Verify the evidence

The proxy runs read-only, so `verify` runs from a throwaway container mounted on
the same volume:

```bash
docker compose exec flugschreiber \
  flugschreiber verify --dir /var/lib/flugschreiber
```

You should see `hash chain intact`, the record count, and `attestation
attested`.

## Generate the documentation

```bash
docker compose exec flugschreiber \
  flugschreiber report --dir /var/lib/flugschreiber --out /tmp/report --pdf \
    --organisation "Muster GmbH" --system-name "Support Assistant"
docker compose cp flugschreiber:/tmp/report ./report
```

## Hand an auditor a bundle

The image is distroless, so stream the bundle out rather than `docker cp` from a
container that has no `tar`:

```bash
docker compose exec flugschreiber \
  flugschreiber export --dir /var/lib/flugschreiber --out - > evidence.tar.gz
```

The bundle carries the segments, the checkpoints, the anchors and every public
key, plus a `VERIFY.md` that specifies the format so a recipient can check it
without installing anything. See [docs/VERIFYING.md](../../../docs/VERIFYING.md).

## Point it at your own model server

The bundled config targets a commented-out `ollama` service. For a real
deployment, delete that service from `compose.yaml` and set `upstream` in
`config.json` to your endpoint:

```json
{ "upstream": "http://vllm.internal:8000" }
```

If the upstream needs a key the application does not send, add
`"upstream_api_key": "sk-..."`, or better, set `FLUGSCHREIBER_UPSTREAM_API_KEY`
in the environment so it stays out of the file. For several model servers behind
one proxy, use the `upstreams` routing list; for TLS, key custody off the host,
timestamp anchoring and content encryption, see the flags in the main
[README](../../../README.md) and the [configuration reference](../../../docs/STABILITY.md).
