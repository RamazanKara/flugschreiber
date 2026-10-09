# Flugschreiber with Docker Compose

This runs the recording proxy in front of a model server, using a config file
rather than flags. Run the commands below from `deploy/examples/docker-compose`.
Before starting, set `upstream` in `config.json` to a reachable server, or
uncomment the `ollama` service, its volume and `depends_on` in `compose.yaml`.
For the bundled Ollama example, pull `llama3.2` after starting the containers
with `docker compose exec ollama ollama pull llama3.2`.

## Run it

```bash
docker compose up -d
```

Point an OpenAI-compatible client at `http://localhost:8080/v1`. Supported
inference endpoints are recorded. To try it without an application:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"hello"}]}'
```

## Verify the evidence

Run the read-only verifier inside the running proxy container:

```bash
docker compose exec flugschreiber \
  flugschreiber verify --dir /var/lib/flugschreiber
```

You should see `hash chain intact` and the record count. Attestation appears
after the first checkpoint (every five minutes by default, or at shutdown).

## Generate the documentation

```bash
docker compose exec flugschreiber \
  flugschreiber report --dir /var/lib/flugschreiber --out /tmp/report --pdf \
    --organisation "Muster GmbH" --system-name "Support Assistant"
docker compose cp flugschreiber:/tmp/report ./report
```

## Hand an auditor a bundle

Stream the bundle without a TTY so its binary bytes reach the file unchanged:

```bash
docker compose exec -T flugschreiber \
  flugschreiber export --dir /var/lib/flugschreiber --out - > evidence.tar.gz
mkdir -p evidence-copy
tar -xzf evidence.tar.gz -C evidence-copy
flugschreiber verify --dir evidence-copy/flugschreiber-evidence
```

The bundle carries the segments, the checkpoints, the anchors and every public
key, plus a `VERIFY.md` that specifies the format so a recipient can check it
without installing anything. See [docs/VERIFYING.md](../../../docs/VERIFYING.md).

## Point it at your own model server

The bundled config targets the optional `ollama` service. To use your own model
server, leave that service commented out and set `upstream` in
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
