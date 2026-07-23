# EU AI Act Article 12 logging for vLLM and Ollama

Article 12 asks that high-risk AI systems technically allow the automatic
recording of events over the system's lifetime. If you run vLLM or Ollama
in-house, this page shows what that looks like in practice and what you still
have to do yourself.

Nothing here is legal advice, and an LLM is not high-risk in itself. Obligations
attach to the use case. This page assumes you have already worked out that they
apply to yours.

## What vLLM and Ollama give you on their own

Both log requests. Neither logs evidence.

vLLM writes request lines to stdout with the request id, token counts and
timings, and exposes Prometheus metrics. Ollama writes similar lines. Both are
designed for operating a server: they answer "is it slow", "is it out of
memory", "how many tokens did that cost". They rotate, they are sampled by
whatever ships them, and nothing about them resists editing.

For Article 12 the gaps that matter are:

- **No integrity.** Anyone who can reach the log file can change it, and nothing
  in the file says so afterwards.
- **No retention floor.** Whatever your log shipper is configured for, which is
  usually 7 to 30 days. Article 19 expects at least six months.
- **Prompts either fully present or fully absent.** vLLM can log prompts, which
  gives you a GDPR problem, or not log them, which gives you no way to tie a
  transcript to an interaction. There is no middle setting.
- **No independent verification.** There is nothing an auditor can run against a
  copy of the log to check it has not been altered.

## Putting Flugschreiber in front of vLLM

```bash
docker run -d --name flugschreiber \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 8080:8080 -v fs-evidence:/var/lib/flugschreiber \
  ghcr.io/ramazankara/flugschreiber:latest \
  serve --upstream http://vllm:8000
```

Then point applications at `http://flugschreiber:8080/v1` instead of
`http://vllm:8000/v1`. Streaming, tool calling and embeddings all work
unchanged, because the proxy relays them rather than reimplementing them.

For Ollama, its OpenAI-compatible endpoint lives under `/v1`:

```bash
flugschreiber serve --upstream http://ollama:11434
```

Ollama's native `/api/generate` and `/api/chat` are not OpenAI-shaped. They pass
through and keep working, but they are not recorded as inference events. If your
applications use the native API, switch them to `/v1` or they will be invisible
in the evidence log.

## What ends up in the log

One record per interaction:

```json
{
  "seq": 42,
  "timestamp": "2026-05-04T08:31:00.123456789Z",
  "prev_hash": "9f2c...",
  "record_hash": "a17b...",
  "event": {
    "event_type": "inference",
    "request_id": "ce71fbc9...",
    "session_id": "sess-42",
    "client_hash": "c140d100...",
    "endpoint": "/v1/chat/completions",
    "upstream": "http://vllm:8000",
    "model_requested": "llama-3.1-8b-instruct",
    "model_served": "llama-3.1-8b-instruct-awq",
    "params": { "temperature": 0.2, "max_tokens": 512 },
    "usage": { "prompt_tokens": 180, "completion_tokens": 64 },
    "finish_reasons": ["stop"],
    "status": 200,
    "latency_ms": 812.4
  }
}
```

Two fields are worth pointing at.

`model_requested` against `model_served` catches substitution. vLLM serving an
AWQ quant under the name the application asked for is normal and fine, and it is
also the kind of thing that is awkward to explain later if nobody wrote it down
at the time.

`client_hash` is a salted hash of the caller's credential. You can attribute
traffic per calling service without the log holding an API key.

## Grouping requests into sessions

The proxy cannot infer that five requests were one conversation. Send a header:

```
X-Flugschreiber-Session: <your conversation id>
```

If your application already has a conversation or case id, use it. This is the
one change that makes `inspect` and per-session reconstruction useful later, and
it is a header, not an SDK.

## Deciding what to do about prompts

The default records a SHA-256 of the request and response bytes and no text.
That is usually right, and it is not the answer for every system.

Keep the default when you need to show that an interaction happened, with which
model and parameters, and you have another system that holds the conversation.
The digest lets you prove that other system's transcript is the transcript of
this interaction.

Use `--content-mode redact` when you need readable transcripts in the evidence
log itself and can accept best-effort masking:

```bash
flugschreiber serve --upstream http://vllm:8000 \
  --content-mode redact --redact-patterns email,iban,credit_card
```

Use `--content-mode store` only when you have a legal basis, a retention policy
and access controls that someone has actually reviewed. Prompts routinely
contain more personal data than the people who write the application expect.

## Making the proxy unavoidable

An evidence log only covers traffic that went through it. On Kubernetes, a
NetworkPolicy that permits ingress to the model server only from the proxy is
what turns "we log our model calls" into a statement you can defend:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vllm-only-via-flugschreiber
spec:
  podSelector:
    matchLabels:
      app: vllm
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: flugschreiber
```

Without something like this, an application that keeps the old base URL in a
config map somewhere will quietly bypass the whole thing, and nothing will
report that it did.

## Checking the log

```bash
flugschreiber verify --dir /var/lib/flugschreiber
```

Exit status 0 means every record hashes to the value it carries and links to its
predecessor. Non-zero means it does not, and the output names the segment, the
line and the sequence number.

This reads files and nothing else. That is the point: an auditor can run it
against a copy, on their own machine, without access to your infrastructure.

Run it on a schedule and record the head hash somewhere the proxy cannot write
to. A chain plus an externally recorded head hash is meaningfully stronger than
a chain alone, because it pins what the log said at a known time.

## What this still does not do

The chain proves the log is internally consistent, not who wrote it. Signed
checkpoints close most of that gap, and they are on by default: verification
checks each signature and checks it against the chain, so a rewrite without the
key leaves behind checkpoints that are validly signed and disagree with the
records they attest to. What remains is an attacker holding the key, which is
why `--signer exec:<command>` exists to keep it off this host, and why the
directory still belongs on append-only or object-lock storage.

Article 12 contemplates logging over the system's lifetime, which includes
events the proxy never sees: model swaps, prompt template changes, retrieval
corpus updates, threshold changes. Those need recording where they happen.

`model_served` and `usage` are what the upstream reported. A model server that
misreports produces a log that faithfully records the misreport.

[MAPPING.md](../MAPPING.md) has the full field-by-field mapping and the rest of
the caveats.
