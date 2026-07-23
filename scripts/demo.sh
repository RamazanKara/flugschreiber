#!/usr/bin/env bash
#
# The 30-second demo, exactly as recorded for the README GIF.
#
# Record with:
#   asciinema rec demo.cast -c ./scripts/demo.sh --overwrite
#   agg --cols 92 --rows 30 --font-size 16 --speed 1.0 demo.cast docs/demo.gif
#
# Everything runs against the built-in mock upstream, so there is no model
# server, no GPU and no network call. Set DEMO_SPEED=0 to run it without the
# typing pauses (that is what CI does).

set -euo pipefail

DEMO_SPEED="${DEMO_SPEED:-1}"
WORK="${WORK:-.demo}"
PORT="${PORT:-8080}"
BIN="${BIN:-./dist/flugschreiber}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RESET=$'\033[0m'

pause() { [ "$DEMO_SPEED" != "0" ] && sleep "$(echo "$1 * $DEMO_SPEED" | bc -l)" || true; }

# type_out prints a command the way a person types it, then runs it.
type_out() {
  printf '%s$ %s' "$DIM" "$RESET"
  if [ "$DEMO_SPEED" = "0" ]; then
    printf '%s%s%s\n' "$BOLD" "$1" "$RESET"
  else
    local i
    for ((i = 0; i < ${#1}; i++)); do
      printf '%s%s%s' "$BOLD" "${1:$i:1}" "$RESET"
      sleep 0.018
    done
    printf '\n'
  fi
  pause 0.35
}

say() { printf '\n%s# %s%s\n\n' "$GREEN" "$1" "$RESET"; pause 0.6; }

cleanup() {
  [ -n "${SERVE_PID:-}" ] && kill "$SERVE_PID" 2>/dev/null || true
  wait "${SERVE_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$WORK"

if [ ! -x "$BIN" ]; then
  echo "building $BIN" >&2
  mkdir -p "$(dirname "$BIN")"
  CGO_ENABLED=0 go build -o "$BIN" ./cmd/flugschreiber
fi

clear

# ---------------------------------------------------------------------------
say "1. Start Flugschreiber in front of your model server."

type_out "flugschreiber serve --mock-upstream --data-dir ./evidence"
"$BIN" serve --mock-upstream --data-dir "$WORK/evidence" --listen "127.0.0.1:$PORT" \
  > "$WORK/serve.log" 2>&1 &
SERVE_PID=$!

for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.05
done
printf '  listening on :%s  ->  upstream\n' "$PORT"
pause 1.0

# ---------------------------------------------------------------------------
say "2. Point your app at it. One environment variable. No code changes."

type_out "export OPENAI_BASE_URL=http://localhost:$PORT/v1"
pause 0.8

# ---------------------------------------------------------------------------
say "3. Make some calls. One of them streamed."

# Each response is written to a file and then excerpted, rather than piped
# into head. Piping would close the connection early, which the proxy would
# correctly record as a cancelled request — accurate, but not what this demo
# is about.
excerpt() { head -c "$1" "$2"; printf '...\n'; }

type_out "curl \$OPENAI_BASE_URL/chat/completions -d '{\"model\":\"llama-3.1-8b\", ...}'"
curl -s "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo-key' \
  -d '{"model":"llama-3.1-8b","temperature":0.2,
       "messages":[{"role":"user","content":"What is our refund window?"}]}' \
  > "$WORK/out1.json"
excerpt 150 "$WORK/out1.json"
pause 0.7

type_out "curl -N ... '\"stream\": true'"
curl -sN "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo-key' \
  -H 'X-Flugschreiber-Session: sess-demo' \
  -d '{"model":"llama-3.1-8b","stream":true,"stream_options":{"include_usage":true},
       "messages":[{"role":"user","content":"Summarise ticket 8821."}]}' \
  > "$WORK/out2.sse"
excerpt 130 "$WORK/out2.sse"
pause 0.7

type_out "curl \$OPENAI_BASE_URL/embeddings -d '{\"model\":\"bge-m3\", ...}'"
curl -s "http://127.0.0.1:$PORT/v1/embeddings" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer other-key' \
  -d '{"model":"bge-m3","input":["contract clause 4","contract clause 5"]}' \
  > "$WORK/out3.json"
excerpt 120 "$WORK/out3.json"
pause 1.0

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

# ---------------------------------------------------------------------------
say "4. Verify the evidence. No server needed — this reads files."

type_out "flugschreiber verify --dir ./evidence"
"$BIN" verify --dir "$WORK/evidence"
pause 1.4

# ---------------------------------------------------------------------------
say "5. Now edit one byte of the log, the way a bad actor would."

type_out "sed -i 's/llama-3.1-8b/llama-3.1-7b/' ./evidence/seg-00000001.jsonl"
cp -r "$WORK/evidence" "$WORK/tampered"
sed -i.bak 's/llama-3.1-8b/llama-3.1-7b/' "$WORK/tampered/seg-00000001.jsonl"
rm -f "$WORK/tampered/seg-00000001.jsonl.bak"
pause 0.5

type_out "flugschreiber verify --dir ./evidence"
"$BIN" verify --dir "$WORK/tampered" || true
pause 1.6

# ---------------------------------------------------------------------------
say "6. Generate the documentation, pre-filled from real traffic."

type_out "flugschreiber report --dir ./evidence --out ./reports"
"$BIN" report \
  --dir "$WORK/evidence" \
  --out "$WORK/reports" \
  --organisation "Muster GmbH" \
  --system-name "Support Assistant" \
  --purpose "drafting first-line support replies for human review" \
  --contact "ai-governance@muster.example"
pause 1.8

type_out "head -32 ./reports/technical-documentation.md"
head -32 "$WORK/reports/technical-documentation.md"
pause 2.5

printf '\n%sEvidence and documentation inputs. Not a compliance certificate.%s\n\n' "$DIM" "$RESET"
pause 1.5
