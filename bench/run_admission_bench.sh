#!/usr/bin/env bash
#
# Measures what the tool-poisoning admission gate costs on the request path.
#
# The design claim being tested is item 4 of the brief: that admission adds
# no meaningful latency because the request path does a cached lookup
# rather than a model call. That claim is only worth making with a number
# attached, so this measures it three ways against the SAME binary, the
# SAME upstream and the SAME machine, varying only the admission config:
#
#   off        -- no admission: block at all (today's behaviour before it)
#   warm       -- admission on, verdict served from the in-process cache
#   cold       -- admission on, cache_ttl 1ns so every request re-reads
#                 Postgres (a deliberately pathological floor, not a
#                 configuration anyone should run)
#
# Unlike the other bench scripts this runs local processes rather than
# CPU-limited containers, because the quantity of interest is a within-run
# A/B: all three arms share every confound, so the delta between them is
# meaningful even though the absolute numbers are not comparable with the
# containerised sections of results.md. That is stated in the output rather
# than left for a reader to infer.
#
# Like the other bench scripts, this only ever prints numbers it measured
# by parsing hey's own output; it never estimates or hardcodes a figure.
#
# Usage: bench/run_admission_bench.sh [--dsn postgres://...]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW_DIR="$REPO_ROOT/bench/.raw"

# shellcheck disable=SC1091
source "$REPO_ROOT/bench/lib.sh"

REQUESTS=3000
CONCURRENCY=25
WARMUP=300
REPS=3

DSN="${PORTCULLIS_ADMISSION_DATABASE_URL:-postgres://$(whoami)@localhost:5432/portcullis_bench}"
for arg in "$@"; do
  case "$arg" in
    --dsn) shift; DSN="$1"; shift ;;
    --dsn=*) DSN="${arg#--dsn=}" ;;
  esac
done

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not found on PATH." >&2; exit 1; }
}
require hey
require go
require psql

mkdir -p "$RAW_DIR"
WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${GW_PID:-}" ]] && kill "$GW_PID" 2>/dev/null || true
  [[ -n "${UP_PID:-}" ]] && kill "$UP_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building the gateway"
go -C "$REPO_ROOT/gateway" build -o "$WORK/portcullis" ./cmd/portcullis

echo "==> starting a native upstream"
cat > "$WORK/upstream.py" <<'PY'
import http.server, json, sys
TOOLS = [{"name": f"tool{i}", "description": f"Benign tool number {i}.",
          "inputSchema": {"type": "object"}} for i in range(25)]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or "{}")
        if body.get("method") == "tools/list":
            payload = {"jsonrpc":"2.0","id":body.get("id"),
                       "result":{"resultType":"complete","tools":TOOLS,"ttlMs":0,"cacheScope":"private"}}
        else:
            payload = {"jsonrpc":"2.0","id":body.get("id"),
                       "result":{"resultType":"complete","content":[{"type":"text","text":"ok"}],
                                 "ttlMs":0,"cacheScope":"private"}}
        out = json.dumps(payload).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def do_GET(self): self.send_response(200); self.send_header("Content-Length","0"); self.end_headers()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 9301), H).serve_forever()
PY
python3 "$WORK/upstream.py" & UP_PID=$!
until curl -sf http://127.0.0.1:9301/healthz >/dev/null 2>&1; do sleep 0.2; done

echo "==> preparing the verdict store"
DB_NAME="${DSN##*/}"
psql -q "${DSN%/*}/postgres" -c "DROP DATABASE IF EXISTS $DB_NAME" -c "CREATE DATABASE $DB_NAME" >/dev/null 2>&1 || true
psql -q "$DSN" -f "$REPO_ROOT/control/migrations/001_admission.sql" >/dev/null

write_config() {  # $1 = output path, $2 = admission block ("" for none)
  cat > "$1" <<YAML
max_inflight: 4096
upstreams:
  - name: bench-native
    namespace: bench
    url: http://127.0.0.1:9301/mcp
    protocol_version: "2026-07-28"
    timeout: 5s
    max_concurrent: 512
$2
YAML
}

start_gateway() {  # $1 = config path
  "$WORK/portcullis" -config "$1" -addr 127.0.0.1:8099 > "$WORK/gw.log" 2>&1 & GW_PID=$!
  until curl -sf http://127.0.0.1:8099/healthz >/dev/null 2>&1; do sleep 0.2; done
}

stop_gateway() { kill "$GW_PID" 2>/dev/null || true; wait "$GW_PID" 2>/dev/null || true; GW_PID=""; }

seed_verdicts() {
  for i in $(seq 0 24); do
    hash=$(psql -tAc "select content_hash from scan_queue where tool_name='tool$i'" "$DSN")
    [[ -z "$hash" ]] && continue
    psql -q "$DSN" -c "INSERT INTO tool_verdicts (namespace, tool_name, content_hash, verdict, produced_by, scanner_fingerprint)
                       VALUES ('bench','tool$i','$hash','benign','layer1','bench')
                       ON CONFLICT DO NOTHING" >/dev/null
  done
}

BODY="$WORK/body.json"
cat > "$BODY" <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bench.tool0","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}
JSON

hey_run() {  # $1 = request count
  hey -n "$1" -c "$CONCURRENCY" -m POST -D "$BODY" \
      -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2026-07-28' \
      -H 'Mcp-Method: tools/call' -H 'Mcp-Name: bench.tool0' \
      http://127.0.0.1:8099/mcp 2>&1
}

run_arm() {  # $1 = label
  local label="$1" rep out
  hey_run "$WARMUP" > /dev/null 2>&1
  for rep in $(seq 1 $REPS); do
    out="$(hey_run "$REQUESTS")"
    # Writes ${label}_rep${rep}.{p50,p95,p99,rps,status} into RAW_DIR, and
    # exits loudly rather than substituting a missing measurement.
    _parse_hey_output "admission_${label}_rep${rep}" "$out"
  done
}

ADMISSION_ON=$(cat <<YAML
admission:
  enabled: true
  database_url: "$DSN"
  refresh_interval: 1h
  cache_ttl: 30s
  on_uncertain: deny
  on_unknown: allow
  on_unavailable: allow
YAML
)
ADMISSION_COLD=${ADMISSION_ON/cache_ttl: 30s/cache_ttl: 1ns}

echo "==> arm 1/3: admission off"
write_config "$WORK/off.yaml" ""
start_gateway "$WORK/off.yaml"
run_arm off
stop_gateway

echo "==> arm 2/3: admission on, warm cache"
write_config "$WORK/warm.yaml" "$ADMISSION_ON"
start_gateway "$WORK/warm.yaml"
seed_verdicts
stop_gateway; start_gateway "$WORK/warm.yaml"   # restart so verdicts are visible from a cold cache
run_arm warm
stop_gateway

echo "==> arm 3/3: admission on, cache disabled (pathological floor)"
write_config "$WORK/cold.yaml" "$ADMISSION_COLD"
start_gateway "$WORK/cold.yaml"
run_arm cold
# Scrape the gate's own histogram while the process is still up -- doing it
# after the shutdown below silently produced an empty section.
curl -s http://127.0.0.1:8099/metrics > "$RAW_DIR/admission_metrics.txt" 2>/dev/null || true
stop_gateway

echo
echo "================ results ================"
echo "machine: $(detect_os | tr '\n' ' ')/ $(detect_cpu_model) / $(detect_cpu_cores) cores"
echo "method:  hey -n $REQUESTS -c $CONCURRENCY, ${WARMUP}-request warmup discarded, median of $REPS"
echo
printf '%-6s %-12s %-12s %-12s %s\n' arm p50 p95 rps statuses
for label in off warm cold; do
  p50=$(median3 "$(fact "admission_${label}_rep1" p50)" "$(fact "admission_${label}_rep2" p50)" "$(fact "admission_${label}_rep3" p50)")
  p95=$(median3 "$(fact "admission_${label}_rep1" p95)" "$(fact "admission_${label}_rep2" p95)" "$(fact "admission_${label}_rep3" p95)")
  rps=$(median3 "$(fact "admission_${label}_rep1" rps)" "$(fact "admission_${label}_rep2" rps)" "$(fact "admission_${label}_rep3" rps)")
  printf '%-6s %-12s %-12s %-12s %s\n' "$label" "$(ms "$p50")ms" "$(ms "$p95")ms" "$rps" "$(fact "admission_${label}_rep1" status | tr '\n' ' ')"
done
echo
OFF_P50=$(median3 "$(fact admission_off_rep1 p50)" "$(fact admission_off_rep2 p50)" "$(fact admission_off_rep3 p50)")
WARM_P50=$(median3 "$(fact admission_warm_rep1 p50)" "$(fact admission_warm_rep2 p50)" "$(fact admission_warm_rep3 p50)")
COLD_P50=$(median3 "$(fact admission_cold_rep1 p50)" "$(fact admission_cold_rep2 p50)" "$(fact admission_cold_rep3 p50)")
echo "added p50, warm cache:  $(awk -v a="$WARM_P50" -v b="$OFF_P50" 'BEGIN{printf "%+.2f", (a-b)*1000}')ms"
echo "added p50, cache off:   $(awk -v a="$COLD_P50" -v b="$OFF_P50" 'BEGIN{printf "%+.2f", (a-b)*1000}')ms"
echo
echo "Admission gate self-reported cost, cache-disabled arm:"
awk '/^portcullis_admission_latency_seconds_(sum|count)/ {print "  " $0}' "$RAW_DIR/admission_metrics.txt" 2>/dev/null || true
awk '/^portcullis_admission_latency_seconds_bucket.*le="0.0001"/ {print "  (requests under 100us) " $0}' "$RAW_DIR/admission_metrics.txt" 2>/dev/null || true
echo
echo "Within-run A/B on one machine with local processes; absolute figures"
echo "are NOT comparable with the containerised sections of results.md."
