#!/usr/bin/env bash
#
# Sweeps concurrency (1/10/100/500/1000) against a single gateway
# instance (native and legacy, vs. their direct-upstream baselines) --
# deliberately NOT the 3-instance/nginx topology, which run_bench.sh
# already found hits CPU contention on this host even at concurrency 50.
#
# Unlike run_bench.sh's fixed-request-count scenarios, each concurrency
# level here runs for a fixed WALL-CLOCK duration (hey -z), so total
# script cost stays predictable regardless of how many requests a given
# concurrency level manages to complete -- a deliberate methodology
# choice for a sweep, not a shortcut.
#
# This script only ever reports numbers it measured (hey's own output,
# docker stats, and the gateway's own /metrics endpoint). It never
# estimates, extrapolates, or hides a bad result -- if a concurrency
# level shows backpressure/bulkhead rejections, that's reported as the
# actual finding at that level, with the real status-code breakdown.
#
# Usage: bench/run_concurrency_sweep.sh [--keep-up]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
RAW_DIR="$REPO_ROOT/bench/.raw"
RESULTS_FRAGMENT="$RAW_DIR/concurrency-sweep.md"

# shellcheck disable=SC1091
source "$REPO_ROOT/bench/lib.sh"

DURATION="10s"
LEVELS=(1 10 100 500 1000)
REPS=2

KEEP_UP=0
for arg in "$@"; do
  case "$arg" in
    --keep-up) KEEP_UP=1 ;;
    *)
      echo "unknown argument: $arg" >&2
      echo "usage: $0 [--keep-up]" >&2
      exit 1
      ;;
  esac
done

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: '$1' is required but not found on PATH." >&2
    exit 1
  fi
}
require docker
require curl
require hey

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose -f "$COMPOSE_FILE")
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f "$COMPOSE_FILE")
else
  echo "error: neither 'docker compose' nor 'docker-compose' is available." >&2
  exit 1
fi

mkdir -p "$RAW_DIR"

cleanup() {
  if [[ "$KEEP_UP" -eq 0 ]]; then
    echo "==> Tearing down bench containers..." >&2
    "${COMPOSE[@]}" --profile bench down --remove-orphans >/dev/null 2>&1 || true
  else
    echo "==> --keep-up set: leaving bench containers running." >&2
  fi
}
trap cleanup EXIT

echo "==> Building and starting upstream-native + upstream-legacy + gateway-solo..." >&2
"${COMPOSE[@]}" --profile bench up -d --build --wait upstream-native upstream-legacy gateway-solo

# Compose auto-names containers "<project>-<service>-<index>" (no
# container_name: override in docker-compose.yml) -- resolve the actual
# container ID once rather than guessing/hardcoding the name.
GATEWAY_SOLO_CONTAINER="$("${COMPOSE[@]}" ps -q gateway-solo)"
if [[ -z "$GATEWAY_SOLO_CONTAINER" ]]; then
  echo "error: could not resolve gateway-solo's container ID for docker stats sampling." >&2
  exit 1
fi

OS_INFO="$(detect_os | tr '\n' ' ' | sed 's/ *$//')"
CPU_MODEL="$(detect_cpu_model)"
CPU_CORES="$(detect_cpu_cores)"
RAM_GB="$(detect_ram_gb)"
echo "==> Machine: $CPU_MODEL, $CPU_CORES cores, ${RAM_GB} GB RAM, $OS_INFO" >&2

BASELINE_NATIVE_URL="http://localhost:9101/mcp"
BASELINE_LEGACY_URL="http://localhost:9102/mcp"
GATEWAY_URL="http://localhost:8081/mcp"
GATEWAY_METRICS_URL="http://localhost:8081/metrics"

NATIVE_BODY_FILE="$RAW_DIR/native-body.json"
LEGACY_BODY_FILE="$RAW_DIR/legacy-body.json"
cat >"$NATIVE_BODY_FILE" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"native.echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
EOF
cat >"$LEGACY_BODY_FILE" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"legacy.echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
EOF

NATIVE_HEADERS=(-H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/call" -H "Mcp-Name: native.echo")
LEGACY_HEADERS=(-H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/call" -H "Mcp-Name: legacy.echo")

echo "==> Establishing one legacy session for the direct-to-upstream baseline..." >&2
LEGACY_SESSION_ID="$(
  curl -s -D - -o /dev/null \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"bench-initialize","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench","version":"1.0"}}}' \
    "$BASELINE_LEGACY_URL" \
  | tr -d '\r' | awk -F': ' 'tolower($1) == "mcp-session-id" { print $2 }'
)"
if [[ -z "$LEGACY_SESSION_ID" ]]; then
  echo "error: failed to obtain an Mcp-Session-Id from the legacy upstream's initialize response." >&2
  exit 1
fi

# Session-reuse totals are cumulative gateway-wide counters; snapshot
# before the sweep starts so the reported rate covers only this run's
# legacy traffic (through the gateway; the baseline never touches the
# session pool).
scrape_metric() {
  local name="$1"
  curl -s "$GATEWAY_METRICS_URL" | awk -v m="$name" '$0 ~ "^"m"{" { sum += $NF } END { print sum+0 }'
}
REUSED_BEFORE="$(scrape_metric portcullis_legacy_session_reused_total)"
CREATED_BEFORE="$(scrape_metric portcullis_legacy_session_created_total)"

# Runs one rep at $concurrency against $url, optionally sampling
# `docker stats` for gateway-solo partway through (only meaningful for
# gateway targets, not direct-upstream baselines).
run_rep() {
  local rep_label="$1" url="$2" body_file="$3" concurrency="$4" sample_stats="$5"
  shift 5
  local headers=("$@")

  hey -z "$DURATION" -c "$concurrency" -m POST -T "application/json" -D "$body_file" "${headers[@]}" "$url" \
    >"$RAW_DIR/${rep_label}.hey.log" 2>&1 &
  local hey_pid=$!

  if [[ "$sample_stats" == "1" ]]; then
    sleep 3
    if kill -0 "$hey_pid" 2>/dev/null; then
      docker stats --no-stream --format '{{.MemUsage}}	{{.CPUPerc}}' "$GATEWAY_SOLO_CONTAINER" 2>/dev/null \
        >>"$RAW_DIR/${rep_label%.rep*}.stats" || true
    fi
  fi

  wait "$hey_pid" || true
  _parse_hey_output "$rep_label" "$(cat "$RAW_DIR/${rep_label}.hey.log")"
}

# Runs both reps for one (label, url, body, concurrency) combination,
# reports the median.
run_level() {
  local label="$1" url="$2" body_file="$3" concurrency="$4" sample_stats="$5"
  shift 5
  local headers=("$@")

  echo "==> ${label} (c=${concurrency}, ${DURATION} x ${REPS} reps)" >&2
  rm -f "$RAW_DIR/${label}.stats"

  local rep
  for rep in 1 2; do
    run_rep "${label}.rep${rep}" "$url" "$body_file" "$concurrency" "$sample_stats" "${headers[@]}"
  done

  local p50 p95 rps
  p50="$(median2 "$(fact "${label}.rep1" p50)" "$(fact "${label}.rep2" p50)")"
  p95="$(median2 "$(fact "${label}.rep1" p95)" "$(fact "${label}.rep2" p95)")"
  rps="$(median2 "$(fact "${label}.rep1" rps)" "$(fact "${label}.rep2" rps)")"
  echo "$p50" >"$RAW_DIR/${label}.p50"
  echo "$p95" >"$RAW_DIR/${label}.p95"
  echo "$rps" >"$RAW_DIR/${label}.rps"

  local statuses
  statuses="$(cat "$RAW_DIR/${label}.rep1.status" "$RAW_DIR/${label}.rep2.status" 2>/dev/null || true)"
  echo "$statuses" >"$RAW_DIR/${label}.status"
}

for level in "${LEVELS[@]}"; do
  run_level "native-baseline-c${level}" "$BASELINE_NATIVE_URL" "$NATIVE_BODY_FILE" "$level" 0 "${NATIVE_HEADERS[@]}"
  run_level "native-gw-c${level}" "$GATEWAY_URL" "$NATIVE_BODY_FILE" "$level" 1 "${NATIVE_HEADERS[@]}"
  run_level "legacy-baseline-c${level}" "$BASELINE_LEGACY_URL" "$LEGACY_BODY_FILE" "$level" 0 "${LEGACY_HEADERS[@]}" -H "Mcp-Session-Id: $LEGACY_SESSION_ID"
  run_level "legacy-gw-c${level}" "$GATEWAY_URL" "$LEGACY_BODY_FILE" "$level" 1 "${LEGACY_HEADERS[@]}"
done

REUSED_AFTER="$(scrape_metric portcullis_legacy_session_reused_total)"
CREATED_AFTER="$(scrape_metric portcullis_legacy_session_created_total)"
REUSED_DELTA=$((REUSED_AFTER - REUSED_BEFORE))
CREATED_DELTA=$((CREATED_AFTER - CREATED_BEFORE))
TOTAL_LEGACY_FORWARDS=$((REUSED_DELTA + CREATED_DELTA))
if [[ "$TOTAL_LEGACY_FORWARDS" -gt 0 ]]; then
  SESSION_REUSE_PCT="$(awk -v r="$REUSED_DELTA" -v t="$TOTAL_LEGACY_FORWARDS" 'BEGIN { printf "%.1f", (r/t)*100 }')"
else
  SESSION_REUSE_PCT="n/a (no legacy forwards through the gateway this run)"
fi

# --- render ------------------------------------------------------------------

stats_summary() {
  local label="$1"
  if [[ ! -s "$RAW_DIR/${label}.stats" ]]; then
    echo "n/a"
    return
  fi
  # Report the raw (mem, cpu%) sample(s) observed for this level as-is --
  # at most one per rep (2 here), so there's little value computing a
  # min/max across possibly-differing memory units (MiB vs GiB); the raw
  # docker stats values speak for themselves.
  paste -sd';' "$RAW_DIR/${label}.stats" | sed $'s/\t/ /g; s/;/; /g'
}

{
  echo "### Concurrency sweep (1 gateway instance, native + legacy)"
  echo
  echo "Machine: $CPU_MODEL, $CPU_CORES cores, ${RAM_GB} GB RAM, $OS_INFO"
  echo
  echo "Method: \`hey -z ${DURATION}\` (duration-bounded, not request-count-bounded --"
  echo "keeps total sweep cost predictable regardless of concurrency), ${REPS} reps"
  echo "per level, median reported. gateway-solo container stats sampled via"
  echo "\`docker stats --no-stream\` partway through each gateway-target rep."
  echo
  echo "| Concurrency | Target | p50 (ms) | p95 (ms) | req/s | Non-200 | gateway-solo mem / cpu |"
  echo "|---:|---|---:|---:|---:|---|---|"
  for level in "${LEVELS[@]}"; do
    for entry in \
      "native-baseline-c${level}|native baseline|0" \
      "native-gw-c${level}|native via gateway|1" \
      "legacy-baseline-c${level}|legacy baseline|0" \
      "legacy-gw-c${level}|legacy via gateway|1"
    do
      lbl="${entry%%|*}"
      rest="${entry#*|}"
      name="${rest%%|*}"
      is_gw="${rest#*|}"

      non200="$(fact "$lbl" status 2>/dev/null | grep -vE '^\[200\]' | tr '\n' ' ' | sed 's/ *$//' || true)"
      [[ -z "$non200" ]] && non200="none"
      stats="n/a"
      [[ "$is_gw" == "1" ]] && stats="$(stats_summary "$lbl")"

      printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
        "$level" "$name" \
        "$(ms "$(fact "$lbl" p50)")" "$(ms "$(fact "$lbl" p95)")" \
        "$(fact "$lbl" rps)" "$non200" "$stats"
    done
  done
  echo
  echo "### Legacy session reuse (whole sweep's legacy-via-gateway traffic)"
  echo
  echo "Sessions reused: ${REUSED_DELTA}, sessions newly created: ${CREATED_DELTA},"
  echo "reuse rate: **${SESSION_REUSE_PCT}%** (\`portcullis_legacy_session_reused_total\`"
  echo "/ \`_created_total\`, scraped from gateway-solo's own \`/metrics\` before and"
  echo "after this sweep)."
} | tee "$RESULTS_FRAGMENT"

echo >&2
echo "==> Concurrency-sweep results fragment written to $RESULTS_FRAGMENT" >&2
echo "==> Raw per-level data under $RAW_DIR/" >&2
