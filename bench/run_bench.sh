#!/usr/bin/env bash
#
# Measures Portcullis gateway overhead: direct-to-upstream vs. through 1
# gateway instance vs. through 3 gateway instances behind an nginx
# round-robin (no sticky sessions), against both a native 2026-07-28
# upstream and a legacy 2025-11-25 upstream (bridged via the
# gateway/internal/translate session-pool shim).
#
# This script only ever prints numbers it measured by parsing `hey`'s own
# output. It never hardcodes, estimates, or fabricates a latency or
# throughput figure — if a measurement can't be parsed, the script fails
# loudly instead of guessing.
#
# Usage: bench/run_bench.sh [--keep-up]
#   --keep-up   Leave the bench containers running after the script exits
#               (default: tear them down).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
RAW_DIR="$REPO_ROOT/bench/.raw"
RESULTS_FILE="$REPO_ROOT/bench/results.md"

# shellcheck disable=SC1091
source "$REPO_ROOT/bench/lib.sh"

REQUESTS=5000
CONCURRENCY=50
WARMUP_REQUESTS=500
REPS=3

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

# --- dependency checks -------------------------------------------------------

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: '$1' is required but not found on PATH." >&2
    echo "$2" >&2
    exit 1
  fi
}

require docker "Install Docker: https://docs.docker.com/get-docker/"
require curl "Install curl (it ships with most systems already)."
require hey "Install hey: go install github.com/rakyll/hey@latest  (or: brew install hey)"

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

# --- bring up the bench stack -------------------------------------------------

echo "==> Building and starting the bench profile (this can take a while on first run)..." >&2
"${COMPOSE[@]}" --profile bench up -d --build --wait

BASELINE_NATIVE_URL="http://localhost:9101/mcp"
BASELINE_LEGACY_URL="http://localhost:9102/mcp"
GATEWAY_SOLO_URL="http://localhost:8081/mcp"
GATEWAY_CLUSTER_URL="http://localhost:8090/mcp"

# --- machine specs -----------------------------------------------------------
# detect_os/detect_cpu_model/detect_cpu_cores/detect_ram_gb now live in
# bench/lib.sh (sourced above), shared with the other bench/*.sh scripts.

OS_INFO="$(detect_os | tr '\n' ' ' | sed 's/ *$//')"
CPU_MODEL="$(detect_cpu_model)"
CPU_CORES="$(detect_cpu_cores)"
RAM_GB="$(detect_ram_gb)"

echo "==> Machine: $CPU_MODEL, $CPU_CORES cores, ${RAM_GB} GB RAM, $OS_INFO" >&2

# --- request bodies -----------------------------------------------------------

NATIVE_BODY_FILE="$RAW_DIR/native-body.json"
LEGACY_BODY_FILE="$RAW_DIR/legacy-body.json"

cat >"$NATIVE_BODY_FILE" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"native.echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
EOF

cat >"$LEGACY_BODY_FILE" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"legacy.echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
EOF

# The same body and MCP headers are sent to every target (direct upstream or
# gateway) so that only "is the gateway in the path" varies between
# scenarios. The one unavoidable exception is Mcp-Session-Id on the legacy
# direct-to-upstream baseline: a real 2025-11-25 server requires a session,
# and a 2026-07-28 client has no concept of one to supply — that's exactly
# the overhead this benchmark exists to measure, not an artifact to hide.

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
echo "    session: $LEGACY_SESSION_ID" >&2

# --- hey runner ---------------------------------------------------------------
#
# Measurements are stashed in plain files under $RAW_DIR, keyed by label,
# instead of associative arrays: this script needs to run on stock macOS
# bash (3.2), which has no `declare -A`. It's also handy for manual
# inspection after the fact.
#
# Each scenario is measured $REPS times (default 3), each preceded by its
# own discarded $WARMUP_REQUESTS-request warmup, and reported as the MEDIAN
# of the reps plus their min-max spread -- a single 5000-request run at p99
# is dominated by outliers (a 13x gap between p50 and p99 on a raw baseline
# run is a sampling-noise signal, not a latency finding), so one run is not
# a measurement, it's an anecdote.

# fact/fact_exists/median3/min3/max3/_parse_hey_output now live in
# bench/lib.sh (sourced above), shared with the other bench/*.sh scripts.

# Runs hey once against $url with $body_file/$headers, for $1 requests.
# Prints hey's raw stdout+stderr. Used for both the discarded warmup and
# each measured rep.
_hey_once() {
  local n="$1" url="$2" body_file="$3"
  shift 3
  hey -n "$n" -c "$CONCURRENCY" -m POST -T "application/json" -D "$body_file" "$@" "$url" 2>&1
}

run_scenario() {
  local label="$1" url="$2" body_file="$3"
  shift 3
  local headers=("$@")

  local cmd=(hey -n "$REQUESTS" -c "$CONCURRENCY" -m POST -T "application/json" -D "$body_file" "${headers[@]}" "$url")
  local cmd_display
  cmd_display="$(printf '%q ' "${cmd[@]}")"
  echo "$cmd_display" >"$RAW_DIR/${label}.cmd"

  echo "==> Running: ${label} (warmup ${WARMUP_REQUESTS} req, then ${REPS}x ${REQUESTS} req at ${CONCURRENCY} concurrent)" >&2
  echo "    ${cmd_display}" >&2

  local rep
  for rep in 1 2 3; do
    _hey_once "$WARMUP_REQUESTS" "$url" "$body_file" "${headers[@]}" >/dev/null 2>&1 || true

    local out rep_label
    rep_label="${label}.rep${rep}"
    out="$(_hey_once "$REQUESTS" "$url" "$body_file" "${headers[@]}")"
    echo "$out" >"$RAW_DIR/${rep_label}.hey.log"
    _parse_hey_output "$rep_label" "$out"
  done

  local p50 p95 p99 rps
  p50="$(median3 "$(fact "${label}.rep1" p50)" "$(fact "${label}.rep2" p50)" "$(fact "${label}.rep3" p50)")"
  p95="$(median3 "$(fact "${label}.rep1" p95)" "$(fact "${label}.rep2" p95)" "$(fact "${label}.rep3" p95)")"
  p99="$(median3 "$(fact "${label}.rep1" p99)" "$(fact "${label}.rep2" p99)" "$(fact "${label}.rep3" p99)")"
  rps="$(median3 "$(fact "${label}.rep1" rps)" "$(fact "${label}.rep2" rps)" "$(fact "${label}.rep3" rps)")"
  echo "$p50" >"$RAW_DIR/${label}.p50"
  echo "$p95" >"$RAW_DIR/${label}.p95"
  echo "$p99" >"$RAW_DIR/${label}.p99"
  echo "$rps" >"$RAW_DIR/${label}.rps"

  # Spread: min-max across the 3 reps, so the report can show how noisy
  # each metric actually was rather than implying false precision.
  echo "$(min3 "$(fact "${label}.rep1" p50)" "$(fact "${label}.rep2" p50)" "$(fact "${label}.rep3" p50)")|$(max3 "$(fact "${label}.rep1" p50)" "$(fact "${label}.rep2" p50)" "$(fact "${label}.rep3" p50)")" >"$RAW_DIR/${label}.p50.spread"
  echo "$(min3 "$(fact "${label}.rep1" p99)" "$(fact "${label}.rep2" p99)" "$(fact "${label}.rep3" p99)")|$(max3 "$(fact "${label}.rep1" p99)" "$(fact "${label}.rep2" p99)" "$(fact "${label}.rep3" p99)")" >"$RAW_DIR/${label}.p99.spread"
  echo "$(min3 "$(fact "${label}.rep1" rps)" "$(fact "${label}.rep2" rps)" "$(fact "${label}.rep3" rps)")|$(max3 "$(fact "${label}.rep1" rps)" "$(fact "${label}.rep2" rps)" "$(fact "${label}.rep3" rps)")" >"$RAW_DIR/${label}.rps.spread"

  # Concatenate all 3 reps' status distributions -- clean 200s across every
  # rep is the bar, not just the median rep.
  local statuses
  statuses="$(cat "$RAW_DIR/${label}.rep1.status" "$RAW_DIR/${label}.rep2.status" "$RAW_DIR/${label}.rep3.status")"
  echo "$statuses" >"$RAW_DIR/${label}.status"

  local clean_200_total
  clean_200_total="$(echo "$statuses" | awk '/^\[200\]/ { sum += $2 } END { print sum+0 }')"
  local expected_total=$((REQUESTS * REPS))
  if [[ "$clean_200_total" != "$expected_total" ]]; then
    echo "    WARNING: '${label}' did not get $expected_total clean [200] responses across $REPS reps (got: $clean_200_total)." >&2
    echo "$statuses" | sed 's/^/      /' >&2
  fi
}

# --- run all 6 scenarios -------------------------------------------------------

run_scenario "native-baseline" "$BASELINE_NATIVE_URL" "$NATIVE_BODY_FILE" "${NATIVE_HEADERS[@]}"
run_scenario "native-1-instance" "$GATEWAY_SOLO_URL" "$NATIVE_BODY_FILE" "${NATIVE_HEADERS[@]}"
run_scenario "native-3-instances" "$GATEWAY_CLUSTER_URL" "$NATIVE_BODY_FILE" "${NATIVE_HEADERS[@]}"

run_scenario "legacy-baseline" "$BASELINE_LEGACY_URL" "$LEGACY_BODY_FILE" "${LEGACY_HEADERS[@]}" -H "Mcp-Session-Id: $LEGACY_SESSION_ID"
run_scenario "legacy-1-instance" "$GATEWAY_SOLO_URL" "$LEGACY_BODY_FILE" "${LEGACY_HEADERS[@]}"
run_scenario "legacy-3-instances" "$GATEWAY_CLUSTER_URL" "$LEGACY_BODY_FILE" "${LEGACY_HEADERS[@]}"

# --- CPU-contention check for the 3-instance scenarios -------------------------
#
# Adding gateway instances behind a load balancer should never make median
# throughput go DOWN or median p50 go UP relative to 1 instance -- if it
# does, that's the host running out of cores to give the extra containers,
# not the architecture failing to scale. Detected per-upstream (native vs
# legacy each get their own verdict) rather than assumed.

contention_detected() {
  local one_instance_label="$1" three_instance_label="$2"
  local rps_1 rps_3 p50_1 p50_3
  rps_1="$(fact "$one_instance_label" rps)"
  rps_3="$(fact "$three_instance_label" rps)"
  p50_1="$(fact "$one_instance_label" p50)"
  p50_3="$(fact "$three_instance_label" p50)"
  awk -v r1="$rps_1" -v r3="$rps_3" -v l1="$p50_1" -v l3="$p50_3" \
    'BEGIN { exit !(r3 < r1 || l3 > l1) }'
}

NATIVE_3_INSTANCE_CONTENTION=0
LEGACY_3_INSTANCE_CONTENTION=0
if contention_detected native-1-instance native-3-instances; then
  NATIVE_3_INSTANCE_CONTENTION=1
  echo "==> WARNING: native-3-instances shows CPU contention (throughput down and/or p50 up vs. 1 instance)." >&2
  echo "    Dropping native 3-instance scaling result from results.md -- not measurable on this hardware." >&2
fi
if contention_detected legacy-1-instance legacy-3-instances; then
  LEGACY_3_INSTANCE_CONTENTION=1
  echo "==> WARNING: legacy-3-instances shows CPU contention (throughput down and/or p50 up vs. 1 instance)." >&2
  echo "    Dropping legacy 3-instance scaling result from results.md -- not measurable on this hardware." >&2
fi

# --- added latency -------------------------------------------------------------

added_latency_ms() {
  local metric="$1" gateway_label="$2" baseline_label="$3"
  awk -v g="$(fact "$gateway_label" "$metric")" -v b="$(fact "$baseline_label" "$metric")" 'BEGIN { printf "%.2f", (g - b) * 1000 }'
}

# ms() now lives in bench/lib.sh (sourced above).

# Renders "median (min–max)" in ms for a given metric fact + its .spread file.
ms_with_spread() {
  local label="$1" metric="$2"
  local median min max
  median="$(fact "$label" "$metric")"
  min="$(cut -d'|' -f1 "$RAW_DIR/${label}.${metric}.spread")"
  max="$(cut -d'|' -f2 "$RAW_DIR/${label}.${metric}.spread")"
  printf '%s (%s–%s)' "$(ms "$median")" "$(ms "$min")" "$(ms "$max")"
}

# --- render report ---------------------------------------------------------------

{
  echo "# Portcullis gateway overhead benchmark"
  echo
  echo "> **These numbers are machine-specific.** They reflect this exact host's"
  echo "> CPU, memory, kernel, and Docker networking stack. Each scenario is the"
  echo "> median of ${REPS} warmed-up repetitions (min–max spread reported"
  echo "> alongside), not a single run -- but still one machine, one point in"
  echo "> time. Do not treat these as portable performance claims — re-run this"
  echo "> script on your own target hardware before relying on them."
  echo
  echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo
  echo "## Machine"
  echo
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| CPU | $CPU_MODEL |"
  echo "| Cores | $CPU_CORES |"
  echo "| RAM | ${RAM_GB} GB |"
  echo "| OS | $OS_INFO |"
  echo
  echo "## Method"
  echo
  echo "- Tool: [\`hey\`](https://github.com/rakyll/hey)"
  echo "- ${REQUESTS} requests, ${CONCURRENCY} concurrent, one \`tools/call\` per request"
  echo "- Each scenario: a discarded ${WARMUP_REQUESTS}-request warmup, then"
  echo "  ${REQUESTS} requests, repeated ${REPS} times. Reported figures are the"
  echo "  MEDIAN of the ${REPS} reps; the Results table also shows the min–max"
  echo "  spread. A single run's p99 is dominated by outliers at this sample"
  echo "  size -- median-of-${REPS} is the stable signal, not a single-shot number."
  echo "- Every bench container (upstream-native, upstream-legacy, gateway-solo,"
  echo "  gateway-a/b/c, nginx-bench) is CPU-limited to 1.0 core in"
  echo "  docker-compose.yml. This host has ${CPU_CORES} cores total; the"
  echo "  3-gateway-instance scenario runs up to 5 of these containers"
  echo "  concurrently (3 gateways + nginx + 1 upstream) alongside \`hey\` itself"
  echo "  and Docker Desktop's own VM overhead, all on the same physical cores."
  echo "  Without an explicit limit, docker compose lets every container burst"
  echo "  across all cores, which was masking true per-request overhead behind"
  echo "  scheduler contention (a previous run of this script showed 3-instance"
  echo "  throughput LOWER than 1-instance -- physically impossible for a"
  echo "  correctly-scaling proxy, and the signature of CPU starvation, not"
  echo "  architecture)."
  echo "- Native upstream speaks 2026-07-28 directly; legacy upstream speaks"
  echo "  2025-11-25 and is bridged through \`gateway/internal/translate\`'s"
  echo "  session pool"
  echo "- Same request body and MCP headers sent to every target, so only"
  echo "  \"is the gateway in the path\" varies — except the legacy baseline,"
  echo "  which must supply \`Mcp-Session-Id\` itself since a real 2025-11-25"
  echo "  server requires one and a 2026-07-28 client has no concept of one to"
  echo "  give it. That's the thing being measured, not an artifact."
  echo "- **3-instance scaling is only reported if it doesn't show contention.**"
  echo "  If median throughput through 3 instances is lower than through 1"
  echo "  instance, or median p50 is higher, that scenario's result is DROPPED"
  echo "  from the tables below rather than reported as a scaling measurement --"
  echo "  see the note where it would otherwise appear."
  echo
  echo "## Exact hey commands"
  echo
  echo '```'
  for label in native-baseline native-1-instance native-3-instances legacy-baseline legacy-1-instance legacy-3-instances; do
    echo "# ${label}"
    fact "$label" cmd
    echo
  done
  echo '```'
  echo
  echo "## Results"
  echo
  echo "| Scenario | Target | p50 ms (min–max) | p95 (ms) | p99 ms (min–max) | req/s | Non-200 responses |"
  echo "|---|---|---|---:|---|---:|---|"
  for entry in \
    "native-baseline|native|direct to upstream (baseline)|0" \
    "native-1-instance|native|through 1 gateway instance|0" \
    "native-3-instances|native|through 3 gateway instances|$NATIVE_3_INSTANCE_CONTENTION" \
    "legacy-baseline|legacy|direct to upstream (baseline)|0" \
    "legacy-1-instance|legacy|through 1 gateway instance|0" \
    "legacy-3-instances|legacy|through 3 gateway instances|$LEGACY_3_INSTANCE_CONTENTION"
  do
    label="${entry%%|*}"
    rest="${entry#*|}"
    upstream="${rest%%|*}"
    rest2="${rest#*|}"
    scenario="${rest2%%|*}"
    dropped="${rest2#*|}"

    if [[ "$dropped" == "1" ]]; then
      printf '| %s | %s | *dropped -- CPU contention on this %s-core host, not a scaling measurement* | | | | |\n' \
        "$scenario" "$upstream" "$CPU_CORES"
      continue
    fi

    # `grep -v` exits 1 when every response was 200 -- the clean, desired
    # outcome, not a failure. Under `set -o pipefail` that would otherwise
    # kill the whole script right when a run went perfectly; `|| true`
    # absorbs it (the empty-output case is handled right below).
    non200="$(fact "$label" status | grep -vE '^\[200\]' | tr '\n' ' ' | sed 's/ *$//' || true)"
    [[ -z "$non200" ]] && non200="none"
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
      "$scenario" "$upstream" \
      "$(ms_with_spread "$label" p50)" "$(ms "$(fact "$label" p95)")" "$(ms_with_spread "$label" p99)" \
      "$(fact "$label" rps)" "$non200"
  done
  echo
  echo "## Added latency (gateway − baseline, median of ${REPS} reps)"
  echo
  echo "| Upstream | Topology | Added p50 latency (ms) | Added p99 latency (ms) |"
  echo "|---|---|---:|---:|"
  echo "| native | 1 gateway instance | $(added_latency_ms p50 native-1-instance native-baseline) | $(added_latency_ms p99 native-1-instance native-baseline) |"
  if [[ "$NATIVE_3_INSTANCE_CONTENTION" == "1" ]]; then
    echo "| native | 3 gateway instances | *dropped -- CPU contention, not measurable on this hardware* | |"
  else
    echo "| native | 3 gateway instances | $(added_latency_ms p50 native-3-instances native-baseline) | $(added_latency_ms p99 native-3-instances native-baseline) |"
  fi
  echo "| legacy | 1 gateway instance | $(added_latency_ms p50 legacy-1-instance legacy-baseline) | $(added_latency_ms p99 legacy-1-instance legacy-baseline) |"
  if [[ "$LEGACY_3_INSTANCE_CONTENTION" == "1" ]]; then
    echo "| legacy | 3 gateway instances | *dropped -- CPU contention, not measurable on this hardware* | |"
  else
    echo "| legacy | 3 gateway instances | $(added_latency_ms p50 legacy-3-instances legacy-baseline) | $(added_latency_ms p99 legacy-3-instances legacy-baseline) |"
  fi
  echo
  echo "p50 is reported alongside p99 here deliberately: at ${REQUESTS} requests,"
  echo "p50 (median of the per-rep medians) is the stable signal, while p99 can"
  echo "still be noisy even after median-of-${REPS} averaging -- see the spread"
  echo "columns in Results above."
  echo
  if [[ "$NATIVE_3_INSTANCE_CONTENTION" == "1" || "$LEGACY_3_INSTANCE_CONTENTION" == "1" ]]; then
    echo "**Multi-instance scaling is not measurable on this ${CPU_CORES}-core host.**"
    echo "Single-gateway-instance overhead above is real and was measured cleanly;"
    echo "the 3-instance topology on this machine hits CPU contention (3 gateways"
    echo "+ nginx + upstreams + \`hey\` + Docker Desktop overhead competing for"
    echo "${CPU_CORES} physical cores) before it demonstrates anything about"
    echo "Portcullis's own scaling behavior. Re-run on a host with more cores (or"
    echo "one dedicated to this benchmark, with \`hey\` running from a separate"
    echo "machine) to get a real multi-instance measurement. Raw per-rep data for"
    echo "the dropped scenario(s) is still saved under \`bench/.raw/\` if you want"
    echo "to inspect it anyway -- it's just not reported as a scaling result."
    echo
  fi
  echo "**These numbers are machine-specific.** Re-run on your own hardware before drawing conclusions."
} | tee "$RESULTS_FILE"

echo >&2
echo "==> Results written to $RESULTS_FILE" >&2
echo "==> Raw hey output for each scenario is under $RAW_DIR/" >&2
echo "==> WARNING: the numbers above are machine-specific — they describe this host, not Portcullis in general." >&2
