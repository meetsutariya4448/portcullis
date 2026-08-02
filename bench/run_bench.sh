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

REQUESTS=5000
CONCURRENCY=50

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

detect_os() {
  case "$(uname -s)" in
    Darwin) sw_vers -productName; sw_vers -productVersion ;;
    Linux)
      if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${PRETTY_NAME:-Linux}"
      else
        uname -sr
      fi
      ;;
    *) uname -sr ;;
  esac
}

detect_cpu_model() {
  case "$(uname -s)" in
    Darwin) sysctl -n machdep.cpu.brand_string ;;
    Linux) awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo ;;
    *) echo "unknown" ;;
  esac
}

detect_cpu_cores() {
  case "$(uname -s)" in
    Darwin) sysctl -n hw.ncpu ;;
    Linux) nproc ;;
    *) echo "unknown" ;;
  esac
}

detect_ram_gb() {
  case "$(uname -s)" in
    Darwin) awk 'BEGIN { printf "%.1f", '"$(sysctl -n hw.memsize)"' / 1073741824 }' ;;
    Linux) awk '/MemTotal/ { printf "%.1f", $2/1048576 }' /proc/meminfo ;;
    *) echo "unknown" ;;
  esac
}

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

fact() { cat "$RAW_DIR/$1.$2"; }

run_hey() {
  local label="$1" url="$2" body_file="$3"
  shift 3
  local headers=("$@")

  local cmd=(hey -n "$REQUESTS" -c "$CONCURRENCY" -m POST -T "application/json" -D "$body_file" "${headers[@]}" "$url")
  local cmd_display
  cmd_display="$(printf '%q ' "${cmd[@]}")"
  echo "$cmd_display" >"$RAW_DIR/${label}.cmd"

  echo "==> Running: ${label} (${REQUESTS} requests, ${CONCURRENCY} concurrent)" >&2
  echo "    ${cmd_display}" >&2

  local out
  out="$("${cmd[@]}" 2>&1)"
  echo "$out" >"$RAW_DIR/${label}.hey.log"

  local p50 p95 p99 rps
  p50="$(echo "$out" | awk '/^ *50% in/ {print $3}')"
  p95="$(echo "$out" | awk '/^ *95% in/ {print $3}')"
  p99="$(echo "$out" | awk '/^ *99% in/ {print $3}')"
  rps="$(echo "$out" | awk -F'[[:space:]]+' '/Requests\/sec:/ {print $3}')"

  if [[ -z "$p50" || -z "$p95" || -z "$p99" || -z "$rps" ]]; then
    echo "error: failed to parse hey output for '${label}'. Raw output saved to $RAW_DIR/${label}.hey.log" >&2
    exit 1
  fi

  echo "$p50" >"$RAW_DIR/${label}.p50"
  echo "$p95" >"$RAW_DIR/${label}.p95"
  echo "$p99" >"$RAW_DIR/${label}.p99"
  echo "$rps" >"$RAW_DIR/${label}.rps"

  local statuses
  statuses="$(echo "$out" | sed -n '/Status code distribution:/,$p' | grep -E '^\s*\[' | tr '\t' ' ' | sed 's/^ *//')"
  echo "$statuses" >"$RAW_DIR/${label}.status"

  # Compare the actual [200] count against $REQUESTS rather than just
  # checking a [200] line exists — that catches both "some non-200s mixed
  # in" and "status distribution didn't parse at all" as the same signal:
  # something about this run wasn't a clean, fully-successful measurement.
  local clean_200_count
  clean_200_count="$(echo "$statuses" | awk '/^\[200\]/ {print $2}')"
  if [[ "$clean_200_count" != "$REQUESTS" ]]; then
    echo "    WARNING: '${label}' did not get $REQUESTS clean [200] responses (got: ${clean_200_count:-none parsed})." >&2
    echo "$statuses" | sed 's/^/      /' >&2
  fi
}

# --- run all 6 scenarios -------------------------------------------------------

run_hey "native-baseline" "$BASELINE_NATIVE_URL" "$NATIVE_BODY_FILE" "${NATIVE_HEADERS[@]}"
run_hey "native-1-instance" "$GATEWAY_SOLO_URL" "$NATIVE_BODY_FILE" "${NATIVE_HEADERS[@]}"
run_hey "native-3-instances" "$GATEWAY_CLUSTER_URL" "$NATIVE_BODY_FILE" "${NATIVE_HEADERS[@]}"

run_hey "legacy-baseline" "$BASELINE_LEGACY_URL" "$LEGACY_BODY_FILE" "${LEGACY_HEADERS[@]}" -H "Mcp-Session-Id: $LEGACY_SESSION_ID"
run_hey "legacy-1-instance" "$GATEWAY_SOLO_URL" "$LEGACY_BODY_FILE" "${LEGACY_HEADERS[@]}"
run_hey "legacy-3-instances" "$GATEWAY_CLUSTER_URL" "$LEGACY_BODY_FILE" "${LEGACY_HEADERS[@]}"

# --- added latency -------------------------------------------------------------

added_latency_ms() {
  local gateway_label="$1" baseline_label="$2"
  awk -v g="$(fact "$gateway_label" p99)" -v b="$(fact "$baseline_label" p99)" 'BEGIN { printf "%.2f", (g - b) * 1000 }'
}

ms() {
  awk -v s="$1" 'BEGIN { printf "%.2f", s * 1000 }'
}

# --- render report ---------------------------------------------------------------

{
  echo "# Portcullis gateway overhead benchmark"
  echo
  echo "> **These numbers are machine-specific.** They reflect this exact host's"
  echo "> CPU, memory, kernel, and Docker networking stack, run once, with no"
  echo "> statistical repeats. Do not treat them as portable performance claims —"
  echo "> re-run this script on your own target hardware before relying on them."
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
  echo "- Native upstream speaks 2026-07-28 directly; legacy upstream speaks"
  echo "  2025-11-25 and is bridged through \`gateway/internal/translate\`'s"
  echo "  session pool"
  echo "- Same request body and MCP headers sent to every target, so only"
  echo "  \"is the gateway in the path\" varies — except the legacy baseline,"
  echo "  which must supply \`Mcp-Session-Id\` itself since a real 2025-11-25"
  echo "  server requires one and a 2026-07-28 client has no concept of one to"
  echo "  give it. That's the thing being measured, not an artifact."
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
  echo "| Scenario | Target | p50 (ms) | p95 (ms) | p99 (ms) | req/s | Non-200 responses |"
  echo "|---|---|---:|---:|---:|---:|---|"
  for entry in \
    "native-baseline|native|direct to upstream (baseline)" \
    "native-1-instance|native|through 1 gateway instance" \
    "native-3-instances|native|through 3 gateway instances" \
    "legacy-baseline|legacy|direct to upstream (baseline)" \
    "legacy-1-instance|legacy|through 1 gateway instance" \
    "legacy-3-instances|legacy|through 3 gateway instances"
  do
    label="${entry%%|*}"
    rest="${entry#*|}"
    upstream="${rest%%|*}"
    scenario="${rest#*|}"
    non200="$(fact "$label" status | grep -vE '^\[200\]' | tr '\n' ' ' | sed 's/ *$//')"
    [[ -z "$non200" ]] && non200="none"
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
      "$scenario" "$upstream" \
      "$(ms "$(fact "$label" p50)")" "$(ms "$(fact "$label" p95)")" "$(ms "$(fact "$label" p99)")" \
      "$(fact "$label" rps)" "$non200"
  done
  echo
  echo "## Added latency (gateway p99 − baseline p99)"
  echo
  echo "| Upstream | Topology | Added p99 latency (ms) |"
  echo "|---|---|---:|"
  echo "| native | 1 gateway instance | $(added_latency_ms native-1-instance native-baseline) |"
  echo "| native | 3 gateway instances | $(added_latency_ms native-3-instances native-baseline) |"
  echo "| legacy | 1 gateway instance | $(added_latency_ms legacy-1-instance legacy-baseline) |"
  echo "| legacy | 3 gateway instances | $(added_latency_ms legacy-3-instances legacy-baseline) |"
  echo
  echo "**These numbers are machine-specific.** Re-run on your own hardware before drawing conclusions."
} | tee "$RESULTS_FILE"

echo >&2
echo "==> Results written to $RESULTS_FILE" >&2
echo "==> Raw hey output for each scenario is under $RAW_DIR/" >&2
echo "==> WARNING: the numbers above are machine-specific — they describe this host, not Portcullis in general." >&2
