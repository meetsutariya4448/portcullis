#!/usr/bin/env bash
#
# Measures real circuit-breaker timing against a live gateway + a real
# upstream container: stops upstream-native, times how long it takes the
# gateway to detect the outage and open the breaker (fast-failing 503s
# instead of slow 502s), then starts upstream-native again and times
# recovery through the breaker's cooldown and half-open trial.
#
# Unlike gateway/internal/server/chaos_test.go (Milestone 5), which
# proves the STATE MACHINE is correct using short, test-only breaker
# windows, this script measures actual WALL-CLOCK timing against the
# bench config's real (default) circuit-breaker tuning -- numbers that
# mean something for an actual deployment, not just "the logic works."
#
# This script only ever reports what it actually observed (HTTP status,
# timestamp, response body) -- it never estimates or assumes a timing
# based on the configured window/cooldown alone.
#
# Usage: bench/run_chaos_bench.sh [--keep-up]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
RAW_DIR="$REPO_ROOT/bench/.raw"
RESULTS_FRAGMENT="$RAW_DIR/chaos-bench.md"

# shellcheck disable=SC1091
source "$REPO_ROOT/bench/lib.sh"

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

echo "==> Building and starting gateway-solo + upstream-native..." >&2
"${COMPOSE[@]}" --profile bench up -d --build --wait upstream-native upstream-legacy gateway-solo

GATEWAY_URL="http://localhost:8081/mcp"
BODY_FILE="$RAW_DIR/native-body.json"
cat >"$BODY_FILE" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"native.echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
EOF
HEADERS=(-H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/call" -H "Mcp-Name: native.echo" -H "Content-Type: application/json")

# probe: sends one request, returns "status|body" (body truncated to
# avoid huge log lines; only used to check for the breaker-open message).
probe() {
  local resp
  resp="$(curl -s -o /tmp/portcullis-chaos-probe-body -w '%{http_code}' -X POST "${HEADERS[@]}" -d @"$BODY_FILE" "$GATEWAY_URL")"
  local body
  body="$(head -c 200 /tmp/portcullis-chaos-probe-body 2>/dev/null || true)"
  echo "${resp}|${body}"
}

echo "==> Confirming the gateway is healthy before the outage..." >&2
healthy_result="$(probe)"
healthy_status="${healthy_result%%|*}"
if [[ "$healthy_status" != "200" ]]; then
  echo "error: expected 200 before the outage, got: $healthy_result" >&2
  exit 1
fi
echo "    OK ($healthy_status)" >&2

echo "==> Stopping upstream-native (real container stop, not simulated)..." >&2
STOP_TIME="$(date +%s)"
"${COMPOSE[@]}" stop upstream-native >/dev/null 2>&1

echo "==> Polling until the breaker opens (fast 503, \"circuit breaker\" in body)..." >&2
TIMELINE_FILE="$RAW_DIR/chaos-timeline.log"
: >"$TIMELINE_FILE"

BREAKER_OPEN_TIME=""
REQUESTS_UNTIL_OPEN=0
DEADLINE=$((STOP_TIME + 30))
while [[ "$(date +%s)" -lt "$DEADLINE" ]]; do
  now="$(date +%s)"
  result="$(probe)"
  status="${result%%|*}"
  body="${result#*|}"
  REQUESTS_UNTIL_OPEN=$((REQUESTS_UNTIL_OPEN + 1))
  echo "t+$((now - STOP_TIME))s  status=${status}  body=${body}" >>"$TIMELINE_FILE"
  if [[ "$status" == "503" && "$body" == *"circuit breaker"* ]]; then
    BREAKER_OPEN_TIME="$now"
    break
  fi
  sleep 0.3
done

if [[ -z "$BREAKER_OPEN_TIME" ]]; then
  echo "error: breaker never opened within 30s of stopping upstream-native. See $TIMELINE_FILE" >&2
  exit 1
fi

DETECTION_SECONDS=$((BREAKER_OPEN_TIME - STOP_TIME))
echo "    Breaker opened ${DETECTION_SECONDS}s after the outage began (${REQUESTS_UNTIL_OPEN} client-facing requests sent; each may itself have retried internally up to the configured max_attempts, each retry independently counting toward the breaker's failure window)." >&2

echo "==> Starting upstream-native again..." >&2
START_TIME="$(date +%s)"
"${COMPOSE[@]}" start upstream-native >/dev/null 2>&1

echo "==> Polling until the gateway recovers (first 200 again)..." >&2
RECOVERED_TIME=""
DEADLINE=$((START_TIME + 30))
while [[ "$(date +%s)" -lt "$DEADLINE" ]]; do
  now="$(date +%s)"
  result="$(probe)"
  status="${result%%|*}"
  body="${result#*|}"
  echo "t+$((now - STOP_TIME))s  status=${status}  body=${body}" >>"$TIMELINE_FILE"
  if [[ "$status" == "200" ]]; then
    RECOVERED_TIME="$now"
    break
  fi
  sleep 0.3
done

if [[ -z "$RECOVERED_TIME" ]]; then
  echo "error: the gateway never recovered within 30s of restarting upstream-native. See $TIMELINE_FILE" >&2
  exit 1
fi

RECOVERY_SECONDS=$((RECOVERED_TIME - START_TIME))
TOTAL_OUTAGE_SECONDS=$((RECOVERED_TIME - STOP_TIME))
echo "    Recovered ${RECOVERY_SECONDS}s after upstream-native was restarted (${TOTAL_OUTAGE_SECONDS}s total from outage start to first successful response)." >&2

rm -f /tmp/portcullis-chaos-probe-body

{
  echo "### Circuit-breaker recovery timing (live, gateway-solo + upstream-native)"
  echo
  echo "Measured against \`bench/configs/gateway.yaml\`'s real circuit-breaker"
  echo "tuning (no \`circuit_breaker:\` block present, so this exercises"
  echo "\`internal/translate\`'s documented defaults: 10s window, 5 min samples,"
  echo "50% threshold, 5s cooldown), via actual \`docker compose stop\`/\`start\`"
  echo "on \`upstream-native\` -- not a simulated failure."
  echo
  echo "| Phase | Wall-clock time |"
  echo "|---|---:|"
  echo "| Outage start -> breaker opens (fast 503) | ${DETECTION_SECONDS}s |"
  echo "| Upstream restarted -> first successful response | ${RECOVERY_SECONDS}s |"
  echo "| Total: outage start -> fully recovered | ${TOTAL_OUTAGE_SECONDS}s |"
  echo
  echo "Client-facing requests sent before the breaker opened: ${REQUESTS_UNTIL_OPEN}"
  echo "(each may have internally retried up to the configured \`retry.max_attempts\`,"
  echo "with each retry independently counting toward the breaker's failure window --"
  echo "see \`internal/retry\`/\`internal/translate/breaker.go\`)."
  echo
  echo "Full observed status timeline (raw, every probe):"
  echo
  echo '```'
  cat "$TIMELINE_FILE"
  echo '```'
} | tee "$RESULTS_FRAGMENT"

echo >&2
echo "==> Chaos-bench results fragment written to $RESULTS_FRAGMENT" >&2
echo "==> Full timeline: $TIMELINE_FILE" >&2
