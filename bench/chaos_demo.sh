#!/usr/bin/env bash
#
# Live terminal dashboard for Portcullis's circuit breaker: brings up
# gateway-solo + upstream-native, then in real time -- redrawing a fixed
# panel in place, not scrolling log spam -- shows the breaker sitting
# CLOSED, a real failure being injected (an actual `docker compose stop`
# on upstream-native, not a simulated one), the breaker opening, holding
# through its cooldown, probing recovery via a HALF_OPEN trial, and
# closing again once upstream-native is restarted.
#
# This is the interactive counterpart to bench/run_chaos_bench.sh, which
# measures the same kind of event and is what produced the committed
# figures in bench/results.md. This script doesn't write to results.md
# or claim to reproduce those exact numbers -- it's meant to be watched,
# not archived.
#
# Usage: bench/chaos_demo.sh [--keep-up]

set -uo pipefail
# Deliberately not `set -e`: during the injected outage, curl/probe
# failures are the expected, interesting part of the demo, not a script
# error to abort on.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
RAW_DIR="$REPO_ROOT/bench/.raw"

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
require tput

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose -f "$COMPOSE_FILE")
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f "$COMPOSE_FILE")
else
  echo "error: neither 'docker compose' nor 'docker-compose' is available." >&2
  exit 1
fi

mkdir -p "$RAW_DIR"

# --- terminal setup -----------------------------------------------------------

# tput needs $TERM set to know the terminal's capabilities; some
# non-interactive or minimal shells (CI runners, `script`-wrapped
# sessions, etc.) don't export it at all, which makes every tput call
# below fail loudly without this fallback.
export TERM="${TERM:-xterm}"

if tput colors >/dev/null 2>&1 && [[ "$(tput colors)" -ge 8 ]]; then
  C_RESET="$(tput sgr0)"
  C_GREEN="$(tput setaf 2)"
  C_RED="$(tput setaf 1)"
  C_YELLOW="$(tput setaf 3)"
  C_BOLD="$(tput bold)"
  C_DIM="$(tput dim 2>/dev/null || true)"
else
  C_RESET=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_BOLD=""; C_DIM=""
fi

CURSOR_HIDDEN=0
cleanup() {
  if [[ "$CURSOR_HIDDEN" -eq 1 ]]; then
    tput cnorm 2>/dev/null || true
  fi
  if [[ "$KEEP_UP" -eq 0 ]]; then
    echo "==> Tearing down bench containers..." >&2
    "${COMPOSE[@]}" --profile bench down --remove-orphans >/dev/null 2>&1 || true
  else
    echo "==> --keep-up set: leaving bench containers running." >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "==> Building and starting upstream-native + gateway-solo..." >&2
"${COMPOSE[@]}" --profile bench up -d --build --wait upstream-native upstream-legacy gateway-solo

GATEWAY_URL="http://localhost:8081/mcp"
GATEWAY_METRICS_URL="http://localhost:8081/metrics"
BODY_FILE="$RAW_DIR/native-body.json"
cat >"$BODY_FILE" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"native.echo","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
EOF
HEADERS=(-H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/call" -H "Mcp-Name: native.echo" -H "Content-Type: application/json")

probe() {
  local resp body
  resp="$(curl -s -o /tmp/portcullis-chaos-demo-body -w '%{http_code}' --max-time 2 -X POST "${HEADERS[@]}" -d @"$BODY_FILE" "$GATEWAY_URL" 2>/dev/null || echo "000")"
  body="$(head -c 200 /tmp/portcullis-chaos-demo-body 2>/dev/null || true)"
  echo "${resp}|${body}"
}

scrape_breaker_state() {
  curl -s --max-time 1 "$GATEWAY_METRICS_URL" 2>/dev/null | awk '/^portcullis_circuit_breaker_state\{/ { print $NF; exit }'
}

# --- demo state ----------------------------------------------------------------

START_TIME="$(date +%s)"
EVENTS=()
add_event() {
  EVENTS+=("$(printf 't+%02ds  %s' "$(( $(date +%s) - START_TIME ))" "$1")")
}
add_event "Demo started -- upstream-native healthy"

STOP_AT_SECONDS=5          # inject failure this many seconds after start
HOLD_OPEN_SECONDS=3        # keep the outage going this long after the breaker opens
RECOVERY_DISPLAY_SECONDS=4 # keep the dashboard up this long after recovery, then exit

STOPPED=0
STOP_TIME=0
BREAKER_OPENED_AT=0
HALF_OPEN_SEEN=0
RESTARTED=0
RESTART_TIME=0
RECOVERED_AT=0

COUNT_200=0
COUNT_502=0
COUNT_503=0
COUNT_OTHER=0

LAST_STATUS="-"
LAST_BODY="(no probe yet)"

tput civis 2>/dev/null && CURSOR_HIDDEN=1
tput clear 2>/dev/null || true

DEADLINE=$(( START_TIME + 90 )) # safety valve: never run past this regardless

while true; do
  now="$(date +%s)"
  elapsed=$((now - START_TIME))

  if [[ "$now" -ge "$DEADLINE" ]]; then
    add_event "Safety timeout reached (90s) -- stopping the demo"
    break
  fi

  if [[ "$STOPPED" -eq 0 && "$elapsed" -ge "$STOP_AT_SECONDS" ]]; then
    "${COMPOSE[@]}" stop upstream-native >/dev/null 2>&1
    STOPPED=1
    STOP_TIME="$now"
    add_event "FAILURE INJECTED -- upstream-native stopped (real container stop)"
  fi

  result="$(probe)"
  LAST_STATUS="${result%%|*}"
  LAST_BODY="${result#*|}"

  breaker_state="$(scrape_breaker_state)"
  case "$breaker_state" in
    0) state_name="CLOSED"; state_color="$C_GREEN" ;;
    1) state_name="OPEN"; state_color="$C_RED" ;;
    2) state_name="HALF_OPEN"; state_color="$C_YELLOW" ;;
    *) state_name="UNKNOWN"; state_color="$C_DIM" ;;
  esac

  if [[ "$STOPPED" -eq 1 && "$BREAKER_OPENED_AT" -eq 0 && "$breaker_state" == "1" ]]; then
    BREAKER_OPENED_AT="$now"
    add_event "Breaker OPENED -- $((BREAKER_OPENED_AT - STOP_TIME))s after the outage began"
  fi

  if [[ "$HALF_OPEN_SEEN" -eq 0 && "$breaker_state" == "2" ]]; then
    HALF_OPEN_SEEN=1
    add_event "Breaker HALF_OPEN -- probing whether upstream-native has recovered"
  fi

  if [[ "$STOPPED" -eq 1 && "$RESTARTED" -eq 0 && "$BREAKER_OPENED_AT" -ne 0 \
        && $((now - BREAKER_OPENED_AT)) -ge "$HOLD_OPEN_SECONDS" ]]; then
    "${COMPOSE[@]}" start upstream-native >/dev/null 2>&1
    RESTARTED=1
    RESTART_TIME="$now"
    add_event "upstream-native restarted"
  fi

  if [[ "$RESTARTED" -eq 1 && "$RECOVERED_AT" -eq 0 && "$LAST_STATUS" == "200" ]]; then
    RECOVERED_AT="$now"
    add_event "RECOVERED -- $((RECOVERED_AT - RESTART_TIME))s after restart, breaker closed"
  fi

  case "$LAST_STATUS" in
    200) COUNT_200=$((COUNT_200 + 1)) ;;
    502) COUNT_502=$((COUNT_502 + 1)) ;;
    503) COUNT_503=$((COUNT_503 + 1)) ;;
    *) COUNT_OTHER=$((COUNT_OTHER + 1)) ;;
  esac

  # --- redraw in place ---------------------------------------------------------
  tput cup 0 0 2>/dev/null || true
  tput ed 2>/dev/null || true
  printf '%s%sPortcullis -- Circuit Breaker Chaos Demo%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  printf '========================================\n\n'
  printf 'Elapsed:        t+%02ds\n\n' "$elapsed"
  printf 'Breaker state:  %s%s%-9s%s\n' "$C_BOLD" "$state_color" "$state_name" "$C_RESET"
  printf 'Last probe:     %s  %s\n\n' "$LAST_STATUS" "$LAST_BODY"
  printf 'Request counts: %s200%s=%-4d  %s502%s=%-4d  %s503%s=%-4d  other=%d\n\n' \
    "$C_GREEN" "$C_RESET" "$COUNT_200" "$C_RED" "$C_RESET" "$COUNT_502" "$C_YELLOW" "$C_RESET" "$COUNT_503" "$COUNT_OTHER"
  printf 'Events:\n'
  for ev in "${EVENTS[@]}"; do
    printf '  %s\n' "$ev"
  done
  printf '\n%s(Ctrl-C to stop early -- containers still torn down cleanly)%s\n' "$C_DIM" "$C_RESET"

  if [[ "$RECOVERED_AT" -ne 0 && $((now - RECOVERED_AT)) -ge "$RECOVERY_DISPLAY_SECONDS" ]]; then
    break
  fi

  sleep 0.5
done

rm -f /tmp/portcullis-chaos-demo-body

echo >&2
echo "==> Demo complete." >&2
if [[ "$BREAKER_OPENED_AT" -ne 0 ]]; then
  echo "    Detection: $((BREAKER_OPENED_AT - STOP_TIME))s from outage to breaker OPEN" >&2
fi
if [[ "$RECOVERED_AT" -ne 0 ]]; then
  echo "    Recovery:  $((RECOVERED_AT - RESTART_TIME))s from restart to first successful response" >&2
fi
echo "    See bench/results.md for the committed, reproducible timing numbers" >&2
echo "    from bench/run_chaos_bench.sh -- this run's numbers are illustrative," >&2
echo "    not a replacement for that measurement." >&2
