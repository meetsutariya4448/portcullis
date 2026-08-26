#!/usr/bin/env bash
#
# Shared shell functions for the bench/*.sh scripts: hey-output parsing,
# median-of-3 helpers, and machine-spec detection. Sourced, not
# duplicated, so run_bench.sh, run_concurrency_sweep.sh, and
# run_chaos_bench.sh can't silently drift apart on how they compute a
# median or parse a hey run.
#
# Requires $RAW_DIR to be set by the sourcing script before calling
# fact/fact_exists/_parse_hey_output.

fact() { cat "$RAW_DIR/$1.$2"; }
fact_exists() { [[ -f "$RAW_DIR/$1.$2" ]]; }

median3() {
  printf '%s\n%s\n%s\n' "$1" "$2" "$3" | sort -n | awk 'NR==2'
}

min3() { printf '%s\n%s\n%s\n' "$1" "$2" "$3" | sort -n | awk 'NR==1'; }
max3() { printf '%s\n%s\n%s\n' "$1" "$2" "$3" | sort -n | awk 'NR==3'; }

median2() {
  # Median of exactly 2 numbers (this file's own use case for the
  # concurrency sweep's 2-rep-per-level budget): the average of the two,
  # since there's no true middle element.
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%s", (a+b)/2 }'
}

min2() { printf '%s\n%s\n' "$1" "$2" | sort -n | awk 'NR==1'; }
max2() { printf '%s\n%s\n' "$1" "$2" | sort -n | awk 'NR==2'; }

# Parses one hey run's raw output into p50/p95/p99/rps/status, or exits
# loudly if any field can't be parsed -- never silently substitutes a
# missing measurement.
_parse_hey_output() {
  local rep_label="$1" out="$2"

  # This build of hey (0.1.5, Homebrew) prints latency-distribution labels
  # as "50%% in ..." (doubled percent sign) instead of "50% in ...".
  # Normalize for parsing only -- the raw per-rep log keeps the actual
  # output verbatim.
  local out_normalized
  out_normalized="$(echo "$out" | sed 's/%%/%/g')"

  local p50 p95 p99 rps
  p50="$(echo "$out_normalized" | awk '/^ *50% in/ {print $3}')"
  p95="$(echo "$out_normalized" | awk '/^ *95% in/ {print $3}')"
  p99="$(echo "$out_normalized" | awk '/^ *99% in/ {print $3}')"
  rps="$(echo "$out" | awk -F'[[:space:]]+' '/Requests\/sec:/ {print $3}')"

  if [[ -z "$p50" || -z "$p95" || -z "$p99" || -z "$rps" ]]; then
    echo "error: failed to parse hey output for '${rep_label}'. Raw output saved to $RAW_DIR/${rep_label}.hey.log" >&2
    exit 1
  fi

  echo "$p50" >"$RAW_DIR/${rep_label}.p50"
  echo "$p95" >"$RAW_DIR/${rep_label}.p95"
  echo "$p99" >"$RAW_DIR/${rep_label}.p99"
  echo "$rps" >"$RAW_DIR/${rep_label}.rps"

  local statuses
  statuses="$(echo "$out" | sed -n '/Status code distribution:/,$p' | grep -E '^\s*\[' | tr '\t' ' ' | sed 's/^ *//')"
  echo "$statuses" >"$RAW_DIR/${rep_label}.status"
}

ms() {
  awk -v s="$1" 'BEGIN { printf "%.2f", s * 1000 }'
}

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
