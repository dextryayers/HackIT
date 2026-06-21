#!/usr/bin/env bash
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET=""
PORT=""
SCRIPT_NAME=""
TIMEOUT=10
ALL=false
JSON=false
QUIET=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -t, --target <host>      Target host (IP or hostname) [required]
  -p, --port <port>        Target port [required]
  -s, --script <name>      Run a single script (omit to run all)
  -c, --category <cat>     Run scripts from a specific category
  -T, --timeout <seconds>  Per-script timeout (default: 10)
  -j, --json               Output JSON results
  -q, --quiet              Suppress per-script output
  -l, --list               List available scripts by category
  -i, --info <script>      Show metadata for a specific script
  -h, --help               Show this help message

Examples:
  $(basename "$0") -t 192.168.1.1 -p 80
  $(basename "$0") -t 10.0.0.1 -p 443 -s ssl-enum-ciphers
  $(basename "$0") -t example.com -p 22 --category ssh -j
  $(basename "$0") -t scanme.org -p 80 --timeout 5 -j
  $(basename "$0") -l
  $(basename "$0") -i ssl-enum-ciphers
EOF
  exit 0
}

if [[ $# -eq 0 ]]; then
  usage
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)
      TARGET="$2"; shift 2 ;;
    -p|--port)
      PORT="$2"; shift 2 ;;
    -s|--script)
      SCRIPT_NAME="$2"; shift 2 ;;
    -c|--category)
      CATEGORY="$2"; shift 2 ;;
    -T|--timeout)
      TIMEOUT="$2"; shift 2 ;;
    -j|--json)
      JSON=true; shift ;;
    -q|--quiet)
      QUIET=true; shift ;;
    -l|--list)
      echo "Available scripts by category:"
      for cat_dir in "$SCRIPTS_DIR"/category_*; do
        :
      done
      for f in "$SCRIPTS_DIR"/*.nse; do
        base=$(basename "$f" .nse)
        prefix="${base%%-*}"
        echo "  [$prefix] $base"
      done | sort
      exit 0 ;;
    -i|--info)
      if [[ -z "$2" ]]; then
        echo "Error: --info requires a script name"
        exit 1
      fi
      SFILE="$SCRIPTS_DIR/${2%.nse}.nse"
      if [[ ! -f "$SFILE" ]]; then
        echo "Error: script '$2' not found"
        exit 1
      fi
      sed -n '/^description/,/^\]\]/p; /^author/,/^license/p; /^categories/p' "$SFILE" | head -20
      exit 0 ;;
    -h|--help)
      usage ;;
    *)
      echo "Unknown option: $1"
      usage ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: --target is required" >&2
  exit 1
fi

if [[ -z "$PORT" ]]; then
  echo "Error: --port is required" >&2
  exit 1
fi

run_single() {
  local script="$1"
  local target="$2"
  local port="$3"
  local timeout="$4"
  local json_out="$5"

  local script_file="$SCRIPTS_DIR/${script%.nse}.nse"
  if [[ ! -f "$script_file" ]]; then
    if $json_out; then
      echo "{\"script\":\"$script\",\"status\":false,\"error\":\"script file not found\"}"
    else
      echo "[SKIP] $script — file not found"
    fi
    return 1
  fi

  local result
  result=$(timeout "$timeout" lua -e "
    local runner = require 'runner'
    runner.SCRIPTS_DIR = '$SCRIPTS_DIR'
    local res = runner.run_single('$script', '$target', $port, '')
    local json = require 'json'
    print(json.encode(res))
  " 2>/dev/null) || result='{"status":false,"error":"timeout or runtime error"}'

  if $json_out; then
    echo "$result"
  else
    local status
    status=$(echo "$result" | lua -e "local j=require('json');local d=j.decode(io.read('*a'));print(d.status and 'OK' or 'FAIL')" 2>/dev/null)
    if [[ "$status" == "OK" ]]; then
      echo "[OK]   $script"
    else
      echo "[FAIL] $script"
    fi
    if ! $QUIET; then
      echo "$result" | lua -e "
        local j=require('json')
        local d=j.decode(io.read('*a'))
        if d.result then
          if type(d.result) == 'table' then
            for k,v in pairs(d.result) do
              print('  ' .. tostring(k) .. ': ' .. tostring(v))
            end
          else
            print('  ' .. tostring(d.result))
          end
        end
        if d.error then print('  error: ' .. d.error) end
      " 2>/dev/null || true
    fi
  fi
}

collect_json() {
  local first=true
  echo '['
  while IFS= read -r line; do
    if $first; then first=false; else echo ','; fi
    echo -n "$line"
  done
  echo ']'
}

if [[ -n "$SCRIPT_NAME" ]]; then
  run_single "$SCRIPT_NAME" "$TARGET" "$PORT" "$TIMEOUT" "$JSON"
elif [[ -n "${CATEGORY:-}" ]]; then
  results=""
  for f in "$SCRIPTS_DIR"/*.nse; do
    base=$(basename "$f" .nse)
    prefix="${base%%-*}"
    if [[ "$prefix" == "$CATEGORY" ]]; then
      if $JSON; then
        results="$results$(run_single "$base" "$TARGET" "$PORT" "$TIMEOUT" true)
"
      else
        run_single "$base" "$TARGET" "$PORT" "$TIMEOUT" false
      fi
    fi
  done
  if $JSON && [[ -n "$results" ]]; then
    echo "$results" | collect_json
  fi
else
  results=""
  for f in "$SCRIPTS_DIR"/*.nse; do
    base=$(basename "$f" .nse)
    case "$base" in
      runner|timeout_protect|category_map) continue ;;
    esac
    if $JSON; then
      results="$results$(run_single "$base" "$TARGET" "$PORT" "$TIMEOUT" true)
"
    else
      run_single "$base" "$TARGET" "$PORT" "$TIMEOUT" false
    fi
  done
  if $JSON && [[ -n "$results" ]]; then
    echo "$results" | collect_json
  fi
fi
