#!/bin/bash
# HackIT Subdomain Recon v3.5 — Direct Go Worker launcher
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKER="$SCRIPT_DIR/go/worker"

if [ ! -f "$WORKER" ]; then
  echo "[!] Worker not found. Run: python3 build_all.py"
  exit 1
fi

exec "$WORKER" "$@"
