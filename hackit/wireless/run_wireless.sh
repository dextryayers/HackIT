#!/bin/bash
# HackIT Wireless Launcher
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$1" = "--cli" ] || [ "$1" = "-c" ]; then
    # Run from the repo root so `hackit` resolves, through the package so
    # the console's relative imports work.
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    exec python3 -m hackit.wireless.console "${@:2}" 2>/dev/null || \
        (cd "$REPO_ROOT" && exec python3 -m hackit.wireless.console "${@:2}")
elif [ "$1" = "--web" ] || [ "$1" = "-w" ]; then
    cd "$SCRIPT_DIR/weblocal" && python3 -m uvicorn main:app --host 0.0.0.0 --port 8081 --reload 2>/dev/null || python3 main.py
else
    cd "$SCRIPT_DIR/weblocal" && python3 gui.py
fi
