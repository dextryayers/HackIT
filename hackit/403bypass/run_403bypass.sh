#!/bin/bash
# HackIT Tool Wrapper

TOOL_DIR="$(basename "$PWD")"
PYTHON_ENTRY="__init__.py"

echo -e "\033[0;36m[+] Launching $TOOL_DIR module via Python Wrapper...\033[0m"

if [ -z "$1" ]; then
    echo -e "\033[0;31m[X] Target URL required.\033[0m"
    echo "Usage: ./run_403bypass.sh <url>"
    exit 1
fi

if [ -f "$PYTHON_ENTRY" ]; then
    python3 "$PYTHON_ENTRY" "$1"
else
    echo -e "\033[0;31m[X] Main orchestrator $PYTHON_ENTRY not found.\033[0m"
    exit 1
fi
