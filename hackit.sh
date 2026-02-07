#!/bin/bash
# HackIt - Security Testing CLI Tool Suite Wrapper

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

# Check if virtual environment exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[!] Virtual environment not found. Please run setup first."
    exit 1
fi

# Run the main CLI
"$VENV_PYTHON" "$SCRIPT_DIR/main.py" "$@"
