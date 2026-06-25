#!/bin/bash
# HackIT Wireless Launcher
cd "$(dirname "$0")"
if [ "$1" = "--cli" ] || [ "$1" = "-c" ]; then
    exec python3 console.py "${@:2}"
elif [ "$1" = "--web" ] || [ "$1" = "-w" ]; then
    cd weblocal && python3 -m uvicorn main:app --host 0.0.0.0 --port 8081 --reload 2>/dev/null || python3 main.py
else
    cd weblocal && python3 gui.py
fi
