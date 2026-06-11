#!/bin/bash
# HackIT Tool Wrapper

TOOL_DIR="$(basename "$PWD")"
GLOBAL_WRAPPER="../../hackit.sh"

echo -e "\033[0;36m[+] Launching $TOOL_DIR module via HackIT Swarm...\033[0m"

if [ -f "$GLOBAL_WRAPPER" ]; then
    $GLOBAL_WRAPPER -mode $TOOL_DIR "$@"
else
    echo -e "\033[0;31m[X] Global HackIT Wrapper not found. Please run from root directory.\033[0m"
    exit 1
fi

