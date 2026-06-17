#!/bin/bash
set -e
HACKIT_GO_DIR="$(cd "$(dirname "$0")" && pwd)"
BOLD='\033[1m'
GREEN='\033[32m'
CYAN='\033[36m'
YELLOW='\033[33m'
RED='\033[31m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     HACKIT AI ENGINE BUILDER v3.0       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

export GO111MODULE=on

build_engine() {
    local dir="$1"
    local name="$2"
    local output="$3"
    echo -ne "  Building ${BOLD}${name}${NC}... "
    if cd "$dir" 2>/dev/null; then
        go mod tidy >/dev/null 2>&1
        go build -ldflags "-s -w" -o "$output" . 2>/dev/null && \
            echo -e "${GREEN}OK${NC} ($(ls -lh "$output" | awk '{print $5}'))" || \
            echo -e "${RED}FAILED${NC}"
        cd - >/dev/null
    else
        echo -e "${YELLOW}SKIPPED (dir not found)${NC}"
    fi
}

echo -e "\n${CYAN}─── Core Engines ───${NC}\n"

build_engine "$HACKIT_GO_DIR" "AI Engine (main)" "ai_engine"
build_engine "$HACKIT_GO_DIR/swarm" "Swarm Engine" "swarm/swarm_engine"

echo -e "\n${CYAN}─── Module Go Engines ───${NC}\n"

MODULES=(
    "hackit/network_scanner/go:network_scanner"
    "hackit/subdomain/go:subdomain_worker"
    "hackit/sqli/go:sqli_worker"
    "hackit/xss/go:xss_worker"
    "hackit/web_fuzzer/go:web_fuzzer"
    "hackit/ssl_tool/go:ssl_tool"
    "hackit/header_audit/go:header_audit"
    "hackit/redirect/go:redirect_scanner"
    "hackit/js/go:js_analyzer"
    "hackit/rce_modul/go:rce_detector"
    "hackit/port_scanner/go:port_scanner"
    "hackit/params/go:param_scanner"
    "hackit/dir_finder/go:dir_finder"
    "hackit/atomix/go:atomix"
    "hackit/cve/go:cve_scanner"
    "hackit/403bypass/go:bypass_scanner"
    "hackit/tech_hunter/go:tech_hunter"
)

HACKIT_ROOT="$HACKIT_GO_DIR/../../.."
for entry in "${MODULES[@]}"; do
    dir="${entry%%:*}"
    out="${entry##*:}"
    build_engine "$HACKIT_ROOT/$dir" "$out" "$out"
done

echo -e "\n${CYAN}─── Summary ───${NC}\n"

TOTAL=$(find "$HACKIT_GO_DIR" -maxdepth 3 -name "ai_engine" -o -name "swarm_engine" 2>/dev/null | wc -l)
for entry in "${MODULES[@]}"; do
    out="${entry##*:}"
    if [ -f "$HACKIT_ROOT/${entry%%:*}/$out" ]; then
        TOTAL=$((TOTAL + 1))
    fi
done

echo -e "  ${GREEN}$TOTAL binaries built successfully${NC}"
echo -e "  ${DIM}Location: $HACKIT_GO_DIR${NC}\n"
