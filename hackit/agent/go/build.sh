#!/bin/bash
# Build every HackIt Go binary.  Output paths are absolute so changing into a
# module directory cannot accidentally create nested build directories.
set -u

HACKIT_GO_DIR="$(cd "$(dirname "$0")" && pwd)"
HACKIT_ROOT="$(cd "$HACKIT_GO_DIR/../../.." && pwd)"

BOLD='\033[1m'
GREEN='\033[32m'
CYAN='\033[36m'
YELLOW='\033[33m'
RED='\033[31m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     HACKIT AI ENGINE BUILDER v3.1       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

export GO111MODULE=on

BUILT=0
FAILED=0

build_engine() {
    local dir="$1"
    local name="$2"
    local output="$3"

    if [ ! -d "$dir" ]; then
        echo -e "  ${YELLOW}SKIP${NC}     ${name} ${DIM}(directory not found)${NC}"
        return
    fi
    if ! find "$dir" -maxdepth 1 -name '*.go' -print -quit | grep -q .; then
        echo -e "  ${YELLOW}SKIP${NC}     ${name} ${DIM}(no Go sources)${NC}"
        return
    fi

    echo -ne "  Building ${BOLD}${name}${NC}... "
    local log
    log="$(mktemp)"
    if (cd "$dir" && go build -ldflags "-s -w" -o "$output" .) 2>"$log"; then
        echo -e "${GREEN}OK${NC} ($(ls -lh "$output" | awk '{print $5}'))"
        BUILT=$((BUILT + 1))
    else
        echo -e "${RED}FAILED${NC}"
        sed 's/^/      /' "$log" | head -20
        FAILED=$((FAILED + 1))
    fi
    rm -f "$log"
}

echo -e "\n${CYAN}─── Core Engines ───${NC}\n"

build_engine "$HACKIT_GO_DIR"        "AI Engine (main)" "$HACKIT_GO_DIR/ai_engine"
build_engine "$HACKIT_GO_DIR/chat_go" "Chat Engine"     "$HACKIT_GO_DIR/chat_go/chat_engine"
build_engine "$HACKIT_GO_DIR/worker"  "Worker Engine"   "$HACKIT_GO_DIR/worker/worker"
build_engine "$HACKIT_GO_DIR/hative"  "Hative Scanner"  "$HACKIT_GO_DIR/hative/hative"
build_engine "$HACKIT_GO_DIR/swarm"   "Swarm Engine"    "$HACKIT_GO_DIR/swarm/swarm_engine"

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
    "hackit/403bypass/go_engine:bypass_engine"
    "hackit/tech_hunter/go:tech_hunter"
)

for entry in "${MODULES[@]}"; do
    dir="${entry%%:*}"
    out="${entry##*:}"
    build_engine "$HACKIT_ROOT/$dir" "$out" "$HACKIT_ROOT/$dir/$out"
done

echo -e "\n${CYAN}─── Summary ───${NC}\n"
echo -e "  ${GREEN}${BUILT} binaries built${NC}, ${FAILED} failed${NC}"
echo -e "  ${DIM}Location: $HACKIT_GO_DIR${NC}\n"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
