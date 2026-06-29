#!/bin/bash
# PortStorm — Unified Engine Build (all under go/)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║      PORTSTORM — BUILD ALL ENGINES          ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${NC}"

# ── 1. C Engine → go/libportstorm_c.so ──────────────────────────
echo -e "\n${BOLD}[1/4] Building C Engine (csrc/ → libportstorm_c.so)...${NC}"
make -C "$DIR/csrc" clean 2>/dev/null || true
make -C "$DIR/csrc" -j$(nproc)
if [ -f "$DIR/libportstorm_c.so" ]; then
    ls -lh "$DIR/libportstorm_c.so"
    echo -e "${GREEN}  ✓ C Engine built${NC}"
else
    echo "  ✗ C Engine build FAILED"
    exit 1
fi

# ── 2. C++ Engine → go/libportstorm_cpp.so ──────────────────────
echo -e "\n${BOLD}[2/4] Building C++ Engine (cxxsrc/ → libportstorm_cpp.so)...${NC}"
make -C "$DIR/cxxsrc" clean 2>/dev/null || true
make -C "$DIR/cxxsrc" -j$(nproc)
if [ -f "$DIR/libportstorm_cpp.so" ]; then
    ls -lh "$DIR/libportstorm_cpp.so"
    echo -e "${GREEN}  ✓ C++ Engine built${NC}"
else
    echo "  ✗ C++ Engine build FAILED"
    exit 1
fi

# ── 3. Go Engine ────────────────────────────────────────────────
echo -e "\n${BOLD}[3/4] Building Go Engine...${NC}"
cd "$DIR"
go build -ldflags="-s -w" -o port_scanner .
if [ -f port_scanner ]; then
    ls -lh port_scanner
    echo -e "${GREEN}  ✓ Go Engine built${NC}"
else
    echo "  ✗ Go Engine build FAILED"
    exit 1
fi

# ── 4. Rust Engine ──────────────────────────────────────────────
echo -e "\n${BOLD}[4/4] Building Rust Engine...${NC}"
if command -v cargo &>/dev/null; then
    cd "$DIR/rustsrc"
    cargo build --release 2>/dev/null && {
        echo -e "${GREEN}  ✓ Rust Engine built${NC}"
        mkdir -p "$DIR/../bin"
        cp target/release/portstorm-rust "$DIR/../bin/" 2>/dev/null || true
    } || {
        echo -e "  ${YELLOW}- Rust build skipped (check Cargo.toml)${NC}"
    }
else
    echo -e "  ${YELLOW}- Cargo not found, skipping Rust engine${NC}"
fi

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║      PORTSTORM — ALL ENGINES BUILT          ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "  C Engine:     $DIR/libportstorm_c.so"
echo "  C++ Engine:   $DIR/libportstorm_cpp.so"
echo "  Go Engine:    $DIR/port_scanner"
echo "  Rust Sources: $DIR/rustsrc/"
echo "  Lua Scripts:  $DIR/../lua/ (14 NSE scripts)"
echo ""
echo "  Run: hackit scan <target>"