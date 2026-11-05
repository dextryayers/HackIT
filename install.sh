#!/usr/bin/env bash
# ==============================================================================
# HackIT one-command installer
# Usage: curl -sSL https://raw.githubusercontent.com/dextryayers/HackIT/main/install.sh | bash
# ==============================================================================
set -euo pipefail

REPO_URL="https://github.com/dextryayers/HackIT.git"
INSTALL_DIR="${HACKIT_HOME:-$HOME/.hackit}"
BIN_DIR="${HACKIT_BIN:-$HOME/.local/bin}"

# -- Palette ------------------------------------------------------------------
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
B='\033[0;34m'; M='\033[0;35m'; W='\033[1;37m'; D='\033[2m'; NC='\033[0m'
BOLD='\033[1m'

# -- Glyphs -------------------------------------------------------------------
OK="${G}✔${NC}"; ERR="${R}✘${NC}"; WARN="${Y}⚠${NC}"; INFO="${C}➔${NC}"
ARROW="${C}▸${NC}"; DOT="${D}·${NC}"

# -- Terminal width ------------------------------------------------------------
COLS=$(tput cols 2>/dev/null || echo 78)
[ "$COLS" -gt 90 ] && COLS=90
INNER=$((COLS - 4))

# -- Box helpers --------------------------------------------------------------
box_top() { local c="${1:-$C}"; printf "  ${c}╔$(printf '═%.0s' $(seq 1 $INNER))╗${NC}\n"; }
box_mid() { local c="${1:-$C}"; printf "  ${c}╠$(printf '═%.0s' $(seq 1 $INNER))╣${NC}\n"; }
box_bot() { local c="${1:-$C}"; printf "  ${c}╚$(printf '═%.0s' $(seq 1 $INNER))╝${NC}\n"; }

box_row() {
    local text="$1" bc="${2:-$C}" cc="${3:-$W}"
    local plain; plain=$(printf '%s' "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local pad=$((INNER - ${#plain}))
    [ $pad -lt 1 ] && pad=1
    printf "  ${bc}║${NC} ${cc}%s${NC}%${pad}s${bc}║${NC}\n" "$text" ""
}

box_title() {
    local title="$1" color="${2:-$C}"
    local tlen=${#title}
    local pad=$(( (INNER - tlen) / 2 ))
    [ $pad -lt 2 ] && pad=2
    local right=$(( INNER - tlen - pad ))
    [ $right -lt 2 ] && right=2
    box_top "$color"
    printf "  ${color}║${NC}%*s%s%*s${color}║${NC}\n" "$pad" "" "$title" "$right" ""
    box_bot "$color"
}

# -- Spinner ------------------------------------------------------------------
spin() {
    local pid=$1 msg="$2"
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${C}%s${NC} ${D}%s${NC}" "${frames[i % ${#frames[@]}]}" "$msg"
        i=$((i + 1))
        sleep 0.08
    done
    printf "\r\033[K"
}

run_step() {
    # run_step "message" command...
    local msg="$1"; shift
    local tmp; tmp=$(mktemp)
    "$@" >"$tmp" 2>&1 &
    local pid=$!
    spin "$pid" "$msg"
    wait "$pid"; local rc=$?
    if [ $rc -eq 0 ]; then
        ok "$msg"
    else
        err "$msg (exit $rc)"
        [ -s "$tmp" ] && tail -5 "$tmp" | sed 's/^/    /'
    fi
    rm -f "$tmp"
    return $rc
}

# -- Banner -------------------------------------------------------------------
clear
box_top "$C"
for line in \
"  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗" \
"  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝" \
"  ███████║███████║██║     █████╔╝ ██║   ██║    " \
"  ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║    " \
"  ██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║    " \
"  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝    "; do
    box_row "$line" "$C" "$B"
done
box_mid "$C"
box_row "  Security Framework  ·  v2.1  ·  one-command installer" "$C" "$W"
box_bot "$C"
echo

# -- Pre-flight ---------------------------------------------------------------
box_title "PRE-FLIGHT CHECKS" "$C"

if ! command -v git >/dev/null 2>&1; then
    err "git is required. Install it first (apt install git / brew install git)."
    exit 1
fi
ok "git found: $(git --version | head -1)"

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 is required. Install Python 3.10+ first."
    exit 1
fi
ok "python3 found: $(python3 --version)"

OS="$(uname -s)"
case "$OS" in
    Linux*)  OS_NAME="Linux" ;;
    Darwin*) OS_NAME="macOS" ;;
    *)       err "Unsupported OS: $OS"; exit 1 ;;
esac
ARCH="$(uname -m)"
ok "Platform: $OS_NAME ($ARCH)"
echo

# -- Step 1: clone / update ---------------------------------------------------
box_title "STEP 1 / 4  ·  SOURCE" "$C"

INSTALL_DIR="${HACKIT_HOME:-$HOME/.hackit}"
REPO_URL="https://github.com/dextryayers/HackIT.git"

if [ -d "$INSTALL_DIR/.git" ]; then
    log "Updating existing installation at $INSTALL_DIR"
    run_step "git pull" git -C "$INSTALL_DIR" pull --ff-only
else
    log "Cloning HackIT into $INSTALL_DIR"
    run_step "git clone" git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"
echo

# -- Step 2: python environment ----------------------------------------------
box_title "STEP 2 / 4  ·  PYTHON ENVIRONMENT" "$C"

if [ ! -d ".venv" ]; then
    run_step "create venv" python3 -m venv .venv
else
    ok "venv already exists, reusing"
fi

source .venv/bin/activate
run_step "upgrade pip" pip install --quiet --upgrade pip
run_step "install requirements" pip install --quiet -r requirements.txt
run_step "install hackit package" pip install --quiet -e .
echo

# -- Step 3: native engines ---------------------------------------------------
box_title "STEP 3 / 4  ·  NATIVE ENGINES" "$C"

if command -v go >/dev/null 2>&1; then
    if [ -d "hackit/agent/go" ]; then
        run_step "build agent go engine" bash -c "cd hackit/agent/go && go build -o ai_engine ."
    fi
    if [ -d "hackit/port_scanner/go" ]; then
        run_step "build port scanner go" bash -c "cd hackit/port_scanner/go && CGO_ENABLED=1 go build -o ../bin/port_scanner ."
    fi
else
    warn "Go not found, skipping Go engines (optional)"
fi

if command -v cargo >/dev/null 2>&1; then
    if [ -d "hackit/bruteforcer/rust_engine" ]; then
        run_step "build rust brute forcer" bash -c "cd hackit/bruteforcer/rust_engine && cargo build --release"
    fi
else
    warn "Cargo not found, skipping Rust engine (optional)"
fi
echo

# -- Step 4: link ------------------------------------------------------------
box_title "STEP 4 / 4  ·  LAUNCHER" "$C"

BIN_DIR="${HACKIT_BIN:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
if [ -x ".venv/bin/hackit" ]; then
    ln -sf "$INSTALL_DIR/.venv/bin/hackit" "$BIN_DIR/hackit"
    ok "linked: $BIN_DIR/hackit -> .venv/bin/hackit"
else
    ln -sf "$INSTALL_DIR/hackit.sh" "$BIN_DIR/hackit"
    ok "linked: $BIN_DIR/hackit -> hackit.sh"
fi

if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    warn "$BIN_DIR is not on your PATH"
    box_row "Add this to your shell profile (~/.bashrc or ~/.zshrc):" "$Y" "$Y"
    box_row "    export PATH=\"$BIN_DIR:\$PATH\"" "$Y" "$W"
fi
echo

# -- Done ---------------------------------------------------------------------
box_top "$G"
box_row "" "$G" "$G"
box_row "  ✔  HackIT installed successfully" "$G" "$G"
box_row "" "$G" "$G"
box_row "  Run 'hackit --help' to get started." "$G" "$W"
box_row "  Run 'hackit console' for the interactive shell." "$G" "$W"
box_row "" "$G" "$G"
box_bot "$G"
echo
echo "  If 'hackit' is not found, reload your shell:"
echo "    source ~/.bashrc   # or ~/.zshrc"
echo