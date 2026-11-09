#!/usr/bin/env bash
# ==============================================================================
# HackIT one-command installer
#
#   curl -sSL https://raw.githubusercontent.com/dextryayers/HackIT/main/install.sh | bash
#
# Works in two modes:
#   * Run from inside a checkout (./install.sh)  -> installs from that checkout
#   * Run piped from curl                        -> clones into ~/.hackit first
#
# Environment overrides:
#   HACKIT_HOME       install directory           (default: ~/.hackit)
#   HACKIT_BIN        where the launcher is linked (default: ~/.local/bin)
#   HACKIT_BRANCH     branch to clone             (default: main)
#   HACKIT_NO_PROFILE set to 1 to skip editing shell profile for PATH
#   HACKIT_SKIP_GO    set to 1 to skip Go/Rust engine builds
# ==============================================================================
set -euo pipefail

REPO_URL="${HACKIT_REPO:-https://github.com/dextryayers/HackIT.git}"
BRANCH="${HACKIT_BRANCH:-main}"
INSTALL_DIR="${HACKIT_HOME:-$HOME/.hackit}"
BIN_DIR="${HACKIT_BIN:-$HOME/.local/bin}"

# -- Palette ------------------------------------------------------------------
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
B='\033[0;34m'; W='\033[1;37m'; D='\033[2m'; NC='\033[0m'

# -- Terminal width (safe when piped and TERM is unset) ------------------------
COLS=$(tput cols 2>/dev/null || echo 78)
[[ "$COLS" =~ ^[0-9]+$ ]] || COLS=78
[ "$COLS" -gt 90 ] && COLS=90
INNER=$((COLS - 4))

# -- Log helpers ----------------------------------------------------------------
log()  { printf "  ${C}➔${NC}  %s\n" "$*"; }
ok()   { printf "  ${G}✔${NC}  %s\n" "$*"; }
warn() { printf "  ${Y}⚠${NC}  %s\n" "$*"; }
err()  { printf "  ${R}✘${NC}  %s\n" "$*" >&2; }

# -- Box helpers -----------------------------------------------------------------
box_top() { local c="${1:-$C}"; printf "  ${c}╔"; printf '═%.0s' $(seq 1 $INNER); printf "╗${NC}\n"; }
box_mid() { local c="${1:-$C}"; printf "  ${c}╠"; printf '═%.0s' $(seq 1 $INNER); printf "╣${NC}\n"; }
box_bot() { local c="${1:-$C}"; printf "  ${c}╚"; printf '═%.0s' $(seq 1 $INNER); printf "╝${NC}\n"; }

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

# -- Runner with a spinner ------------------------------------------------------
spin() {
    local pid=$1 msg="$2"
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    if [ ! -t 1 ]; then
        wait "$pid"
        return $?
    fi
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${C}%s${NC} ${D}%s${NC}" "${frames[i % ${#frames[@]}]}" "$msg"
        i=$((i + 1))
        sleep 0.08
    done
    printf "\r\033[K"
    wait "$pid"
}

run_step() {
    # run_step "message" command...
    local msg="$1"; shift
    local tmp; tmp=$(mktemp)
    "$@" >"$tmp" 2>&1 &
    local pid=$!
    spin "$pid" "$msg" && rc=0 || rc=$?
    if [ $rc -eq 0 ]; then
        ok "$msg"
    else
        err "$msg (exit $rc)"
        [ -s "$tmp" ] && tail -8 "$tmp" | sed 's/^/    /'
    fi
    rm -f "$tmp"
    return $rc
}

# -- Where are we running from? ---------------------------------------------------
SOURCE_DIR=""
_self="${BASH_SOURCE[0]:-$0}"
if [ -f "$_self" ]; then
    _dir=$(cd "$(dirname "$_self")" 2>/dev/null && pwd || true)
    if [ -n "$_dir" ] && [ -f "$_dir/setup.py" ] && [ -d "$_dir/hackit" ]; then
        SOURCE_DIR="$_dir"
    fi
fi

# -- Banner -------------------------------------------------------------------------
[ -t 1 ] && { clear 2>/dev/null || true; }
box_top "$C"
for line in \
"  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗" \
"  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝" \
"  ███████║███████║██║     █████╔╝ ██║   ██║   " \
"  ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║   " \
"  ██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║   " \
"  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   "; do
    box_row "$line" "$C" "$B"
done
box_mid "$C"
box_row "  Security Framework  ·  v2.2  ·  one-command installer" "$C" "$W"
box_bot "$C"
echo

# -- Pre-flight ----------------------------------------------------------------------
box_title "PRE-FLIGHT CHECKS" "$C"

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 is required. Install Python 3.10+ first."
    exit 1
fi
PY_VER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
case "$PY_VER" in
    3.[0-9]|2.*) err "Python $PY_VER is too old. Need 3.10+."; exit 1 ;;
esac
ok "python3 found: $(python3 --version 2>&1)"

if [ -z "$SOURCE_DIR" ]; then
    if ! command -v git >/dev/null 2>&1; then
        err "git is required to clone HackIT. Install it first (apt install git / brew install git)."
        exit 1
    fi
    ok "git found: $(git --version | head -1)"
fi

OS="$(uname -s)"
case "$OS" in
    Linux*)  OS_NAME="Linux" ;;
    Darwin*) OS_NAME="macOS" ;;
    *)       err "Unsupported OS: $OS"; exit 1 ;;
esac
ok "Platform: $OS_NAME ($(uname -m))"

if python3 -c 'import ensurepip' >/dev/null 2>&1; then
    ok "python3 venv available"
else
    warn "python3-venv (ensurepip) missing — installer will bootstrap pip via get-pip.py"
    warn "on Debian/Ubuntu you can also: sudo apt install python3.13-venv"
fi
echo

# -- Step 1: source -------------------------------------------------------------------
box_title "STEP 1 / 4  ·  SOURCE" "$C"

if [ -n "$SOURCE_DIR" ]; then
    INSTALL_DIR="$SOURCE_DIR"
    log "Using local checkout at $INSTALL_DIR"
else
    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Updating existing installation at $INSTALL_DIR"
        run_step "git pull" git -C "$INSTALL_DIR" pull --ff-only || warn "git pull failed — keeping current checkout"
    else
        if [ -e "$INSTALL_DIR" ]; then
            BACKUP="$INSTALL_DIR.bak.$(date +%Y%m%d%H%M%S)"
            warn "$INSTALL_DIR exists and is not a git checkout — moving it to $BACKUP"
            mv "$INSTALL_DIR" "$BACKUP"
        fi
        log "Cloning HackIT into $INSTALL_DIR"
        run_step "git clone" git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    fi
fi
cd "$INSTALL_DIR"
echo

# -- Step 2: python environment ----------------------------------------------------------
box_title "STEP 2 / 4  ·  PYTHON ENVIRONMENT" "$C"

VENV="$INSTALL_DIR/.venv"
VENV_MADE=0
if [ ! -d "$VENV" ]; then
    if python3 -m venv "$VENV" >"$INSTALL_DIR/.venv.log" 2>&1; then
        VENV_MADE=1
    else
        # No ensurepip on this system (Debian/Ubuntu without python3-venv):
        # build the venv without pip and bootstrap pip over HTTPS instead.
        warn "venv with pip failed — retrying with --without-pip + get-pip.py bootstrap"
        rm -rf "$VENV"
        rm -f "$INSTALL_DIR/.venv.log"
        if python3 -m venv --without-pip "$VENV" >/dev/null 2>&1; then
            VENV_MADE=1
        else
            rm -rf "$VENV"
            err "could not create a virtual environment at $VENV"
            err "install python3-venv (sudo apt install python3.13-venv) and re-run"
            exit 1
        fi
    fi
else
    VENV_MADE=1
fi
rm -f "$INSTALL_DIR/.venv.log"

PIP="$VENV/bin/pip"
if [ ! -x "$PIP" ]; then
    log "bootstrapping pip into the venv (get-pip.py)"
    GET_PIP="$VENV/get-pip.py"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$GET_PIP" || { err "download of get-pip.py failed"; exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q https://bootstrap.pypa.io/get-pip.py -O "$GET_PIP" || { err "download of get-pip.py failed"; exit 1; }
    else
        err "neither curl nor wget found — bootstrap pip manually, or install python3-venv"
        exit 1
    fi
    "$VENV/bin/python" "$GET_PIP" --quiet || { err "pip bootstrap failed"; exit 1; }
    rm -f "$GET_PIP"
    ok "pip bootstrapped"
fi
[ "$VENV_MADE" = "1" ] && ok "venv ready at $VENV"

run_step "upgrade pip" "$PIP" install --quiet --upgrade pip
if [ -f requirements.txt ]; then
    run_step "install requirements" "$PIP" install --quiet -r requirements.txt
fi
run_step "install hackit package" "$PIP" install --quiet -e .
echo

# -- Step 3: native engines ---------------------------------------------------------------
box_title "STEP 3 / 4  ·  NATIVE ENGINES" "$C"

if [ "${HACKIT_SKIP_GO:-0}" = "1" ]; then
    warn "HACKIT_SKIP_GO=1 — skipping Go/Rust engines"
elif command -v go >/dev/null 2>&1; then
    if [ -f hackit/agent/go/build.sh ]; then
        # build.sh builds every Go module + the Rust pro_scan engine.
        # A failure here must not abort the install — Python fallbacks exist.
        run_step "build native engines" bash hackit/agent/go/build.sh || warn "some engines failed to build — tool still works, those modules will use Python fallbacks"
    fi
else
    warn "Go not found — skipping native engines (optional)"
    log "Install Go from https://go.dev/dl/ then re-run this installer to enable them"
fi
echo

# -- Step 4: launcher ----------------------------------------------------------------------
box_title "STEP 4 / 4  ·  LAUNCHER" "$C"

mkdir -p "$BIN_DIR"
HACKIT_BIN_PATH="$VENV/bin/hackit"
if [ -x "$HACKIT_BIN_PATH" ]; then
    ln -sf "$HACKIT_BIN_PATH" "$BIN_DIR/hackit"
    ok "linked: $BIN_DIR/hackit -> $HACKIT_BIN_PATH"
else
    err "entry point not found at $HACKIT_BIN_PATH — the package install may have failed"
    exit 1
fi

PATH_LINE="export PATH=\"$BIN_DIR:\$PATH\""
PROFILE=""
case ":${SHELL:-}:" in
    *:zsh:*)  PROFILE="$HOME/.zshrc" ;;
    *)        PROFILE="$HOME/.bashrc" ;;
esac

path_has_bin_dir() { case ":$PATH:" in *":$BIN_DIR:"*) return 0 ;; *) return 1 ;; esac; }

if path_has_bin_dir; then
    ok "$BIN_DIR already on PATH"
else
    if [ "${HACKIT_NO_PROFILE:-0}" = "1" ]; then
        warn "$BIN_DIR is not on your PATH"
        box_row "Add this to your shell profile:" "$Y" "$Y"
        box_row "    $PATH_LINE" "$Y" "$W"
    else
        touch "$PROFILE"
        if ! grep -Fq "$BIN_DIR" "$PROFILE" 2>/dev/null; then
            printf '\n# hackit\n%s\n' "$PATH_LINE" >> "$PROFILE"
            ok "added $BIN_DIR to PATH in $PROFILE"
        else
            ok "$PROFILE already references $BIN_DIR"
        fi
        export PATH="$BIN_DIR:$PATH"
    fi
fi
echo

# -- Done -----------------------------------------------------------------------------------
box_top "$G"
box_row "" "$G" "$G"
box_row "  ✔  HackIT installed successfully" "$G" "$G"
box_row "" "$G" "$G"
box_row "  hackit --help       show all commands" "$G" "$W"
box_row "  hackit              interactive console" "$G" "$W"
box_row "  hackit cve <url>    CVE intel scan" "$G" "$W"
box_row "" "$G" "$G"
box_bot "$G"
echo
echo "  If 'hackit' is not found in this shell yet:"
echo "    source ~/.bashrc   # or ~/.zshrc"
echo
