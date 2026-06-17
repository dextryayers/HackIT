#!/bin/bash

# ==============================================================================
# HACKIT 🚀 AI PENTEST FRAMEWORK
# Cross-platform launcher, installer & commander
# ==============================================================================

# -- Colors --
R='\033[0;31m';  G='\033[0;32m';  Y='\033[1;33m'
B='\033[0;34m';  C='\033[0;36m';  M='\033[0;35m'
W='\033[1;37m';  D='\033[2m';     NC='\033[0m'

# -- Glyphs --
OK="${G}✔${NC}"; ERR="${R}✘${NC}"; WARN="${Y}⚠${NC}"
INFO="${C}➔${NC}"; ARROW="${C}▸${NC}"

# -- Paths --
HACKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
GO_ENGINE_DIR="$HACKIT_DIR/hackit/agent/go"
GO_CHAT_DIR="$HACKIT_DIR/hackit/agent/chat_go"
GO_BYPASS_DIR="$HACKIT_DIR/hackit/403bypass/go_engine"

# -- OS & terminal --
OS="$(uname -s)"
case "$OS" in
    Darwin*)  OS_NAME="macOS"   ;;
    MINGW*|CYGWIN*|MSYS*) OS_NAME="Windows" ;;
    *)        OS_NAME="Linux"   ;;
esac

PYTHON="python3"; [ "$OS_NAME" = "Windows" ] && PYTHON="python"

COLS=$(tput cols 2>/dev/null || echo 72)
[ "$COLS" -gt 80 ] && COLS=80

# ── helpers ───────────────────────────────────────────────────────────────────
INNER=$((COLS - 4))  # chars between box corners

box_top() { local c="${1:-$C}"; printf "  ${c}╔$(printf '═%.0s' $(seq 1 $INNER))╗${NC}\n"; }
box_mid() { local c="${1:-$C}"; printf "  ${c}╠$(printf '═%.0s' $(seq 1 $INNER))╣${NC}\n"; }
box_bot() { local c="${1:-$C}"; printf "  ${c}╚$(printf '═%.0s' $(seq 1 $INNER))╝${NC}\n"; }

# print a row: left border + content + right border, padded to INNER
# Usage: box_row "text" [color] [content_color]
box_row() {
    local text="$1" bc="${2:-$C}" cc="${3:-$W}"
    local plain; plain=$(printf '%s' "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local pad=$((INNER - ${#plain}))
    [ $pad -lt 1 ] && pad=1
    printf "  ${bc}║${NC}${cc}%s${NC}%${pad}s${bc}║${NC}\n" "$text" ""
}

print_box() {
    local title="$1" color="${2:-$C}"
    local tlen=${#title}
    local pad=$(( (INNER - tlen) / 2 ))
    [ $pad -lt 2 ] && pad=2
    local right=$(( INNER - tlen - pad ))
    [ $right -lt 2 ] && right=2
    box_top "$color"
    printf "  ${color}║${NC}%*s${W}%s${NC}%*s${color}║${NC}\n" $pad "" "$title" $right ""
    box_bot "$color"
}

section() {
    echo -e "\n  ${C}┌─${D}$(printf '─%.0s' $(seq 1 $((COLS-6))))${NC}"
    echo -e "  ${C}│${NC}  ${W}$1${NC}"
    echo -e "  ${C}└─${D}$(printf '─%.0s' $(seq 1 $((COLS-6))))${NC}"
}

step()     { echo -e "  ${ARROW}  $1"; }
step_ok()  { echo -e "  ${OK}  ${G}$1${NC}"; }
step_fail() { echo -e "  ${ERR}  ${R}$1${NC}"; }
step_warn(){ echo -e "  ${WARN}  ${Y}$1${NC}"; }

spinner() {
    local pid=$1 msg="$2" spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    echo -ne "  ${C}⠋${NC}  $msg"
    while kill -0 "$pid" 2>/dev/null; do
        for i in $(seq 0 9); do
            echo -ne "\r  ${C}${spin:$i:1}${NC}  $msg"; sleep 0.08
        done
    done
    wait "$pid" && echo -e "\r  ${OK}  ${G}$msg${NC}" || echo -e "\r  ${ERR}  ${R}$msg${NC}"
}

run_spinner() { local m="$1"; shift; ("$@" &>/dev/null) & spinner $! "$m"; }

detect_pkg_mgr() {
    command -v apt-get &>/dev/null && echo "apt" && return
    command -v dnf     &>/dev/null && echo "dnf" && return
    command -v pacman  &>/dev/null && echo "pacman" && return
    command -v zypper  &>/dev/null && echo "zypper" && return
    command -v apk     &>/dev/null && echo "apk" && return
    echo "unknown"
}

# ── BANNER ────────────────────────────────────────────────────────────────────
print_banner() {
    echo -e ""
    box_top "$C"
    box_row "" "$C"
    box_row "       H a c k i t   I n s t a l l" "$C" "$W"
    box_row "" "$C"
    box_row "  AI Penetration Testing Framework" "$C" "$D"
    box_bot "$C"
    echo -e ""
}

# ── HELP ──────────────────────────────────────────────────────────────────────
show_help() {
    print_banner
    print_box "USAGE" "$C"
    echo -e ""
    echo -e "  ${W}./hackit.sh${NC}  ${D}[command]${NC}  ${D}[options...]${NC}"
    echo -e ""

    box_top "$W"
    box_row "  COMMANDS" "$W" "$Y"
    box_mid "$W"
    box_row "  install    Install all deps + build + launch" "$W" "$G"
    box_row "  update     Git pull + rebuild engines" "$W" "$G"
    box_row "  build      Rebuild Go engines only" "$W" "$G"
    box_row "  version    Show version info" "$W" "$G"
    box_row "  help       Show this help screen" "$W" "$G"
    box_bot "$W"
    echo -e ""

    box_top "$W"
    box_row "  EXAMPLES" "$W" "$Y"
    box_mid "$W"
    box_row "  ./hackit.sh                 Enter the framework" "$W" "$D"
    box_row "  ./hackit.sh install          Install everything + launch" "$W" "$D"
    box_row "  ./hackit.sh agent            Open AI agent" "$W" "$D"
    box_row "  ./hackit.sh ports scan -p 1-1000 --targets example.com" "$W" "$D"
    box_row "  ./hackit.sh vuln sqli --url http://test.com?id=1" "$W" "$D"
    box_bot "$W"
    echo -e ""
}

# ── SYSTEM DEPS ───────────────────────────────────────────────────────────────
install_system_deps() {
    section "System Dependencies"

    local INSTALL_CMD=""
    local PKGS=""

    case "$OS_NAME" in
        macOS)
            step "Checking Homebrew..."
            if ! command -v brew &>/dev/null; then
                step_warn "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            step_ok "Homebrew ready"
            run_spinner "Installing system packages..." brew install go nmap python3 ruby git curl
            ;;

        Windows)
            if command -v choco &>/dev/null; then
                run_spinner "Installing via Chocolatey..." choco install -y golang nmap python3 ruby git
            elif command -v winget &>/dev/null; then
                run_spinner "Installing via Winget..." winget install -e --id GoLang.Go && winget install -e --id Insecure.Nmap && winget install -e --id Python.Python.3.11
            else
                step_warn "No package manager found. Install manually: go, nmap, python3, git"
            fi
            ;;

        Linux)
            if [ "$EUID" -ne 0 ]; then
                step_warn "Root needed for system packages."
                step_warn "Run: sudo ./hackit.sh install"
                echo -e ""
                step "Trying without root (will skip system packages)..."
                return 1
            fi

            local PKG=$(detect_pkg_mgr)
            step "Package manager: ${PKG}"

            case "$PKG" in
                apt)
                    INSTALL_CMD="apt-get install -y -qq"
                    PKGS="golang nmap python3 python3-pip python3-venv ruby git curl wget build-essential"
                    step "Updating package lists..."
                    apt-get update -qq 2>/dev/null || true
                    run_spinner "Installing system packages..." apt-get install -y -qq $PKGS
                    ;;
                dnf)
                    PKGS="golang nmap python3 python3-pip ruby git curl wget gcc make"
                    run_spinner "Installing system packages..." dnf install -y $PKGS
                    ;;
                pacman)
                    PKGS="go nmap python python-pip ruby git curl wget base-devel"
                    run_spinner "Installing system packages..." pacman -Sy --noconfirm $PKGS
                    ;;
                zypper)
                    PKGS="go nmap python3 python3-pip ruby git curl wget gcc make"
                    run_spinner "Installing system packages..." zypper --non-interactive install $PKGS
                    ;;
                apk)
                    PKGS="go nmap python3 py3-pip ruby git curl wget build-base"
                    run_spinner "Installing system packages..." apk add --no-cache $PKGS
                    ;;
                *)
                    step_warn "Unknown package manager. Install manually: go, nmap, python3, git"
                    return 1
                    ;;
            esac
            ;;
    esac

    echo -e ""
    for tool in go nmap $PYTHON git; do
        if command -v "$tool" &>/dev/null; then
            local ver=""
            case "$tool" in
                go)     ver=$(go version 2>/dev/null | grep -oE 'go[0-9.]+' | head -1) ;;
                nmap)   ver=$(nmap --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1) ;;
                git)    ver=$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1) ;;
                *)      ver=$($tool --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1) ;;
            esac
            step_ok "${tool} ${ver:+$ver}"
        else
            step_fail "${tool} not found"
        fi
    done
}

# ── PYTHON DEPS ───────────────────────────────────────────────────────────────
install_python_deps() {
    section "Python Dependencies"
    cd "$HACKIT_DIR"

    # Bootstrap pip if missing
    if ! $PYTHON -m pip --version &>/dev/null; then
        step "pip not found, bootstrapping..."
        $PYTHON -m ensurepip --upgrade 2>/dev/null || $PYTHON -m ensurepip 2>/dev/null || true
    fi
    step_ok "pip ready"

    run_spinner "Upgrading pip + setuptools..." $PYTHON -m pip install --quiet --upgrade pip setuptools wheel

    if [ -f requirements.txt ]; then
        local REQ_COUNT=$(grep -cE '^[a-zA-Z0-9]' requirements.txt 2>/dev/null || echo 0)
        step "Installing ${REQ_COUNT} Python packages..."
        if $PYTHON -m pip install --quiet -r requirements.txt 2>/dev/null; then
            step_ok "All Python packages installed"
        else
            step_warn "Some packages failed — check internet or install manually:"
            step_warn "  pip install -r requirements.txt"
        fi
    fi

    run_spinner "Registering hackit package..." $PYTHON -m pip install --quiet -e .
    step_ok "hackit package registered"
}

# ── GO ENGINES ────────────────────────────────────────────────────────────────
build_go_engine() {
    local dir="$1" name="$2" out="${3:-ai_engine}"
    [ ! -d "$dir" ] && step_warn "Skipping ${name} (not found)" && return
    step "Building ${name}..."
    cd "$dir"
    go mod tidy 2>/dev/null || true
    if go build -ldflags="-s -w" -o "$out" . 2>/dev/null; then
        local SIZE=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out" 2>/dev/null || echo 0)
        local HR="$(numfmt --to=iec "$SIZE" 2>/dev/null || echo "${SIZE}B")"
        step_ok "${name} → ${out} (${HR})"
    else
        step_fail "${name} build failed"
    fi
    cd "$HACKIT_DIR"
}

build_engines() {
    section "Go Engines"
    export GO111MODULE=on
    local ANY=false

    for spec in "$GO_ENGINE_DIR:AI Engine:ai_engine" "$GO_CHAT_DIR:Chat Engine:chat_engine" "$GO_BYPASS_DIR:Bypass Engine:bypass_engine"; do
        local dir="${spec%%:*}" rest="${spec#*:}"
        local name="${rest%%:*}" out="${rest##*:}"
        if [ -d "$dir" ]; then build_go_engine "$dir" "$name" "$out"; ANY=true; fi
    done

    if [ "$ANY" = false ]; then
        step_warn "No Go engine directories found"
    else
        echo -e ""; step_ok "All engines built"
    fi
}

# ── GLOBAL SYMLINK ────────────────────────────────────────────────────────────
setup_symlink() {
    section "Global Access"
    local LINK_TARGET=""

    if [ -w /usr/local/bin ]; then
        LINK_TARGET="/usr/local/bin/hackit"
    elif [ -d "$HOME/.local/bin" ] && [ -w "$HOME/.local/bin" ]; then
        LINK_TARGET="$HOME/.local/bin/hackit"
    elif echo "$PATH" | grep -q "$HOME/.local/bin"; then
        mkdir -p "$HOME/.local/bin" 2>/dev/null && LINK_TARGET="$HOME/.local/bin/hackit"
    fi

    if [ -n "$LINK_TARGET" ]; then
        ln -sf "$HACKIT_DIR/hackit.sh" "$LINK_TARGET"
        step_ok "Symlink created: ${LINK_TARGET}"
    else
        step_warn "Could not create symlink. Add this to your ~/.bashrc:"
        echo -e "       ${D}alias hackit='${HACKIT_DIR}/hackit.sh'${NC}"
    fi
}

# ── VERIFY ────────────────────────────────────────────────────────────────────
verify_install() {
    section "Verification"

    local ALL_GOOD=true

    # Python
    if $PYTHON -c "import hackit" 2>/dev/null; then
        step_ok "hackit Python module loads"
    else
        step_fail "hackit Python module broken"
        ALL_GOOD=false
    fi

    # Engines
    local E_COUNT=0
    for e in ai_engine chat_engine bypass_engine; do
        local found=$(find "$HACKIT_DIR" -name "$e" -type f 2>/dev/null | head -1)
        if [ -n "$found" ] && [ -x "$found" ]; then
            E_COUNT=$((E_COUNT + 1))
        fi
    done
    step_ok "${E_COUNT}/3 Go engines executable"

    # CLI works
    if $PYTHON main.py --version &>/dev/null; then
        step_ok "CLI responds"
    else
        step_fail "CLI not responding"
        ALL_GOOD=false
    fi

    echo -e ""
    if [ "$ALL_GOOD" = true ]; then
        step_ok "Everything looks good!"
    else
        step_warn "Some checks failed — review output above"
    fi
}

# ── INSTALL ────────────────────────────────────────────────────────────────────
do_install() {
    print_banner
    local SEP=$(printf '─%.0s' $(seq 1 $INNER))
    echo -e "  ${C}${SEP}${NC}"
    echo -e "  ${W}  HACKIT INSTALLER${NC}          ${D}${OS_NAME} | $(date '+%H:%M:%S')${NC}"
    echo -e "  ${C}${SEP}${NC}"
    echo -e ""

    install_system_deps
    echo -e ""
    install_python_deps
    echo -e ""
    build_engines
    echo -e ""
    setup_symlink
    echo -e ""
    verify_install

    # Final summary
    echo -e ""
    box_top "$G"
    box_row "     HACKIT INSTALLATION COMPLETE" "$G" "$W"
    box_mid "$G"
    box_row "  OS        ${OS_NAME}" "$G" "$D"
    box_row "  Python    $($PYTHON --version 2>/dev/null || echo 'N/A')" "$G" "$D"
    box_row "  Go        $(go version 2>/dev/null | grep -oE 'go[0-9.]+' || echo 'N/A')" "$G" "$D"
    local ECOUNT=$(find "$HACKIT_DIR" -name 'ai_engine' -o -name 'chat_engine' -o -name 'bypass_engine' 2>/dev/null | wc -l)
    box_row "  Engines   ${ECOUNT}/3 built" "$G" "$D"
    box_row "  Command   hackit  or  ./hackit.sh" "$G" "$C"
    box_bot "$G"
    echo -e ""

    # Auto-launch
    echo -e "  ${C}▸${NC}  ${W}Launching HackIT...${NC}\n"
    cd "$HACKIT_DIR"
    exec $PYTHON main.py
}

# ── UPDATE ─────────────────────────────────────────────────────────────────────
do_update() {
    print_banner
    section "Update"
    cd "$HACKIT_DIR"
    step "Pulling latest code..."
    if git pull origin main 2>&1; then
        step_ok "Repository updated"
    else
        step_fail "Git pull failed"
        exit 1
    fi
    echo -e ""
    build_engines
    echo -e ""
    step_ok "HackIT is up to date"
}

# ── VERSION ────────────────────────────────────────────────────────────────────
show_version() {
    print_banner
    echo -e "  ${W}Version${NC}  ${C}2.1.0${NC}"
    echo -e "  ${W}OS${NC}      ${C}${OS_NAME}${NC}"
    echo -e "  ${W}Python${NC}  ${C}$($PYTHON --version 2>/dev/null || echo 'N/A')${NC}"
    echo -e "  ${W}Go${NC}      ${C}$(go version 2>/dev/null || echo 'N/A')${NC}"
    echo -e "  ${W}Dir${NC}     ${D}${HACKIT_DIR}${NC}"
    echo -e ""
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN ROUTER
# ══════════════════════════════════════════════════════════════════════════════

CMD="${1:-}"

case "$CMD" in
    install|INSTALL)
        do_install
        ;;
    update|UPDATE)
        do_update
        ;;
    build|BUILD)
        print_banner
        build_engines
        ;;
    version|--version|-v)
        show_version
        ;;
    help|--help|-h|'/?')
        show_help
        ;;
    "")
        show_help
        echo -e "  ${C}▸${NC}  ${W}Entering HackIT framework...${NC}\n"
        cd "$HACKIT_DIR"
        exec $PYTHON main.py
        ;;
    *)
        cd "$HACKIT_DIR"
        exec $PYTHON main.py "$@"
        ;;
esac
