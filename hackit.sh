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
OK="${G}✔${NC}"
ERR="${R}✘${NC}"
WARN="${Y}⚠${NC}"
INFO="${C}➔${NC}"
ARROW="${C}▸${NC}"

# -- Paths --
HACKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
GO_ENGINE_DIR="$HACKIT_DIR/hackit/agent/go"
GO_CHAT_DIR="$HACKIT_DIR/hackit/agent/chat_go"
GO_BYPASS_DIR="$HACKIT_DIR/hackit/403bypass/go_engine"

# -- OS & terminal --
OS="$(uname -s)"
case "$OS" in
    Darwin*)  OS_NAME="macOS"   ;; MINGW*|CYGWIN*|MSYS*) OS_NAME="Windows" ;;
    *)        OS_NAME="Linux"   ;;
esac

PYTHON="python3"; [ "$OS_NAME" = "Windows" ] && PYTHON="python"

COLS=$(tput cols 2>/dev/null || echo 72)
[ "$COLS" -gt 80 ] && COLS=80

# ── helpers ───────────────────────────────────────────────────────────────────
print_box() {
    local title="$1" color="${2:-$C}"
    local pad=$(( (COLS - 4 - ${#title}) / 2 ))
    [ $pad -lt 2 ] && pad=2
    local right=$(( COLS - 4 - ${#title} - pad ))
    [ $right -lt 2 ] && right=2
    printf "  ${color}╔"
    printf '═%.0s' $(seq 1 $((COLS-2)))
    printf "╗${NC}\n"
    printf "  ${color}║${NC}%*s${W}%s${NC}%*s${color}║${NC}\n" $pad "" "$title" $right ""
    printf "  ${color}╚"
    printf '═%.0s' $(seq 1 $((COLS-2)))
    printf "╝${NC}\n"
}

section() {
    echo -e "\n  ${C}┌─${D}$(printf '─%.0s' $(seq 1 $((COLS-6))))${NC}"
    echo -e "  ${C}│${NC}  ${W}$1${NC}"
    echo -e "  ${C}└─${D}$(printf '─%.0s' $(seq 1 $((COLS-6))))${NC}"
}

step() {
    echo -e "  ${ARROW}  $1"
}

step_ok()   { echo -e "  ${OK}  ${G}$1${NC}"; }
step_fail() { echo -e "  ${ERR}  ${R}$1${NC}"; }
step_warn() { echo -e "  ${WARN}  ${Y}$1${NC}"; }

spinner() {
    local pid=$1; local msg="$2"; local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    echo -ne "  ${C}⠋${NC}  $msg"
    while kill -0 "$pid" 2>/dev/null; do
        for i in $(seq 0 9); do
            echo -ne "\r  ${C}${spin:$i:1}${NC}  $msg"
            sleep 0.08
        done
    done
    wait "$pid" && echo -e "\r  ${OK}  ${G}$msg${NC}" || echo -e "\r  ${ERR}  ${R}$msg${NC}"
}

run_spinner() {
    local msg="$1"; shift
    ("$@" &>/dev/null) &
    spinner $! "$msg"
}

# ── OS detection details ──────────────────────────────────────────────────
detect_pkg_mgr() {
    command -v apt-get &>/dev/null && echo "apt"    && return
    command -v dnf     &>/dev/null && echo "dnf"    && return
    command -v pacman  &>/dev/null && echo "pacman" && return
    command -v zypper  &>/dev/null && echo "zypper" && return
    echo "unknown"
}

# ── BANNER ────────────────────────────────────────────────────────────────────
print_banner() {
    echo -e ""
    printf "  ${C}╔══════════════════════════════════════════════════════╗${NC}\n"
    printf "  ${C}║${NC}                                                     ${C}║${NC}\n"
    printf "  ${C}║${NC}              ${W}H a c k i t   I n s t a l l${NC}              ${C}║${NC}\n"
    printf "  ${C}║${NC}                                                     ${C}║${NC}\n"
    printf "  ${C}║${NC}       ${D}AI Penetration Testing Framework${NC}         ${C}║${NC}\n"
    printf "  ${C}╚══════════════════════════════════════════════════════╝${NC}\n"
    echo -e ""
}

# ── HELP ──────────────────────────────────────────────────────────────────────
show_help() {
    print_banner
    print_box "USAGE" "$C"

    echo -e ""
    echo -e "  ${W}./hackit.sh${NC}  ${D}[command]${NC}  ${D}[options...]${NC}"
    echo -e ""

    echo -e "  ${W}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${W}║${NC}  ${Y}COMMANDS${NC}                                            ${W}║${NC}"
    echo -e "  ${W}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${W}║${NC}  ${G}install${NC}    Install deps + build + launch             ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${G}update${NC}     Git pull + rebuild engines                ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${G}build${NC}      Rebuild Go engines only                   ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${G}version${NC}    Show version info                         ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${G}help${NC}       Show this help screen                     ${W}║${NC}"
    echo -e "  ${W}╚══════════════════════════════════════════════════════╝${NC}"
    echo -e ""

    echo -e "  ${W}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${W}║${NC}  ${Y}EXAMPLES${NC}                                          ${W}║${NC}"
    echo -e "  ${W}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${W}║${NC}  ${D}./hackit.sh${NC}          Enter the framework             ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${D}./hackit.sh install${NC}   Install everything + launch    ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${D}./hackit.sh agent${NC}     Open AI agent                  ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${D}./hackit.sh ports scan -p 1-1000 --targets example.com${NC}  ${W}║${NC}"
    echo -e "  ${W}║${NC}  ${D}./hackit.sh vuln sqli --url http://test.com?id=1${NC}     ${W}║${NC}"
    echo -e "  ${W}╚══════════════════════════════════════════════════════╝${NC}"
    echo -e ""
}

# ── SYSTEM DEPS ───────────────────────────────────────────────────────────────
install_system_deps() {
    section "System Dependencies"

    case "$OS_NAME" in
        macOS)
            step "Checking Homebrew..."
            if ! command -v brew &>/dev/null; then
                step_warn "Homebrew not found, installing..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            step_ok "Homebrew ready"
            run_spinner "Installing go, nmap, python3, ruby..." brew install go nmap python3 ruby
            ;;

        Windows)
            if command -v choco &>/dev/null; then
                run_spinner "Installing via Chocolatey..." choco install -y golang nmap python3 ruby
            elif command -v winget &>/dev/null; then
                run_spinner "Installing via Winget..." winget install -e --id GoLang.Go && winget install -e --id Insecure.Nmap
            else
                step_warn "No package manager found. Install manually: go, nmap, python3"
            fi
            ;;

        Linux)
            if [ "$EUID" -ne 0 ]; then
                step_warn "Skipping system deps (not root). Run with: sudo ./hackit.sh install"
                return
            fi
            local PKG=$(detect_pkg_mgr)
            step "Detected package manager: ${PKG}"
            case "$PKG" in
                apt)    run_spinner "Installing deps..." bash -c "apt-get update -qq && apt-get install -y -qq golang nmap python3 python3-pip ruby" ;;
                dnf)    run_spinner "Installing deps..." bash -c "dnf install -y golang nmap python3 python3-pip ruby" ;;
                pacman) run_spinner "Installing deps..." bash -c "pacman -Sy --noconfirm go nmap python python-pip ruby" ;;
                zypper) run_spinner "Installing deps..." bash -c "zypper --non-interactive install go nmap python3 python3-pip ruby" ;;
                *)      step_warn "Unknown package manager. Install go, nmap, python3 manually." ;;
            esac
            ;;
    esac

    echo -e ""
    for tool in go nmap $PYTHON; do
        if command -v "$tool" &>/dev/null; then
            ver=$($tool version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
            step_ok "${tool} ${ver:-ready}"
        else
            step_fail "${tool} not found"
        fi
    done
}

# ── PYTHON DEPS ───────────────────────────────────────────────────────────────
install_python_deps() {
    section "Python Dependencies"

    cd "$HACKIT_DIR"

    run_spinner "Upgrading pip..." $PYTHON -m pip install --quiet --upgrade pip

    if [ -f requirements.txt ]; then
        local REQ_COUNT=$(grep -cE '^[a-zA-Z]' requirements.txt 2>/dev/null || echo 0)
        step "Installing ${REQ_COUNT} packages from requirements.txt..."
        if $PYTHON -m pip install --quiet -r requirements.txt 2>/dev/null; then
            step_ok "Python packages installed"
        else
            step_fail "Some packages failed (check network)"
        fi
    fi

    run_spinner "Installing hackit package..." $PYTHON -m pip install --quiet -e .
    step_ok "hackit package registered"
}

# ── GO ENGINES ────────────────────────────────────────────────────────────────
build_go_engine() {
    local dir="$1" name="$2" out="${3:-ai_engine}"
    if [ ! -d "$dir" ]; then
        step_warn "Skipping ${name} (directory not found)"
        return
    fi
    step "Building ${name}..."
    cd "$dir"
    go mod tidy 2>/dev/null || true
    if go build -ldflags="-s -w" -o "$out" . 2>/dev/null; then
        local SIZE=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out" 2>/dev/null || echo 0)
        step_ok "${name} → ${out} ($(numfmt --to=iec $SIZE 2>/dev/null || echo "${SIZE}B"))"
    else
        step_fail "${name} build failed"
    fi
    cd "$HACKIT_DIR"
}

build_engines() {
    section "Go Engines"

    export GO111MODULE=on
    local ANY=false

    if [ -d "$GO_ENGINE_DIR" ]; then
        build_go_engine "$GO_ENGINE_DIR" "AI Engine"   "ai_engine"
        ANY=true
    fi
    if [ -d "$GO_CHAT_DIR" ]; then
        build_go_engine "$GO_CHAT_DIR"  "Chat Engine"  "chat_engine"
        ANY=true
    fi
    if [ -d "$GO_BYPASS_DIR" ]; then
        build_go_engine "$GO_BYPASS_DIR" "Bypass Engine" "bypass_engine"
        ANY=true
    fi

    if [ "$ANY" = false ]; then
        step_warn "No Go engine directories found"
    else
        echo -e ""
        step_ok "All engines ready"
    fi
}

# ── INSTALL ────────────────────────────────────────────────────────────────────
do_install() {
    print_banner
    echo -e "  ${C}────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${W}  HACKIT INSTALLER${NC}          ${D}${OS_NAME} | $(date '+%H:%M:%S')${NC}"
    echo -e "  ${C}────────────────────────────────────────────────────────────${NC}"
    echo -e ""

    install_system_deps
    echo -e ""
    install_python_deps
    echo -e ""
    build_engines
    echo -e ""

    # Global symlink
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
        step_ok "Symlink: ${LINK_TARGET}"
    else
        step_warn "Could not create symlink. Add to PATH manually:"
        echo -e "       ${D}alias hackit='${HACKIT_DIR}/hackit.sh'${NC}"
    fi

    # Summary
    echo -e ""
    echo -e "  ${G}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${G}║${NC}          ${W}HACKIT INSTALLATION COMPLETE${NC}          ${G}║${NC}"
    echo -e "  ${G}╠════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${G}║${NC}  ${W}OS${NC}        ${D}${OS_NAME}${NC}                              ${G}║${NC}"
    echo -e "  ${G}║${NC}  ${W}Python${NC}    $($PYTHON --version 2>/dev/null || echo 'N/A')                    ${G}║${NC}"
    echo -e "  ${G}║${NC}  ${W}Go${NC}        $(go version 2>/dev/null | grep -oE 'go[0-9.]+' || echo 'N/A')              ${G}║${NC}"
    echo -e "  ${G}║${NC}  ${W}Engines${NC}   $(find "$HACKIT_DIR" -name 'ai_engine' -o -name 'chat_engine' -o -name 'bypass_engine' 2>/dev/null | wc -l)/3 built           ${G}║${NC}"
    echo -e "  ${G}║${NC}  ${W}Run${NC}        ${C}./hackit.sh${NC}                          ${G}║${NC}"
    echo -e "  ${G}╚════════════════════════════════════════════════════╝${NC}"
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
