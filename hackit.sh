#!/bin/bash

# ==============================================================================
# HACKIT V3 - AUTONOMOUS AI PENTEST SWARM
# GLOBAL BASH WRAPPER & ORCHESTRATOR
# ==============================================================================

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Base Paths
HACKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
GO_ENGINE_DIR="$HACKIT_DIR/hackit/agent/go"

print_banner() {
    echo -e "${RED}"
    cat << "EOF"
  _   _               _   ___ _____ 
 | | | | __ _  ___| | / /_ _|_   _|
 | |_| |/ _` |/ __| |/ / | |  | |  
 |  _  | (_| | (__|   <  | |  | |  
 |_| |_|\__,_|\___|_|\_\|___| |_|  
       Autonomous AI Swarm Engine
EOF
    echo -e "${NC}"
}

check_dependencies() {
    echo -e "${CYAN}[+] Checking system dependencies...${NC}"
    MISSING=0

    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}[!] Golang not found.${NC}"
        MISSING=1
    fi

    if ! command -v nmap &> /dev/null; then
        echo -e "${YELLOW}[!] Nmap not found.${NC}"
        MISSING=1
    fi

    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}[!] Python3 not found.${NC}"
        MISSING=1
    fi

    if [ $MISSING -eq 1 ]; then
        echo -e "${RED}[X] Missing dependencies! Launching Auto-Installer...${NC}"
        auto_install_deps
    else
        echo -e "${GREEN}[V] All dependencies are met.${NC}"
    fi
}

auto_install_deps() {
    echo -e "${CYAN}[+] Detecting Operating System (Windows/Mac/Linux)...${NC}"
    OS="$(uname -s)"
    
    if [[ "$OS" == *"Darwin"* ]]; then
        echo -e "${CYAN}[+] Detected macOS. Using Homebrew...${NC}"
        if ! command -v brew &> /dev/null; then
            echo -e "${RED}[!] Homebrew not found! Installing Homebrew...${NC}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install go nmap python ruby
    elif [[ "$OS" == *"MINGW"* || "$OS" == *"CYGWIN"* || "$OS" == *"MSYS"* ]]; then
        echo -e "${CYAN}[+] Detected Windows (Git Bash/MSYS).${NC}"
        if command -v choco &> /dev/null; then
            echo -e "${CYAN}[+] Using Chocolatey...${NC}"
            choco install -y golang nmap python ruby
        elif command -v winget &> /dev/null; then
            echo -e "${CYAN}[+] Using Winget...${NC}"
            winget install -e --id GoLang.Go
            winget install -e --id Insecure.Nmap
            winget install -e --id Python.Python.3.11
            winget install -e --id RubyInstallerTeam.Ruby
        else
            echo -e "${RED}[X] Windows Package Manager (Choco/Winget) not found! Please install dependencies manually.${NC}"
            exit 1
        fi
    else
        # Linux (Debian/Ubuntu/Fedora/Arch)
        if [ "$EUID" -ne 0 ]; then
            echo -e "${RED}[!] Please run 'sudo ./hackit.sh install' on Linux.${NC}"
            exit 1
        fi
        if command -v apt-get &> /dev/null; then
            echo -e "${CYAN}[+] Using APT (Debian/Ubuntu/WSL)...${NC}"
            apt-get update
            apt-get install -y golang nmap python3 python3-pip ruby
        elif command -v dnf &> /dev/null; then
            echo -e "${CYAN}[+] Using DNF (Fedora/RHEL)...${NC}"
            dnf install -y golang nmap python3 python3-pip ruby
        elif command -v pacman &> /dev/null; then
            echo -e "${CYAN}[+] Using Pacman (Arch Linux)...${NC}"
            pacman -Sy --noconfirm go nmap python python-pip ruby
        else
            echo -e "${RED}[X] Linux OS not recognized. Please install manually.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[V] Dependencies successfully installed cross-platform!${NC}"
}

build_engine() {
    echo -e "${CYAN}[+] Recompiling HackIT Swarm Engine (Go)...${NC}"
    cd "$GO_ENGINE_DIR" || exit 1
    
    # Enable Go Modules
    export GO111MODULE=on
    go mod tidy
    
    # Build for the current platform
    go build -ldflags "-s -w" -o ai_engine .
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[V] Swarm Engine successfully compiled!${NC}"
    else
        echo -e "${RED}[X] Compilation failed! Check the errors above.${NC}"
        exit 1
    fi
}

install_global() {
    print_banner
    check_dependencies
    build_engine

    echo -e "${CYAN}[+] Creating global symlink...${NC}"
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] You are not root. Attempting to use sudo for /usr/local/bin symlink...${NC}"
        sudo ln -sf "$HACKIT_DIR/hackit.sh" /usr/local/bin/hackit
    else
        ln -sf "$HACKIT_DIR/hackit.sh" /usr/local/bin/hackit
    fi

    echo -e "${GREEN}======================================================================${NC}"
    echo -e "${GREEN}[V] HackIT successfully installed globally!${NC}"
    echo -e "${GREEN}[V] You can now type ${YELLOW}hackit${GREEN} from anywhere in your terminal.${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo -e "Usage Examples:"
    echo -e "  hackit -swarm example.com -swarm-scope active_stealth"
    echo -e "  hackit -autopilot example.com"
}

# ==============================================================================
# MAIN EXECUTION ROUTER
# ==============================================================================

if [ "$1" == "install" ]; then
    install_global
    exit 0
fi

if [ "$1" == "update" ]; then
    echo -e "${CYAN}[+] Updating HackIT from GitHub repository...${NC}"
    cd "$HACKIT_DIR" || exit 1
    git pull origin main
    build_engine
    echo -e "${GREEN}[V] Update complete!${NC}"
    exit 0
fi

# Print banner for normal execution
print_banner

# Determine Executable based on OS
OS="$(uname -s)"
ENGINE="$GO_ENGINE_DIR/ai_engine"

if [[ "$OS" == *"MINGW"* || "$OS" == *"CYGWIN"* || "$OS" == *"MSYS"* ]]; then
    # If run from Git Bash on Windows
    ENGINE="$GO_ENGINE_DIR/ai_engine.exe"
fi

if [ ! -f "$ENGINE" ]; then
    echo -e "${RED}[X] Swarm Engine not compiled yet! Running auto-build...${NC}"
    build_engine
fi

# Execute the Go Engine and pass all user arguments
echo -e "${CYAN}[+] Connecting to Swarm Engine...${NC}"
cd "$HACKIT_DIR" || exit 1

# If user provided no arguments, show help
if [ $# -eq 0 ]; then
    $ENGINE -h
    exit 0
fi

# Pass arguments directly to the engine
$ENGINE "$@"
