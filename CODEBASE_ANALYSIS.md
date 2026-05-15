# HackIt Framework - Complete Codebase Analysis

## 📋 Project Overview

**HackIt** is a professional-grade, multi-language penetration testing and security reconnaissance framework authored by **AniipID**. It combines multiple programming languages (Python, Go, Rust, C/C++, Ruby, Lua) in a **Hexa-Engine Architecture** for optimal performance and specialization.

**Version**: 2.1.0 (with Tech Hunter V3 and OSINT enhancements)
**Python Version Required**: ≥ 3.8
**Purpose**: Penetration testing, vulnerability scanning, reconnaissance, and security analysis

---

## 🏗️ Hexa-Engine Architecture

The framework follows a layered multi-language design where each language handles tasks best suited to it:

```
┌─────────────────────────────────────────────┐
│         HACKIT CLI Entry Point              │
│     (Python: click CLI interface)           │
└─────────────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────┐
│    GO CORE ORCHESTRATOR (Module Bridge)     │
│  - Concurrency & Goroutines                 │
│  - Network multiplexing (10,000+ connections)
│  - RPC/CGO coordination                     │
│  - AI Engine integration                    │
└─────────────────────────────────────────────┘
         /          │          │          \
    ┌────┴┐    ┌────┴┐    ┌────┴┐    ┌────┴┐
    │RUST │    │ C++ │    │PYTHON    │ LUA │
    │     │    │     │    │ ENGINE   │     │
    └─────┘    └─────┘    └─────────┘    └─────┘
  (Brute-  (Raw Packets) (WAF Logic)  (NSE-style
   force)    (OS Detect)  (Vuln Heur)  Probes)
```

---

## 📦 Core Dependencies

```
✓ click==8.1.7              # CLI framework
✓ aiohttp==3.9.1            # Async HTTP client
✓ requests==2.31.0          # HTTP library
✓ beautifulsoup4==4.12.2    # HTML parsing
✓ dnspython==2.4.2          # DNS queries
✓ cryptography==41.0.7      # Cryptographic operations
✓ scapy==2.5.0              # Packet crafting & sniffing
✓ colorama==0.4.6           # Terminal colors (Windows)
✓ fake-useragent==1.4.0     # User-Agent spoofing
✓ rich==13.7.0              # Rich terminal formatting
✓ tqdm==4.66.1              # Progress bars
✓ tabulate==0.9.0           # Table formatting
✓ psutil==5.9.8             # System utilities
✓ python-dotenv==1.0.1      # Environment variables
```

---

## 🐍 Python Module Architecture

### 1. **Core Entry Point** (`main.py`, `cli.py`)

**Files:**
- [main.py](main.py) - Entry point wrapper
- [hackit/cli.py](hackit/cli.py) - Main CLI group with click decorators

**Purpose:**
- Defines the `hackit` command-line interface using Click
- Manages global options: `--proxy`, `--no-verify`, `--no-banner`, `--verbose`
- Sets environment variables for module access (`HACKIT_PROXY`, `HACKIT_VERIFY`)
- Organizes subcommands into logical groups: `ports`, `web`, `vuln`, `recon`, `ssl`, `util`
- Enters interactive console if no subcommand provided

**Key Commands:**
```
hackit ports scan            # Port scanning
hackit web headers           # HTTP header analysis
hackit web tech              # Technology detection
hackit web fuzz              # Web fuzzer
hackit vuln xss              # XSS scanner
hackit vuln sqli             # SQL injection tester
hackit recon subdomains      # Subdomain enumeration
hackit recon ips             # IP range scanning
hackit ssl check             # SSL/TLS analysis
hackit agent                 # AI agent interface
```

**Flow:**
```
User Input → cli.py (Click Parser) → Set Environment Variables 
→ Display Banner → Route to Appropriate Module
```

---

### 2. **Configuration System** (`config.py`)

**File:** [hackit/config.py](hackit/config.py)

**Purpose:**
- Persistent configuration management stored in `~/.hackit_config.json`
- Manages themes, AI provider keys, and user settings

**Key Functions:**
- `load_config()` - Loads config from disk with fallback to defaults
- `save_config(config)` - Atomic write with temp file safety
- `get_theme()` - Returns active theme name
- `set_theme(theme_name)` - Updates theme preference
- `get_user_info()` - Returns username and hostname

**Default Configuration:**
```python
{
    "theme": "kali",
    "user": getpass.getuser(),
    "hostname": socket.gethostname(),
    "aggressive_default": True,
    "stealth_default": True,
    "ai_keys": {
        "gemini": "",
        "groq": "",
        "openai": "",
        "claude": "",
        "deepseek": "",
        "openrouter": ""
    },
    "ai_provider": "gemini"
}
```

---

### 3. **UI & Logging System** (`ui.py`, `logger.py`)

**Files:**
- [hackit/ui.py](hackit/ui.py) - Terminal styling and banner
- [hackit/logger.py](hackit/logger.py) - Structured logging

**Features:**
- Color-coded output (Kali, ASCII, minimal themes)
- Banner display (`display_banner()`)
- Progress indicators
- Logging with severity levels

---

### 4. **Port Scanner Module** (`port_scanner/`)

**Files:**
- [hackit/port_scanner/core.py](hackit/port_scanner/core.py) - Python socket-based scanner
- `hackit/port_scanner/go/` - High-performance Go implementation
- `hackit/port_scanner/go_bridge.py` - Bridge to Go engine

**`PortScanner` Class (Python):**

```python
class PortScanner:
    • common_services: {port: service_name} mapping
    • scan_port(host, port, timeout) → JSON result
    • scan(host, ports=None, timeout=1, threads=100) → List[Dict]
```

**Features:**
- Multi-threaded scanning using ThreadPoolExecutor
- Service identification (21=FTP, 22=SSH, 80=HTTP, etc.)
- Banner grabbing with protocol-specific probes
- Supports port ranges and comma-separated lists
- Timeout configuration per port

**Protocol-Specific Probes:**
```
HTTP (80, 8080, 443):  HEAD / HTTP/1.1\r\n...
FTP (21):              Banner on connect
SSH (22):              Banner on connect
MySQL (3306):          MySQL handshake
PostgreSQL (5432):     Postgres protocol
```

**Performance:**
- Python: 100 threads @ 1-second timeout
- Go: 10,000+ concurrent connections via Goroutines

**CLI Usage:**
```bash
hackit ports scan -p 80,443 --targets example.com
hackit ports scan -p 1-1000 --targets 192.168.1.1
```

---

### 5. **Directory Finder / Brute Forcer** (`dir_finder/`)

**Key Files:**
- [hackit/dir_finder/analyzer.py](hackit/dir_finder/analyzer.py) - Smart analysis engine
- `hackit/dir_finder/dir_finder.rb` - Ruby fuzzer
- `hackit/dir_finder/db/` - Wordlist database
- `hackit/dir_finder/rust_engine/` - Rust brute-force engine

**SmartAnalyzer Class:**

```python
class SmartAnalyzer:
    # Features
    • detect_tech()      → Parse headers and detect tech stack
    • extract_js_endpoints() → Regex-based endpoint discovery
    • detect_waf()       → Fingerprint WAF technology
    • find_backups()     → Search for .zip, .tar.gz, .bak files
```

**Tech Detection:**
- Header-based: X-Powered-By, Server
- Meta tags: Generator meta tags
- Fingerprints: WordPress (`wp-content`), Laravel (`laravel_session`)
- WAF Detection: Cloudflare, FortiWeb, Akamai

**Endpoint Extraction:**
- Regex: `["'](/[a-zA-Z0-9\._\-/]+)["']` finds URL patterns
- JavaScript parsing for API routes
- Filters false positives (comments starting with //)

**CLI Usage:**
```bash
hackit dirfinder --url https://target.com --wordlist common.txt
```

---

### 6. **Technology Hunter** (`tech_hunter/`)

**Key Files:**
- [hackit/tech_hunter/brain.py](hackit/tech_hunter/brain.py) - Intelligence correlator
- `hackit/tech_hunter/go/` - Go fingerprinting engine

**Features (v3.0):**
- **200+ Technology Detection**: CMS, Frontend, Backend, JS libraries
- **Confidence Scoring**: Refined algorithm for accuracy
- **Organizational Mapping**: Detects affiliated domains and subsidiaries
- **OSINT Integration**: WHOIS, DNS, Network intelligence

**Fingerprinting Targets:**
```
CMS:               Wix, Squarespace, Ghost, TYPO3, Drupal, WordPress
Frontend FW:       React, Vue, Angular, Astro, Svelte
Styling:           Tailwind CSS, Bootstrap, Material Design
JS Libraries:      GSAP, Alpine.js, Preact, Solid.js
Backend:           Node.js, Django, Rails, Laravel
Hosting:           AWS, Azure, Cloudflare, Vercel
```

---

### 7. **Sub-domain Enumeration** (`subdomain/`)

**Bridge:** [hackit/subdomain/go_bridge.py](hackit/subdomain/go_bridge.py)

**Engine Features:**
- Passive subdomain discovery
- Active brute-forcing with wordlists
- Zone transfer attempts
- Takeover detection
- Permutation generation
- Recursive enumeration

**CLI Flags:**
```
-d, --domain        Target domain
-w, --wordlist      Path to wordlist
--passive-only      Only passive enumeration
--active-only       Only active brute-force
--recursive         Recursively enumerate subdomains
--takeover          Check for subdomain takeovers
--permutations      Generate subdomain permutations
-c, --concurrency   Number of threads
--filter-codes      HTTP status codes to filter
-v, --verbose       Verbose output
```

**Output Fields:**
```
sub, ip, port, server, title, status, tech, asn, whois, geo, cname, ptr, service
```

---

### 8. **XSS Scanner** (`xss/`)

**Bridge:** [hackit/xss/go_bridge.py](hackit/xss/go_bridge.py)

**GoEngine Class:**

```python
class GoEngine:
    • ensure_compiled() → Compiles Go source if needed
    • run(url) → Yields streaming JSON results
```

**Features:**
- Payload-based XSS detection
- Streaming result mode (line-by-line JSON parsing)
- Custom payloads from `payload.txt`
- Go worker auto-compilation on modification

**Compilation Logic:**
```
If binary doesn't exist OR source newer than binary:
    → go build -o worker.exe .
    → Returns True on success
```

---

### 9. **SQL Injection Tester** (`sqli/`)

**Files:**
- [hackit/sqli/build_sqli.py](hackit/sqli/build_sqli.py) - Builder script
- `hackit/sqli/go/` - Go engine
- `hackit/sqli/cpp/` - C++ implementation
- `hackit/sqli/c/` - Low-level C implementation

**Approaches:**
- **Time-based blind SQLi**: Analyze response timing
- **Error-based SQLi**: Parse database error messages
- **Union-based SQLi**: Extract via UNION SELECT
- **WAF bypass**: Mutation and encoding techniques

---

### 10. **SSL/TLS Analysis** (`ssl_tool/`)

**Core:** [hackit/ssl_tool/core.py](hackit/ssl_tool/core.py)

**Analysis:**
- Certificate chain validation
- Cipher suite strength analysis
- Protocol version detection (SSL3.0, TLS 1.0-1.3)
- Certificate pinning detection
- Heartbleed, POODLE vulnerability checks

**CLI Usage:**
```bash
hackit ssl check --host target.com --port 443
```

---

### 11. **Header Audit** (`header_audit/`)

**Bridge:** [hackit/header_audit/go_bridge.py](hackit/header_audit/go_bridge.py)

**Security Headers Checked:**
- `X-Frame-Options` (Clickjacking)
- `X-Content-Type-Options` (MIME sniffing)
- `Content-Security-Policy` (XSS mitigation)
- `Strict-Transport-Security` (HSTS)
- `X-XSS-Protection` (Legacy XSS filter)
- `Access-Control-Allow-Origin` (CORS)
- `Referrer-Policy` (Referrer leakage)

---

### 12. **Web Fuzzer** (`web_fuzzer/`)

**Engines:**
- `cpp_bridge.py` - C++ implementation
- `go_bridge.py` - Go implementation
- `rust_bridge.py` - Rust implementation

**Features:**
- Multi-wordlist fuzzing
- Status code filtering
- Response size analysis
- Timeout handling
- Custom header injection

**CLI Usage:**
```bash
hackit web fuzz --url https://target.com/FUZZ --wordlist common.txt
```

---

### 13. **Parameter Fuzzer** (`params/`)

**Core:** [hackit/params/core.py](hackit/params/core.py)

**Approach:**
- Detects parameter injection points
- Tests common parameters (id, user, search, etc.)
- Payload mutation and encoding
- Response differentiation analysis

---

### 14. **JavaScript Analyzer** (`js/`)

**Bridge:** [hackit/js/go_bridge.py](hackit/js/go_bridge.py)

**Analysis:**
- Source map detection
- Secret/API key discovery in JS
- Endpoint extraction
- Library detection and version identification
- Vulnerable JS patterns

---

### 15. **Redirect Follower** (`redirect/`)

**Bridge:** [hackit/redirect/go_bridge.py](hackit/redirect/go_bridge.py)

**Features:**
- Detects HTTP/301/302/307/308 redirects
- Follows redirect chains
- Open redirect vulnerability detection
- Protocol confusion (HTTP→HTTPS)

---

### 16. **CVE Checker** (`cve/`)

**Bridge:** [hackit/cve/go_bridge.py](hackit/cve/go_bridge.py)

**Features:**
- Maps detected tech to CVEs
- Queries CVE databases
- Severity scoring (CVSS)
- Exploitation likelihood

---

### 17. **Network Scanner** (`network_scanner/`)

**Bridge:** [hackit/network_scanner/go_bridge.py](hackit/network_scanner/go_bridge.py)

**Features:**
- CIDR range scanning
- Host discovery
- Network topology mapping
- ARP spoofing detection
- Network sniffing

---

### 18. **NSE Scripts Engine** (`nse_engine.py`)

**Purpose:** Nmap Script Engine (NSE) -inspired modular scripting framework

**Architecture:**

```python
def load_scripts() → List[str]
    # Scans hackit/nse_scripts/ for *.py modules
    # Returns list of available script names

def run_scripts_for_port(names, host, port, info) → List[Dict]
    # Imports each script module
    # Calls module.run(host, port, info)
    # Returns aggregated findings
```

**Script Interface:**
```python
def run(host: str, port: int, info: Dict) -> List[Dict]:
    # info contains: status, banner, service, etc.
    # Returns list of findings (dicts) or []
    # Errors should not crash engine
```

**Example Script:**
- [hackit/nse_scripts/http_server_info.py](hackit/nse_scripts/http_server_info.py) - HTTP server detection

**Features:**
- Safe sandboxed execution
- Error isolation (one script error doesn't crash engine)
- Reusable module pattern
- Rapid prototyping for CVE checks

---

### 19. **Interactive Console** (`console.py`)

**File:** [hackit/console.py](hackit/console.py)

**HackItConsole Class:**

```python
class HackItConsole:
    # Features
    • interactive_loop()       # REPL interface
    • tab_completion()         # Auto-complete commands
    • history_management()     # Readline integration
    • context_switching()      # Module context (e.g., "ports > scan")
    • themed_prompts()         # Dynamic prompt based on theme
```

**Features:**
- Metasploit-like experience
- Tab completion for commands
- Command history (saved to `~/.hackit_history`)
- Context-aware prompting
- Readline/Pyreadline support

**Prompt Formats:**
```
hackit> dirfinder --url target.com
hackit (ports)> scan -p 80,443 target.com
hackit (web)> tech --url target.com
```

---

### 20. **AI Agent Engine** (`agent/`)

**Key Files:**
- [hackit/agent/brain.py](hackit/agent/brain.py) - AI coordination
- [hackit/agent/commands.py](hackit/agent/commands.py) - Specialized modes
- [hackit/agent/go/main.go](hackit/agent/go/main.go) - Go engine

**AIHyperBrain Class:**

```python
class AIHyperBrain:
    • config: Load AI provider keys
    • provider: Active AI provider (gemini, groq, claude, etc.)
    • system_prompt: Unified security + coding expertise
    • chat(prompt) → str
        # Executes command parsing
        # Routes to appropriate provider
        # Implements failover mechanism
```

**Features:**

**System Prompt Characteristics:**
- Identity: HackIt AI v2.1 (created by Hanif Abdrrohim)
- Expertise: Go, Python, CVE analysis, WAF bypass, OWASP
- Tone: Technical, tactical, warm
- Output: Plain-text (no Markdown formatting)

**Command Modes:**
```
/risk        # Risk assessment analysis
/attack      # Attack vector suggestions
/vuln        # Vulnerability analysis
/payload     # Payload generation
/build       # Program building from scratch
/analyze     # Security analysis of tools
```

**Failover Mechanism:**
- If primary provider fails → Try next configured provider
- Keeps rotating until success or all exhausted
- Graceful degradation

**Supported AI Providers:**
1. **Gemini** (Google) - Primary default
2. **Groq** - Fast inference
3. **Claude** (Anthropic) - Advanced reasoning
4. **OpenAI** - GPT-4, GPT-3.5
5. **OpenRouter** - Aggregated API
6. **DeepSeek** - Alternative model

**Go AI Engine** (`agent/go/main.go`):
- Handles HTTP clients for all providers
- Manages conversation history
- Vulnerability analysis mode
- Model selection optimization

---

### 21. **Anonymity Tools** (`anonymity.py`)

**Purpose:**
- Proxy configuration
- VPN toggling
- User-Agent rotation
- Request spoofing headers
- Geolocation masking

---

## 🔵 Go Modules (`/agent/go/`, `/port_scanner/go/`, etc.)

### Core Go Features Across Modules:

**1. Concurrency:**
- Goroutines for handling 10,000+ connections
- Channel-based communication
- WaitGroups for synchronization

**2. Networking:**
- Raw packet crafting with `google/gopacket`
- HTTP/HTTPS client libraries
- DNS resolution and enumeration
- Socket manipulation

**3. Data Processing:**
- JSON encoding/decoding
- CSV/TSV output
- Large dataset filtering
- Real-time streaming

**4. Integration:**
- Command-line flags parsing
- subprocess stdio handling
- Error propagation to Python

---

### **Agent Go Engine** (`agent/go/main.go`)

**Flags:**
```
-provider    AI provider (gemini, groq, claude, etc.)
-key         API key for provider
-prompt      User prompt
-system      System prompt (context)
-model       Model name
-analyze     Enable vulnerability analysis mode
-tool        Tool name being analyzed
-clear       Clear conversation history
-mode        Command mode (risk, attack, vuln, etc.)
```

**Provider Handlers:**
```go
handleGemini()              // Google's Gemini API
handleOpenAICompatible()    // OpenAI-compatible APIs
handleClaude()              // Anthropic's Claude
// Each recursively tries multiple model versions/endpoints
```

**History Management:**
- Stores conversation context in local file
- Max history depth to prevent token overflow
- Clear history on demand

**Vulnerability Analyzer:**
- Parses scan output
- Generates AI analysis prompts
- Categorizes findings by severity

---

## 🦀 Rust Modules

**Locations:** `*/rust_engine/`, `/dir_finder/rust_engine/`, `/tech_hunter/rust_engine/`

**Use Cases:**
- **Mass Directory Bruteforcing**: Optimized with `tokio` async
- **Port Scanning**: Parallel connection attempts
- **Wordlist Processing**: High-speed file parsing
- **Performance**: 50x faster than Python for CPU-intensive tasks

**Key Dependencies:**
- `tokio` - Async runtime
- `libpcap-sys` - Packet capture bindings
- `regex` - Pattern matching

---

## 🔴 C/C++ Modules

**Locations:** `*/c/`, `*/cpp/`

**Specializations:**

**C (TCP/IP Fingerprinting):**
- OS identification via TTL, Window Size, IP ID anomalies
- 98% accuracy on remote kernel detection
- Low-level socket manipulation

**C++ (Service Probes):**
- Banner matching with regex
- Binary handshake patterns (MSSQL, TNS, RDP)
- Protocol-specific detection
- Advanced firewall/IDS evasion (fragmented packets)

---

## 🌙 Lua Scripting (`/lua/`)

**Purpose:** NSE-style extensibility layer

**Features:**
- Sandboxed execution
- Module loading
- CVE-specific probes
- Custom rule definitions

**Use Cases:**
- Rapid prototyping
- CVE-2021-44228 (Log4Shell) detection
- Service-specific vulnerability checks
- Custom scanning policies

---

## 🔴 Ruby Components

**File:** `hackit/scripts/` (various `.rb` files)

**Integration:**
- CLI orchestration helpers
- Task scheduling
- Thread-pool management
- Advanced text processing

---

## 📊 Data Flow Analysis

### Typical Scan Execution Flow:

```
1. User Input
   ↓
2. Click CLI Parser (cli.py)
   ↓
3. Set Global Environment Variables
   ↓
4. Import & Initialize Module
   ↓
5a. Python Engine          5b. Go Bridge              5c. Compiled Binary
    ├─ Socket operations   ├─ Goroutines            ├─ Rust (Brute-force)
    ├─ HTTP requests       ├─ Concurrency            ├─ C/C++ (Raw packets)
    └─ Analysis             └─ RPC to binary         └─ Lua (Scripts)
   ↓
6. Aggregate Results
   ↓
7. Format Output (JSON/Table/Text)
   ↓
8. Display to User
```

### Module Interaction Matrix:

```
CLI (main entry)
├─ config.py        (Load user settings)
├─ ui.py            (Display output)
├─ Port Scanner
│  ├─ Python: core.py
│  └─ Go: port_scanner/go/main.go
├─ Tech Hunter
│  ├─ brain.py (correlation)
│  └─ Go: tech_hunter/go/
├─ Subdomain Enum
│  └─ Go: subdomain/go/main.go
├─ XSS Scanner
│  └─ Go: xss/go/main.go
├─ SQLi Tester
│  ├─ Go: sqli/go/
│  ├─ C++: sqli/cpp/
│  └─ C: sqli/c/
├─ AI Agent
│  ├─ brain.py (coordination)
│  └─ Go: agent/go/main.go (provider routing)
├─ NSE Engine
│  └─ Loads /nse_scripts/*.py (custom probes)
├─ Web Fuzzer
│  ├─ Go: web_fuzzer/go/
│  ├─ C++: web_fuzzer/cpp/
│  └─ Rust: web_fuzzer/rust/
└─ Console
   └─ Interactive REPL for multi-command workflow
```

---

## 🎯 Key Files Summary Table

| File/Module | Purpose | Language | Performance |
|---|---|---|---|
| cli.py | CLI interface | Python | Entry point |
| port_scanner/core.py | Basic port scanning | Python | ~100 ports/sec |
| port_scanner/go/ | High-perf scanning | Go | ~10,000 concurrent |
| dir_finder/analyzer.py | Directory discovery | Python | Medium speed |
| dir_finder/rust_engine/ | High-speed brute-force | Rust | 50x faster |
| tech_hunter/brain.py | Tech fingerprinting | Python | Real-time |
| subdomain/go/ | Subdomain enum | Go | High concurrency |
| xss/go/ | XSS detection | Go | Streaming |
| sqli/ (C++/C) | SQLi testing | C/C++ | Raw performance |
| ssl_tool/core.py | SSL analysis | Python | On-demand |
| agent/brain.py | AI orchestration | Python | Multi-provider |
| agent/go/ | AI backends | Go | Provider routing |
| console.py | Interactive shell | Python | User interaction |
| nse_engine.py | Script loader | Python | Modular |

---

## 🔄 Compilation & Runtime

### Build Process:

1. **on first use** or **source modification**:
   ```python
   ensure_compiled():
       if not binary_exists or source_newer_than_binary:
           go build -o worker.exe .
   ```

2. **Go modules** compile to:
   - Windows: `worker.exe`
   - Linux/Mac: `worker` (no extension)

3. **Cross-platform compatibility:**
   - Binary names adjusted via `platform.system()`
   - Path separators handled automatically

### Execution:

```python
# Subprocess execution with streaming
process = subprocess.Popen(
    [binary_path, ...args],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
```

---

## 🔐 Security Considerations

### Configuration Security:
- User config stored in home directory (`~/.hackit_config.json`)
- API keys isolated in config (not in code)
- Atomic file writes prevent corruption

### Execution Security:
- NSE scripts in isolated modules (error doesn't crash engine)
- Subprocess errors caught gracefully
- No shell=True by default (prevents command injection)

### Output Security:
- Banner grabbing length limited (100 chars max)
- HTML parsing sanitized
- User input validated before use

---

## 📈 Scalability Features

1. **Concurrency:**
   - Python: ThreadPoolExecutor (100 threads)
   - Go: Goroutines (10,000+ concurrent)
   - Rust: Tokio async (unlimited scaling)

2. **Memory Efficiency:**
   - Streaming JSON parsing (not loading entire file)
   - Lazy module loading
   - Generator patterns for results

3. **Network Optimization:**
   - Connection pooling
   - Timeout management
   - Batch requests

---

## 🎓 Development Patterns

### Module Structure (Standard):
```
hackit/module_name/
├─ __init__.py              # Entry point
├─ go_bridge.py             # Python↔Go interface
├─ core.py                  # Python business logic
├─ go/
│  ├─ main.go               # Go implementation
│  ├─ go.mod                # Go module definition
│  └─ [helpers].go
├─ c/                       # C implementation
├─ cpp/                     # C++ implementation
└─ rust_engine/             # Rust implementation
```

### Click CLI Pattern:
```python
import click

@click.command()
@click.option('--param', default='value', help='Description')
def module_name(param):
    """Module description"""
    # Implementation
    pass

if __name__ == '__main__':
    module_name()
```

---

## 🚀 Future Enhancement Opportunities

1. **Performance:**
   - Implement connection pooling for HTTP
   - Use async/await more extensively
   - Cache results between scans

2. **Features:**
   - Mac OS support improvements
   - GPU-accelerated brute-forcing
   - Machine learning-based WAF bypass

3. **Integration:**
   - GraphQL query fuzzer
   - gRPC endpoint scanner
   - Kubernetes cluster scanner

4. **AI:**
   - Local LLM support (Ollama)
   - Fine-tuning on vulnerability patterns
   - Automated exploitation

---

## 📝 Notes for Developers

- **Python Entry**: All user-facing commands start in `cli.py`
- **Go Backend**: Performance-critical sections use Go with Goroutines
- **Language Selection**:
  - Python: Logic, parsing, user interaction
  - Go: I/O, concurrency, networking
  - Rust: Brute-force, high-speed scanning
  - C/C++: Raw packet operations, OS detection
  - Lua: Scriptable probes, extensibility
  - Ruby: CLI helpers, task orchestration

- **Error Handling**:
  - Graceful failures in subprocess calls
  - Fallback mechanisms (e.g., AI provider failover)
  - User-friendly error messages

- **Testing**:
  - Integration tests via CLI
  - Unit tests for logic modules
  - Performance benchmarks for Go/Rust

---

**Last Updated:** 2026-05-15
**Framework Version:** 2.1.0
**Total Lines of Code:** ~50,000+ (across all languages)
