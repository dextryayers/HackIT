# HackIt Framework - Data Flow & Architecture Deep Dive

## 📊 Complete Data Flow Diagrams

### 1. CLI Entry Point Flow

```
┌─────────────────┐
│  User Command   │
│ hackit ports    │
│   scan -p 80   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ cli.py: Click Parser                │
│ • Parses arguments                  │
│ • Validates options                 │
│ • Sets global env vars              │
└────────┬────────────────────────────┘
         │
    ┌────┴─────┐
    │           │
    ▼           ▼
Set Env Vars   Show Banner
│              │
├─ PROXY       ├─ ASCII art
├─ VERIFY      ├─ Framework info
└─ VERBOSE     └─ Usage tips
    │
    ▼
┌──────────────────────────────────┐
│ Route to Submodule               │
│ (e.g., port_scanner)             │
└──────────────────────────────────┘
```

---

### 2. Port Scanning Flow (Python Implementation)

```
hackit ports scan -p 80,443 -t example.com
         │
         ▼
┌─────────────────────────────────┐
│ port_scanner.scan(...)          │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ Parse Port Range                │
│ • "80,443" → [80, 443]          │
│ • "1-100" → range(1, 101)       │
│ • None → range(1, 1025)         │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ ThreadPoolExecutor (100 threads)│
├─ Thread 1: scan_port(h, 80)    │
├─ Thread 2: scan_port(h, 443)   │
├─ ...                            │
└─ Thread N: scan_port(h, 22)    │
└─────────────────────────────────┘
         │
    ┌────┴─────┬─────┬─────┐
    │           │     │     │
    ▼           ▼     ▼     ▼
 PORT 80     PORT 22  PORT 443  PORT 3306
    │           │     │     │
    ▼           ▼     ▼     ▼
[OPEN]       [CLOSED] [OPEN] [CLOSED]
Banner       Empty    Banner  Empty
         │
         ▼
┌──────────────────────────────────┐
│ Aggregate Results               │
│ [{port: 80, status: open, ...}] │
│ [{port: 443, status: open, ...} │
└──────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│ Format & Display Output          │
│ • JSON                           │
│ • Table                          │
│ • Colored text                   │
└──────────────────────────────────┘
```

---

### 3. Go Bridge Flow (XSS Scanner Example)

```
hackit vuln xss --url https://target.com
         │
         ▼
┌────────────────────────────────┐
│ xss/go_bridge.py               │
│ GoEngine.ensure_compiled()     │
└────────┬───────────────────────┘
         │
         ├─ Check if binary exists
         │
         ├─ If not or source newer:
         │  └─ go build -o worker.exe .
         │
         ▼
┌────────────────────────────────┐
│ worker.exe -url https://...    │
│ (Go program starts)            │
│                                │
│ main() {                       │
│   • Parse flags               │
│   • Load payloads from disk   │
│   • Create HTTP client        │
│   • Iterate payloads          │
│   • Test each payload         │
│   • Collect results           │
│   • Output JSON               │
│ }                             │
└────────┬───────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ JSON Output (streaming)        │
│ {"vuln": "xss", "param": "..."}│
│ {"vuln": "xss", "param": "..."}│
│ {...}                          │
└────────┬───────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ Python: Parse JSON per line    │
│ • Filter out noise             │
│ • Extract JSON objects         │
│ • Yield results                │
└────────┬───────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ Display to User                │
│ [+] Found XSS vulnerability    │
│ Parameter: id                  │
│ Payload: <img src=x>           │
└────────────────────────────────┘
```

---

### 4. Tech Hunter Intelligence Flow

```
hackit web tech --url https://target.com
         │
         ▼
┌─────────────────────────────────┐
│ tech_hunter.detect(url)         │
└─────────────────────────────────┘
         │
    ┌────┴────┬────────┬────────┬────────┐
    │          │        │        │        │
    ▼          ▼        ▼        ▼        ▼
[HTTP GET]  [Parse]  [Regex]  [Finger] [DB Match]
    │          │        │        │        │
    ├─ Headers │        │        │        │
    ├─ Body    │        │        │        │
    └─ HTML    │        │        │        │
         │     │        │        │        │
         └─────┴────────┴────────┴────────┘
                │
                ▼
        ┌──────────────────┐
        │ Correlation      │
        │ brain.correlate()│
        │                  │
        │ • Tech Stack     │
        │ • WAF Detection  │
        │ • Confidence     │
        │ • Recommendations
        └────────┬─────────┘
                │
                ▼
        ┌──────────────────────┐
        │ Intelligence Report  │
        │                      │
        │ WordPress 6.0.0      │
        │ → Confidence: 95%    │
        │ → 10 Exploits        │
        │                      │
        │ Cloudflare WAF       │
        │ → Bypass: Complex    │
        └──────────────────────┘
```

---

### 5. Subdomain Enumeration Flow (Go)

```
hackit recon subdomains -d target.com --active-only
         │
         ▼
┌────────────────────────────────┐
│ subdomain/go_bridge.py         │
│ GoEngine.run(...)              │
└────────┬───────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ go/main.go                     │
│                                │
│ Passive Enumeration:           │
│ • WHOIS parsing                │
│ • Shodan/Censys queries        │
│ • Certificate logs (CT)        │
│                                │
│ Active Enumeration:            │
│ • DNS wordlist brute-force     │
│ • CIDR/IP scanning             │
│ • Permutation generation       │
│                                │
│ Concurrency:                   │
│ for each domain {              │
│   go resolve(domain)           │
│ }                              │
└────────┬───────────────────────┘
         │
    ┌────┴────┬─────┬─────┬─────┐
    │          │     │     │     │
    ▼          ▼     ▼     ▼     ▼
  api.t    www.t  mail.t dev.t admin.t
    │       │     │     │     │
    ├─ DNS ├─DNS ├─DNS ├─DNS ├─DNS
    │       │     │     │     │
    └─ IP: 1.2.3.4 / Port: 443 / Server: nginx
         │
         ├─ HTTP GET /
         ├─ Extract Title
         ├─ Detect Tech
         └─ Fingerprint Service
         │
         ▼
    ┌──────────────────────┐
    │ JSON Results         │
    │ {                    │
    │   "domain": "api...", │
    │   "ip": "1.2.3.4",   │
    │   "status": 200,     │
    │   "title": "API",    │
    │   "server": "nginx"  │
    │ }                    │
    └────────┬─────────────┘
             │
             ▼
    ┌──────────────────────┐
    │ Aggregate & Dedupe   │
    │ (Multiple resolvers) │
    └────────┬─────────────┘
             │
             ▼
    ┌──────────────────────┐
    │ Display Results      │
    │ Found: 24 subdomains │
    └──────────────────────┘
```

---

### 6. AI Agent Orchestration Flow

```
hackit agent "What are the top CVEs for WordPress?"
         │
         ▼
┌────────────────────────────┐
│ agent/brain.py             │
│ AIHyperBrain.chat(prompt)  │
└────────┬───────────────────┘
         │
    ┌────┴─────────────────┐
    │                      │
    ▼                      ▼
[Parse Command]     [Default Mode]
  /payload           (Regular chat)
  /vuln
  /build
    │                      │
    └──────────┬───────────┘
               │
         ┌─────▼─────┐
         │ Check AI  │
         │ Config    │
         │           │
         │ Provider: │
         │ gemini    │
         └─────┬─────┘
               │
         ┌─────▼──────────────────────────┐
         │ agent/go/main.go               │
         │ Invoke AI Engine               │
         │                                │
         │ -provider gemini               │
         │ -key <API_KEY>                 │
         │ -model gemini-2.5-flash        │
         │ -prompt "..."                  │
         │ -system "..."                  │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ Provider Selection             │
         │                                │
         │ If provider == gemini {        │
         │   Try v1, v1beta endpoints     │
         │   Try multiple models:         │
         │   • gemini-2.5-flash           │
         │   • gemini-3-flash             │
         │   • gemini-pro-latest          │
         │ }                              │
         │                                │
         │ If fails → Try next provider   │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ HTTP Request to AI API         │
         │ POST https://api.google.com/.. │
         │ Headers: Content-Type: json    │
         │ Body: {                        │
         │   "contents": [...],           │
         │   "systemInstruction": {...}   │
         │ }                              │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ Parse Response                 │
         │                                │
         │ {                              │
         │   "candidates": [{             │
         │     "content": {               │
         │       "text": "Response..."    │
         │     }                          │
         │   }]                           │
         │ }                              │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ Save to History                │
         │ (~/.hackit_history)            │
         │ • User message                 │
         │ • Assistant response           │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ Return to User                 │
         │                                │
         │ [+] CVE-2024-XXXXX - Critical │
         │     WordPress Plugin Bug      │
         │     CVSS: 9.8                 │
         │                                │
         │ [+] CVE-2024-YYYYY - High     │
         │     Core SQL Injection        │
         │     CVSS: 8.2                 │
         └──────────────────────────────┘
```

---

### 7. Directory Finder Rust Engine Flow

```
hackit dirfinder --url https://target.com --wordlist big.txt
         │
         ▼
┌────────────────────────────────┐
│ dir_finder/                    │
│ Smart Analyzer (Python)        │
└────────┬───────────────────────┘
         │
         ├─ Launch Rust engine
         │  (dir_finder/rust_engine/)
         │
         ▼
┌────────────────────────────────┐
│ Rust Main                      │
│                                │
│ Load wordlist into memory      │
│ Spawn Tokio runtime            │
│ (Async, non-blocking I/O)      │
└────────┬───────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ Tokio Executor (unlimited tasks)
│                                │
│ for each word {                │
│   spawn async task {           │
│     path = word                │
│     url = base_url + path      │
│     HEAD request to url        │
│     Parse status code          │
│     Store result               │
│   }                            │
│ }                              │
└────────┬───────────────────────┘
         │
    ┌────┴─────────────────────────────┐
    │                                  │
    ▼                                  ▼
 [200 OK]                          [404 Not Found]
 /admin → Save                      /foobar → Skip
 /api   → Save
    │                                  │
    └──────────────┬───────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Real-time streaming  │
        │ (Process.stdout)     │
        │                      │
        │ /admin 200           │
        │ /api 200             │
        │ /backup.zip 200      │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Python Bridge        │
        │ Collects results     │
        │ Displays to user     │
        └──────────────────────┘

Performance: ~5,000 requests/second
vs Python: ~50 requests/second (100x faster)
```

---

### 8. Module Initialization Sequence

```
hackit (user command)
   │
   ▼
main.py
   │
   ├─ Import cli from hackit.cli
   │
   ▼
cli.py: @click.group()
   │
   ├─ Imports all modules:
   │  ├─ from hackit.port_scanner import scan_ports
   │  ├─ from hackit.dir_finder import dirfinder
   │  ├─ from hackit.tech_hunter import detect
   │  ├─ from hackit.subdomain import enumerate
   │  ├─ from hackit.xss import scan_xss
   │  ├─ from hackit.sqli import test_sqli
   │  ├─ from hackit.agent import agent
   │  └─ ... (more modules)
   │
   ├─ Registers subcommands:
   │  ├─ ports.add_command(scan_ports)
   │  ├─ web.add_command(detect_tech)
   │  ├─ vuln.add_command(scan_xss)
   │  └─ ... (more groups)
   │
   ▼
On subcommand execution:
   │
   ├─ Set environment variables
   │  ├─ HACKIT_PROXY
   │  ├─ HACKIT_VERIFY
   │  └─ HACKIT_NO_BANNER
   │
   ├─ Display banner (unless --no-banner)
   │
   ├─ Load config
   │  └─ ~/.hackit_config.json
   │
   ├─ Initialize module
   │  ├─ Load wordlists
   │  ├─ Check Go compilation status
   │  ├─ Load AI provider keys
   │  └─ Prepare bridges
   │
   ▼
Execute module logic
   │
   ├─ Python processing
   ├─ Go bridge calls
   ├─ Rust engine invocations
   ├─ C/C++ compiled binaries
   └─ Lua script loading
   │
   ▼
Display results
   ├─ Format output (JSON, table, text)
   ├─ Apply color coding
   └─ Save to file (if requested)
```

---

## 🔨 Build Architecture

### Compilation Sequence

```
1. Setup Phase
   ├─ First run detected
   ├─ check_go_installed() → Requires Go 1.18+
   ├─ Check source files exist
   └─ Create output directories

2. Per-Module Compilation (On-Demand)
   ├─ When module first called:
   │  └─ GoEngine.ensure_compiled()
   │
   ├─ Check modification timestamps:
   │  ├─ If binary doesn't exist → Compile
   │  ├─ If source newer → Recompile
   │  └─ If current → Skip
   │
   ▼
3. Go Build Command
   │
   cd hackit/port_scanner/go/
   go build -o worker.exe .
   (or 'worker' on Unix)
   │
   ├─ Reads go.mod for dependencies
   ├─ Compiles all .go files in directory
   ├─ Links dependencies
   └─ Creates single binary
   │
   ▼
4. Success Indicators
   ├─ Binary file created/updated
   ├─ File permissions set to executable
   ├─ Load test on first execution
   └─ Ready for subprocess invocation

5. Failure Handling
   ├─ If go not found → Error message
   ├─ If build fails → Display go compile error
   ├─ If binary won't execute → Fallback to Python
   └─ Graceful degradation
```

### Go Module Dependencies (`go.mod` typical):

```go
module hackit/worker

go 1.21

require (
    github.com/projectdiscovery/dnsx v1.1.3
    github.com/projectdiscovery/goflags v0.1.6
    github.com/projectdiscovery/gologger v1.1.8
    github.com/projectdiscovery/mapcidr v1.0.9
    google/gopacket v1.31.20
)
```

---

## 🔄 Concurrent Execution Model

### Python Threading
```
Port Scanner:
• ThreadPoolExecutor(max_workers=100)
• Each thread: socket.connect_ex() + banner grab
• Queue-based result collection
• CPU-bound: Light overhead, network I/O dominated

Directory Finder (Python):
• ThreadPoolExecutor(max_workers=100)
• Each thread: HTTP GET request
• Thread overhead: Significant for high concurrency
```

### Go Concurrency
```
Subdomain Enumerator:
• 1 Goroutine per domain to resolve
• Channels for result coordination
• No thread switching overhead
• Can handle 10,000+ concurrent connections

Typical flow:
func main() {
    resultsChan := make(chan Result)
    for _, domain := range domains {
        go func(d string) {
            result := resolveDomain(d)
            resultsChan <- result
        }(domain)
    }
    for i := 0; i < len(domains); i++ {
        result := <-resultsChan
        fmt.Println(result)
    }
}
```

### Rust Async
```
Web Fuzzer:
• Tokio runtime (async executor)
• #[tokio::main] macro
• Future-based composability
• Zero-cost abstractions

Typical pattern:
#[tokio::main]
async fn main() {
    let tasks: Vec<_> = wordlist.iter()
        .map(|word| {
            tokio::spawn(async move {
                fuzz_endpoint(word).await
            })
        })
        .collect();
    
    for task in tasks {
        let result = task.await;
        println!("{}", result);
    }
}
```

---

## 📊 Resource Usage Patterns

### Memory
```
Startup:    ~50 MB (Python + dependencies)
Per module:  +10-50 MB (dependent on module)
Concurrency: ~1 MB per thread (Python)
            ~100 KB per goroutine (Go)
            ~50 KB per async task (Rust)
```

### CPU
```
Port Scanner:
• Python: I/O-bound (low CPU, high network)
• Go: I/O-bound (low CPU, high network)

Directory Bruteforcer:
• Python: I/O-bound (low CPU, high network)
• Rust: I/O-bound optimized (near-zero CPU idle)

Tech Detection:
• Python: CPU-bound (parsing, regex, correlation)
• Rust: CPU-bound optimized (better cache locality)

AI Agent:
• Go: I/O-bound (network latency to API)
```

### Network
```
Typical scan:
• 1,000 hosts × 100 ports = 100,000 packets
• Average: ~1 Mbps bandwidth
• Peak: ~10 Mbps (TCP SYN flood capable)

Subdomain enumeration:
• Active: 10,000+ DNS queries
• Passive: Zero bandwidth (database lookups)

Tech detection:
• 1 HTTP GET + optional JS parsing
• ~50 KB per target
```

---

## 🔄 Error Recovery Mechanisms

### Subprocess Failures
```python
try:
    result = subprocess.run([binary], capture_output=True, check=True)
    data = json.loads(result.stdout)
except subprocess.CalledProcessError as e:
    # Binary returned non-zero exit code
    return {"error": "process failed"}
except json.JSONDecodeError:
    # Invalid JSON output
    return {"error": "invalid output format"}
except Exception as e:
    # Unexpected error
    return {"error": str(e)}
```

### AI Provider Failover
```python
providers_to_try = [
    (configured_provider, configured_key),
    (backup_provider_1, backup_key_1),
    (backup_provider_2, backup_key_2),
]

for provider, key in providers_to_try:
    try:
        response = call_provider(provider, key, prompt)
        if response.success:
            return response
    except Exception:
        continue

return {"error": "all providers exhausted"}
```

### NSE Script Isolation
```python
for script_name in scripts:
    try:
        module = import_module(f"hackit.nse_scripts.{script_name}")
        findings = module.run(host, port, info)
    except Exception as e:
        findings = [{"error": f"script failed: {e}"}]
    
    # Continue to next script regardless of previous failure
    collecting_results.extend(findings)
```

---

## 🚀 Performance Optimization Techniques

### 1. Connection Pooling
```python
# aiohttp handles connection pooling automatically
# requests can use Session for pooling
session = requests.Session()
for url in urls:
    session.get(url)  # Reuses TCP connection
```

### 2. Batch Operations
```python
# Instead of 1000 individual requests
# Batch into groups
for batch in chunks(urls, size=100):
    results = parallel_batch_request(batch)
```

### 3. Caching
```python
# Cache DNS lookups
dns_cache = {}
if domain in dns_cache:
    ip = dns_cache[domain]
else:
    ip = socket.gethostbyname(domain)
    dns_cache[domain] = ip
```

### 4. Process Prewarming (Go)
```python
# Compile Go binaries during module import
# Not on every invocation
class GoEngine:
    def __init__(self):
        self.ensure_compiled()  # Warm cache
```

### 5. Streaming Output
```python
# Don't collect all results then display
# Stream as they arrive
for line in process.stdout:
    result = parse_line(line)
    display(result)  # Immediate feedback
```

---

## 🔐 Security Considerations in Architecture

### Input Validation
```python
# All user inputs validated before subprocess calls
def validate_domain(domain):
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        raise ValueError("Invalid domain")
    if domain.startswith('.'):
        raise ValueError("Domain cannot start with dot")
    return domain

cmd = [binary, '-d', validate_domain(user_input)]
subprocess.run(cmd)  # Safe
```

### Command Injection Prevention
```python
# Use list for subprocess args, NOT string
subprocess.run(['go', 'run', 'main.go', '-flag', value])  # ✓ SAFE
subprocess.run('go run main.go -flag ' + value, shell=True)  # ✗ UNSAFE
```

### SSL Verification
```python
# Environment variable controls SSL verification
verify_ssl = os.environ.get('HACKIT_VERIFY') == '1'
requests.get(url, verify=verify_ssl)

# Default: verify=True (secure)
# User can override with --no-verify flag
```

---

## 📈 Scalability Considerations

### Horizontal Scaling
```
Single machine:
• Python:  100 threads → 100 concurrent connections
• Go:      10,000 goroutines → 10,000+ concurrent
• Rust:    Unlimited async → 100,000+ concurrent

For distributed scanning:
• Use multiple HackIt instances
• Distribute targets via load balancer
• Aggregate results from multiple instances
```

### Vertical Optimization
```
CPU optimization:
• Increase GOMAXPROCS for Go (use all cores)
• Use -O2 -O3 optimization flags for C/C++

Memory optimization:
• Stream processing instead of buffering
• Lazy loading of wordlists

I/O optimization:
• Increase ulimit -n (file descriptors)
• Use sendfile() for large transfers
```

---

This comprehensive data flow analysis covers all major execution paths, concurrency models, and performance characteristics of the HackIt framework.
