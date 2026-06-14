#!/bin/bash
# SQLi Engine — Full Build Script
# Builds Go binary + Rust shared library + verifies Python imports
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== SQLi Engine v4.0 — Full Build ==="
echo ""

# Step 1: Build Go engine
echo "[1/4] Building Go engine..."
cd "$DIR/go"
mkdir -p bin
go build -o bin/worker .
BIN_SIZE=$(stat --format=%s bin/worker 2>/dev/null || stat -f%z bin/worker 2>/dev/null)
echo "  → bin/worker ($BIN_SIZE bytes)"
./bin/worker -h 2>/dev/null | head -1
echo ""

# Step 2: Build Rust shared library
echo "[2/4] Building Rust engine..."
cd "$DIR/go/rust_engine"
cargo build --release --quiet 2>/dev/null || cargo build --release
LIB=$(ls target/release/librust_engine.so 2>/dev/null || ls target/release/rust_engine.dll 2>/dev/null || echo "N/A")
if [ -f "$LIB" ]; then
    LIB_SIZE=$(stat --format=%s "$LIB" 2>/dev/null || stat -f%z "$LIB" 2>/dev/null)
    echo "  → $LIB ($LIB_SIZE bytes)"
else
    echo "  → $LIB"
fi
echo ""

# Step 3: Build wireless Go workers
echo "[3/4] Building Wireless Go workers..."
WIRELESS_DIR="$DIR/../wireless/go_workers"
if [ -d "$WIRELESS_DIR" ]; then
    cd "$WIRELESS_DIR"
    go build -o /dev/null . 2>&1 && echo "  → OK (wireless workers compile)"
else
    echo "  → Skipped (wireless not in expected path)"
fi
echo ""

# Step 4: Verify Python imports
echo "[4/4] Verifying Python imports..."
python3 -c "
import sys, os
sys.path.insert(0, '$DIR/../..')
from hackit.sqli.go_bridge import GoEngine
from hackit.sqli.rust_bridge import RustEngine
g = GoEngine()
r = RustEngine()
print(f'  → GoEngine.sqli:   available={g.available}  binary={os.path.exists(g.binary_path)}')
print(f'  → RustEngine.sqli: available={r.available}')
print('  ✓ All imports OK')
"
echo ""

# Summary
echo "=== Build Complete ==="
echo ""
echo "Usage:"
echo "  sqli -u <URL> --dbs"
echo "  sqli -u <URL> --dbs --tables"
echo "  sqli -u <URL> -D <db> -T <table> --dump"
echo "  sqli -u <URL> --risk-level 5 --dump-all"
echo "  sqli -u <URL> --os-access   # OS command exec"
echo "  sqli -u <URL> --exfil-dns   # OOB DNS exfil"
echo ""

# Count payloads
echo "Payload count by DBMS:"
cd "$DIR/go/payloads"
for f in *.go; do
    count=$(grep -c 'Type:' "$f" 2>/dev/null || true)
    if [ "$count" -gt 0 ]; then
        dbms=$(echo "$f" | sed 's/\.go//')
        printf "  %-15s %3d\n" "$dbms" "$count"
    fi
done
echo "  ———————————————"
echo "  TOTAL: $(grep -rh 'Type:' *.go 2>/dev/null | wc -l)"
