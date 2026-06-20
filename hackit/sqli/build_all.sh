#!/bin/bash
# SQLi Engine — Full Build Script
# Builds Go binary + verifies Python imports
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== SQLi Engine v4.0 — Full Build ==="
echo ""

# Step 1: Build Go engine
echo "[1/3] Building Go engine..."
cd "$DIR/go"
mkdir -p bin
go build -o bin/worker .
BIN_SIZE=$(stat --format=%s bin/worker 2>/dev/null || stat -f%z bin/worker 2>/dev/null)
echo "  → bin/worker ($BIN_SIZE bytes)"
./bin/worker -h 2>/dev/null | head -1
echo ""

# Step 2: Build wireless Go workers
echo "[2/3] Building Wireless Go workers..."
WIRELESS_DIR="$DIR/../wireless/go_workers"
if [ -d "$WIRELESS_DIR" ]; then
    cd "$WIRELESS_DIR"
    go build -o /dev/null . 2>&1 && echo "  → OK (wireless workers compile)"
else
    echo "  → Skipped (wireless not in expected path)"
fi
echo ""

# Step 3: Verify Python imports
echo "[3/3] Verifying Python imports..."
python3 -c "
import sys, os
sys.path.insert(0, '$DIR/../..')
from hackit.sqli.go_bridge import GoEngine
g = GoEngine()
print(f'  → GoEngine: available={g.available}  binary={os.path.exists(g.binary_path)}')
print('  ✓ All imports OK')
"
echo ""

# Summary
echo "=== Build Complete ==="
echo ""
echo "Usage:"
echo "  sqli"
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
