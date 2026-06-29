#!/bin/bash
# PortStorm — Build ALL Engines (delegates to go/build_engines.sh)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$DIR/go/build_engines.sh"
