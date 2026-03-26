#!/usr/bin/env bash
# Run both Apple-Silicon hotspot suites. Use the per-suite scripts if only one
# area changed:
#   - run_hotspots_symmetric.sh
#   - run_hotspots_pk.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/run_hotspots_symmetric.sh"
"$SCRIPT_DIR/run_hotspots_pk.sh"
