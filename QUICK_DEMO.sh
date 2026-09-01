#!/bin/bash
# ==============================================================================
# QUICK_DEMO.sh — 5-minute HIDS demonstration
# Simplified version for quick on-demand demo
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

printf '\n=== HIDS 5-MINUTE DEMO ===\n\n'
printf 'This demonstrates the core capabilities:\n'
printf '  1. Baseline capture\n'
printf '  2. Clean system verification\n'
printf '  3. Three threat scenarios\n'
printf '  4. Alert logging\n\n'

# Check for root
if [[ $(id -u) -ne 0 ]]; then
    printf 'Error: This demo requires root privileges.\n'
    printf 'Run: sudo ./QUICK_DEMO.sh\n'
    exit 1
fi

printf 'Running full orchestrated demo...\n\n'
exec sudo bash demo.sh
