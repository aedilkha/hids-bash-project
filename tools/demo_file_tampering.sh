#!/bin/bash
# ==============================================================================
# demo_file_tampering.sh
# Demonstrates Module 4 (File Integrity) detection.
# Creates a temporary copy of /etc/passwd, modifies it, and Module 4 detects it.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_FILE="/tmp/hids-demo-sensitive.conf"

cleanup() {
    rm -f "$DEMO_FILE"
}
trap cleanup EXIT INT TERM

printf 'Simulated attack: file tampering detected\n'
printf 'Demo file: %s\n' "$DEMO_FILE"
printf 'Expected transition: mode 600 -> 666 -> removed\n'
printf 'Run: sudo ./hids.sh --config hids.demo.conf --module 4\n'
printf 'Expected: [HIGH] FIM-001 Permissions on the demo file too broad\n\n'

printf 'tamperable demo configuration\n' > "$DEMO_FILE"
chmod 666 "$DEMO_FILE"
printf 'Changed %s permissions to 666 (baseline mode is 600)\n' "$DEMO_FILE"
printf 'Waiting 10 seconds before cleanup...\n'
sleep 10
printf 'Removed demo file and restored the host automatically\n'
