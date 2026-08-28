#!/bin/bash
# Safely create a process from /tmp so Module 3 can demonstrate PRC-001.
# The copied binary and process are removed automatically when the script exits.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_BINARY="/tmp/hids-demo-process"
DEMO_PID=""

cleanup() {
    if [[ -n "$DEMO_PID" ]]; then
        kill "$DEMO_PID" 2>/dev/null || true
        wait "$DEMO_PID" 2>/dev/null || true
    fi
    rm -f "$DEMO_BINARY"
}
trap cleanup EXIT INT TERM

sleep_binary="$(command -v sleep 2>/dev/null || true)"
if [[ -z "$sleep_binary" ]]; then
    printf 'Cannot find sleep; demo cannot run.\n' >&2
    exit 1
fi

cp "$sleep_binary" "$DEMO_BINARY"
chmod 700 "$DEMO_BINARY"
"$DEMO_BINARY" 30 &
DEMO_PID=$!

printf 'Simulated attack: temporary executable started with PID %s\n' "$DEMO_PID"
printf 'Running Module 3; expected detection: PRC-001\n\n'

bash "$SCRIPT_DIR/hids.sh" --no-color --module 3
scan_exit=$?

if grep -q 'PRC-001' "$SCRIPT_DIR"/logs/alerts.jsonl 2>/dev/null || \
   grep -q 'PRC-001' /var/log/hids/alerts.jsonl 2>/dev/null; then
    printf '\nDemo passed: PRC-001 was recorded.\n'
    exit 0
fi

printf '\nDemo did not observe PRC-001 (module exit %s).\n' "$scan_exit" >&2
exit 1
