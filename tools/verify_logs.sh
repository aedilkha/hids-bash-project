#!/bin/bash
# Verify the SHA-256 chain generated for HIDS alerts.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${1:-$SCRIPT_DIR/hids.conf}"
source "$CONFIG_FILE" 2>/dev/null || true
LOG_DIR="${LOG_DIR:-/var/log/hids}"
CHAIN_FILE="$LOG_DIR/alerts.sha256"
ALERT_LOG="$LOG_DIR/alerts.log"

if [[ ! -r "$CHAIN_FILE" || ! -r "$ALERT_LOG" ]]; then
    printf 'Missing readable alert log or hash chain in %s\n' "$LOG_DIR" >&2
    exit 1
fi

previous_hash=""
line_number=0
while IFS=$'\t' read -r record_hash encoded_payload; do
    ((line_number++))
    payload="$(printf '%s' "$encoded_payload" | base64 -d 2>/dev/null)" || {
        printf 'Invalid payload at chain record %d\n' "$line_number" >&2
        exit 1
    }
    expected_hash="$(printf '%s' "$payload" | sha256sum | awk '{print $1}')"
    [[ "$record_hash" == "$expected_hash" && "$payload" == "$previous_hash"* ]] || {
        printf 'Integrity failure at chain record %d\n' "$line_number" >&2
        exit 1
    }
    previous_hash="$record_hash"
done < "$CHAIN_FILE"

printf 'Integrity OK: %d alert record(s) verified in %s\n' "$line_number" "$CHAIN_FILE"
printf 'Protect the log and chain files from root-level tampering as well.\n'