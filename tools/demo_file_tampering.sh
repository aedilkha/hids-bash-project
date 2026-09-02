#!/bin/bash
# ==============================================================================
# demo_file_tampering.sh
# Demonstrates Module 4 (File Integrity) detection.
# Creates a temporary copy of /etc/passwd, modifies it, and Module 4 detects it.
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_FILE="/tmp/hids-demo-passwd"
DEMO_BACKUP="/tmp/hids-demo-passwd.bak"
ORIGINAL_MODE=""

cleanup() {
    if [[ -n "$ORIGINAL_MODE" && -e /etc/ssh/sshd_config ]]; then
        chmod "$ORIGINAL_MODE" /etc/ssh/sshd_config 2>/dev/null || true
    fi
    rm -f "$DEMO_FILE" "$DEMO_BACKUP"
}
trap cleanup EXIT INT TERM

# Create a test file in /etc-like location (but in /tmp for safety)
if [[ ! -f /etc/passwd ]]; then
    printf 'Cannot find /etc/passwd; demo cannot run.\n' >&2
    exit 1
fi

# For demo: change permissions on a watched file to demonstrate detection.

printf 'Simulated attack: file tampering detected\n'
printf 'Expected detection: FIM-001 (permissions too broad)\n\n'

# Make /etc/ssh/sshd_config world-readable (bad)
# First, check if we can do this
if [[ -w /etc/ssh/sshd_config ]]; then
    ORIGINAL_MODE="$(stat -c '%a' /etc/ssh/sshd_config)"
    cp -p /etc/ssh/sshd_config "$DEMO_BACKUP"
    chmod 644 /etc/ssh/sshd_config  # Should be 600
    printf 'Changed /etc/ssh/sshd_config permissions to 644 (was 600)\n'
    printf 'Run: sudo ./hids.sh --module 4\n'
    printf 'Expected: [HIGH] FIM-001 Permissions on /etc/ssh/sshd_config too broad\n\n'
    
    # Give user time to run the check
    printf 'Waiting 10 seconds before cleanup...\n'
    sleep 10
    
    # Restore
    if [[ -f "$DEMO_BACKUP" ]]; then
        cp -p "$DEMO_BACKUP" /etc/ssh/sshd_config
        chmod "$ORIGINAL_MODE" /etc/ssh/sshd_config
        rm -f "$DEMO_BACKUP"
        printf 'Restored /etc/ssh/sshd_config\n'
    fi
else
    printf 'Insufficient permissions to modify /etc/ssh/sshd_config\n'
    printf 'For demo, this script must be run as root.\n'
    exit 1
fi
