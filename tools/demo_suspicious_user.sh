#!/bin/bash
# ==============================================================================
# demo_suspicious_user.sh
# Demonstrates Module 2 (User Activity) detection.
# Creates a temporary user with suspiciously low UID to demonstrate detection.
# ==============================================================================

set -u

DEMO_USER="hids_demo_user"
DEMO_UID=200

cleanup() {
    # Remove the demo user if it exists
    if id "$DEMO_USER" &>/dev/null; then
        userdel -r "$DEMO_USER" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

printf 'Simulated attack: suspicious user account created\n'
printf 'Expected detection: USR-002 (new privileged-like account)\n\n'

# Check if we have root
if [[ $(id -u) -ne 0 ]]; then
    printf 'This demo requires root privileges.\n'
    printf 'Run: sudo ./tools/demo_suspicious_user.sh\n'
    exit 1
fi

# Create a user with a suspiciously low UID (typically system account)
if useradd -u "$DEMO_UID" -s /bin/bash "$DEMO_USER" 2>/dev/null; then
    printf 'Created user: %s (UID: %d)\n' "$DEMO_USER" "$DEMO_UID"
    printf 'This looks like a system account but is actually interactive.\n'
    printf 'Run: sudo ./hids.sh --module 2\n'
    printf 'Expected: [MEDIUM] USR-002 Suspicious account with low UID\n\n'
    
    # Give user time to run the check
    printf 'Waiting 10 seconds before cleanup...\n'
    sleep 10
else
    printf 'Could not create demo user (already exists?)\n'
    exit 1
fi
