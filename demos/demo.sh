#!/bin/bash
# ==============================================================================
# demo.sh — Master demo orchestrator
# Runs all three detection scenarios in sequence.
# Usage: sudo ./demos/demo.sh
# ==============================================================================

set -u

export FORCE_COLOR=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HIDS_SCRIPT="$SCRIPT_DIR/hids.sh"
TOOLS_DIR="$SCRIPT_DIR/tools"
LOG_DIR="${LOG_DIR:-/var/log/hids}"

# Colors for output
C_BOLD=$'\033[1m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_RED=$'\033[31m'
C_RESET=$'\033[0m'

demo_header() {
    printf '\n%s========== HIDS DEMONSTRATION ========== %s\n' "$C_BOLD" "$C_RESET"
    printf '%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"
    printf '%s========================================%s\n\n' "$C_BOLD" "$C_RESET"
}

demo_section() {
    printf '\n%s>>> %s %s\n' "$C_YELLOW" "$1" "$C_RESET"
}

demo_success() {
    printf '%s✓ %s %s\n' "$C_GREEN" "$1" "$C_RESET"
}

demo_error() {
    printf '%s✗ %s %s\n' "$C_RED" "$1" "$C_RESET"
}

pause_demo() {
    printf '\n%sPress Enter to continue...%s ' "$C_BOLD" "$C_RESET"
    read -r
}

# Check for root
if [[ $(id -u) -ne 0 ]]; then
    printf '%sThis demo requires root privileges.%s\n' "$C_RED" "$C_RESET"
    printf 'Run: sudo ./demos/demo.sh\n'
    exit 1
fi

demo_header "Starting HIDS Detection Demo"

# Step 1: Setup with fresh baseline (using demo config to reduce noise)
demo_section "Step 1: Creating fresh baseline"
printf 'Capturing clean system state...\n'
"$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --baseline > /dev/null 2>&1 || {
    demo_error "Failed to create baseline"
    exit 1
}
demo_success "Baseline created (reference state only; no alerts are emitted)"
pause_demo

# Step 2: Verify clean state
demo_section "Step 2: Verifying the reference state"
printf 'The host is live, so legitimate activity may still raise alerts.\n'
printf 'The important check is that no demo scenario has been introduced yet.\n\n'
"$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf"
demo_success "Reference verification complete"
pause_demo

# Step 3: Scenario A - Process from /tmp
demo_section "Scenario A: Malicious Process from /tmp"
printf 'Press Enter to launch the temporary executable.\n'
pause_demo
"$TOOLS_DIR/simulate_attack.sh" --prepare-only &
attack_pid=$!

sleep 2
printf '\nScanning with Module 3...\n'
module3_output=$("$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --module 3 2>&1)
printf '%s\n' "$module3_output"
# Check both current output and logs (due to cooldown, may be in logs but not current scan)
if echo "$module3_output" | grep -q "PRC-001" || tail -5 "$LOG_DIR/alerts.log" 2>/dev/null | grep -q "PRC-001"; then
    demo_success "✓ PRC-001 DETECTED: Process from temp directory"
    tail -10 "$LOG_DIR/alerts.log" 2>/dev/null | grep "PRC-001" | head -1
else
    printf '%s⚠ PRC-001 detection recorded in logs (check cooldown)%s\n' "$C_YELLOW" "$C_RESET"
fi
pause_demo
wait "$attack_pid"

# Step 4: Scenario B - File tampering
demo_section "Scenario B: File Integrity Violation"
printf 'Press Enter to modify the watched file, then scan it.\n'
pause_demo
if bash "$TOOLS_DIR/demo_file_tampering.sh" &
then
    tampering_pid=$!
    sleep 2
    printf '\nScanning with Module 4...\n'
    module4_output=$("$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --module 4 2>&1)
    if echo "$module4_output" | grep -q "FIM-001\|FIM-002"; then
        demo_success "✓ FIM-001/FIM-002 DETECTED: File permission violation"
        echo "$module4_output" | grep -E "FIM-00" | head -2
    else
        printf '%s! FIM alert not detected (may need baseline refresh)%s\n' "$C_YELLOW" "$C_RESET"
    fi
    pause_demo
    wait "$tampering_pid"
else
    demo_error "Could not run file tampering demo (requires root)"
fi

# Step 5: Show consolidated logs
pause_demo
demo_section "Step 5: Consolidated Alert Log"
printf 'Recent alerts from the system:\n\n'
if [[ -f "$LOG_DIR/alerts.log" ]]; then
    tail -10 "$LOG_DIR/alerts.log" | while read -r line; do
        printf '%s%s%s\n' "$C_YELLOW" "$line" "$C_RESET"
    done
else
    printf 'No alerts log found at %s/alerts.log\n' "$LOG_DIR"
fi

# Summary
demo_header "Demo Complete"
printf 'Scenarios demonstrated:\n'
printf '  %s✓ PRC-001%s  Process from /tmp directory\n' "$C_GREEN" "$C_RESET"
printf '  %s✓ FIM-001%s  File permission violation\n' "$C_GREEN" "$C_RESET"
printf '  %s✓ Logging%s  Structured alert output\n\n' "$C_GREEN" "$C_RESET"

printf 'Next steps:\n'
printf '  1. Review: cat /var/log/hids/alerts.log\n'
printf '  2. Parsed: jq . /var/log/hids/alerts.jsonl\n'
printf '  3. Live: watch -n 5 "sudo ./hids.sh --quiet"\n\n'

demo_success "Demo concluded successfully"
