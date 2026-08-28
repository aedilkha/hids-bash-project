#!/bin/bash
# ==============================================================================
# hids.sh — Host Intrusion Detection System
# Orchestrator: loads config, shared library and modules, runs them in order
# and prints a summary.
#
# Usage:
#   ./hids.sh                 # full run
#   ./hids.sh --module 3      # a single module
#   ./hids.sh --baseline      # (re)capture the reference state
#   ./hids.sh --no-color      # output without colors (mail, file)
#   ./hids.sh --config /etc/hids/hids.conf
# ==============================================================================

set -uo pipefail
# Note: no "set -e". A HIDS must NEVER stop because one collection command
# failed — it must carry on with the other checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly VERSION="1.0"

# --- Global alert counters (incremented by alert() in common.sh) ---
ALERT_COUNT_CRITICAL=0
ALERT_COUNT_HIGH=0
ALERT_COUNT_MEDIUM=0
ALERT_COUNT_INFO=0

# usage: prints help and exits.
usage() {
    cat <<EOF
HIDS v$VERSION — Host Intrusion Detection System

Usage: $0 [options]

  --module N     Run only module N (1-4)
  --baseline     Capture the machine's reference state, without alerting
  --config FILE  Configuration file (default: ./hids.conf)
  --no-color     Disable colors
  --quiet        Show only alerts (no context lines)
  -h, --help     Show this help

Exit codes: 0 = nothing to report, 1 = MEDIUM/HIGH alerts, 2 = CRITICAL
EOF
    exit 0
}

# --- Argument parsing ---
CONFIG_FILE="$SCRIPT_DIR/hids.conf"
ONLY_MODULE=""
BASELINE_MODE=0
NO_COLOR=0
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)   ONLY_MODULE="$2"; shift 2 ;;
        --baseline) BASELINE_MODE=1;  shift   ;;
        --config)   CONFIG_FILE="$2"; shift 2 ;;
        --no-color) NO_COLOR=1;       shift   ;;
        --quiet)    QUIET=1;          shift   ;;
        -h|--help)  usage ;;
        *) echo "Unknown option: $1" >&2; exit 64 ;;
    esac
done

export NO_COLOR QUIET BASELINE_MODE

# --- Load the core ---
source "$SCRIPT_DIR/libs/common.sh"
load_config "$CONFIG_FILE"
setup_colors

# --- Load the modules (each defines one public function run_<name>) ---
for module in "$SCRIPT_DIR"/modules/*.sh; do
    [[ -r "$module" ]] && source "$module"
done

# print_header: report header, identical on every run.
print_header() {
    printf '%s==================================================================%s\n' "$C_BOLD" "$C_RESET"
    printf '%s  HIDS v%-5s - SECURITY REPORT%s\n' "$C_BOLD" "$VERSION" "$C_RESET"
    printf '%s==================================================================%s\n' "$C_BOLD" "$C_RESET"
    kv "Host"   "$HOSTNAME_FQDN"
    kv "Date"   "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    kv "Uptime" "$(uptime -p 2>/dev/null || echo 'n/a')"
    kv "Run by" "$(whoami)"
    [[ $BASELINE_MODE -eq 1 ]] && kv "Mode" "BASELINE CAPTURE (no alerts emitted)"
    [[ $(id -u) -ne 0 ]] && kv "Warning" "non-root: some checks will be partial"
}

# print_summary: end-of-run summary + exit code.
print_summary() {
    local total=$((ALERT_COUNT_CRITICAL + ALERT_COUNT_HIGH + ALERT_COUNT_MEDIUM))

    section "SUMMARY"
    kv "CRITICAL alerts" "$ALERT_COUNT_CRITICAL"
    kv "HIGH alerts"     "$ALERT_COUNT_HIGH"
    kv "MEDIUM alerts"   "$ALERT_COUNT_MEDIUM"
    kv "Info"            "$ALERT_COUNT_INFO"
    kv "Text log"        "$ALERT_LOG"
    kv "JSON log"        "$ALERT_JSON"

    if (( total == 0 )); then
        printf '\n  %sNo anomaly detected on this run.%s\n\n' "$C_GREEN" "$C_RESET"
        return 0
    fi

    printf '\n  %s%d anomaly(ies) to review.%s\n\n' "$C_YELLOW" "$total" "$C_RESET"
    (( ALERT_COUNT_CRITICAL > 0 )) && return 2
    return 1
}

# main: orchestration. Each module is guarded so one crash doesn't stop the rest.
main() {
    print_header

    if [[ -z "$ONLY_MODULE" || "$ONLY_MODULE" == "1" ]]; then
        run_system_health   || echo "  [!] Module 1 failed (code $?)" >&2
    fi
    if [[ -z "$ONLY_MODULE" || "$ONLY_MODULE" == "2" ]]; then
        run_user_activity   || echo "  [!] Module 2 failed (code $?)" >&2
    fi
    if [[ -z "$ONLY_MODULE" || "$ONLY_MODULE" == "3" ]]; then
        run_process_network || echo "  [!] Module 3 failed (code $?)" >&2
    fi
    if [[ -z "$ONLY_MODULE" || "$ONLY_MODULE" == "4" ]]; then
        run_file_integrity  || echo "  [!] Module 4 failed (code $?)" >&2
    fi

    print_summary
}

main
exit $?