#!/bin/bash
# ==============================================================================
# menu.sh — HIDS Interactive Menu
# An interactive console menu for running HIDS modules and operations
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SCRIPT_DIR
readonly HIDS_SCRIPT="$SCRIPT_DIR/hids.sh"
readonly CONFIG_FILE="$SCRIPT_DIR/hids.conf"

# Import common library for colors and functions
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
load_config "$CONFIG_FILE"
setup_colors

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# clear_screen: clear console
clear_screen() {
    clear
}

# print_header: print menu header with ASCII art
print_header() {
    printf "${C_BOLD}${C_BLUE}"
    cat <<'HEADER'
╔═════════════════════════════════════════════════════════════════════╗
║                              ███                                    ║
║                              ██████                                 ║
║                              ██ █ ██                                ║
║                              ██  ███                                ║
║                              ███ █ ██                               ║
║                               ██ █  ███                             ║
║                           █████   █████████                         ║
║                      █████████   ███ █ █████████                    ║
║                    ████████ █  █ █ █ ██  ███████████                ║
║                 ██████       █ █ █    ██  █    ██████               ║
║               ███ █                       █      ██████             ║
║             ██           █          ███   ████        ███           ║
║            ██     ██  ██  █    █   █████   █          █ ██          ║
║           ███ ███  █        █        ██    ██    ██  ██  ███        ║
║           ████████    ██████████   █ █    █ █     █ █ ███████       ║
║           ███████████████████████████████████████████████████       ║
║            ████████████    ██ █  ██  ███ ██       ██  ██████        ║
║             ████    █                              █  ████          ║
║             ██  ██████████████ █   █ ███████████████  ███           ║
║             █        ██████           ████████        ███           ║
║             █      ██     ███   █    ██      ██        ██           ║
║             █    ██  ████  ██  ██   ██   ████  █       ██           ║
║   ███████████     ██       ██  ██   ██        ██       ██████████   ║
║ █████████████       ████████   ██    ██████████        █████████████║
║████        ██             █   ██      █               ██            ║
║            ██      ███████    ██       ███████       ███            ║
║             ██              ████   █                 ██             ║
║              ██            █████  ██                ██              ║
║               ██            ███████               ███               ║
║                ██                                ███                ║
║                 ██    ████████████              ███                 ║
║                  ██         ████████████      ███                   ║
║                   ██                       ████                     ║
║                    █████████████████████████                        ║
╠═════════════════════════════════════════════════════════════════════╣
║                          PARANO-HIDS V1                             ║
╠═════════════════════════════════════════════════════════════════════╣
║         Monitoring  ▬ Analysis  ▬ Protection  ▬ Response            ║
╚═════════════════════════════════════════════════════════════════════╝
HEADER
    printf "${C_RESET}\n"
}

# press_enter: wait for user to press enter
press_enter() {
    printf "${C_DIM}Press ENTER to continue...${C_RESET}"
    read -r
}

# print_menu: print the main menu options
print_menu() {
    cat <<EOF
${C_BOLD}SELECT AN OPTION:${C_RESET}

    ${C_GREEN}1${C_RESET}) Run Full Analysis (all modules)
    ${C_GREEN}2${C_RESET}) Run System Health Check (Module 1)
    ${C_GREEN}3${C_RESET}) Run User & Authentication Analysis (Module 2)
    ${C_GREEN}4${C_RESET}) Run Process & Network Check (Module 3)
    ${C_GREEN}5${C_RESET}) Run Advanced File Integrity Check (Module 4)
   
    ${C_BLUE}6${C_RESET}) View Latest Alerts
    ${C_BLUE}7${C_RESET}) Capture Baseline State
    ${C_BLUE}8${C_RESET}) View Configuration
    ${C_MAGENTA}10${C_RESET}) Guided Presentation Demo
   
    ${C_YELLOW}9${C_RESET}) View Help
    ${C_RED}0${C_RESET}) Exit

EOF
}

# presentation_pause: keep the presenter in control and state what to show.
presentation_pause() {
    printf '\n%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"
    printf '%sPress ENTER to continue...%s ' "$C_DIM" "$C_RESET"
    IFS= read -r || exit 0
}

# run_presentation_demo: guided, reversible demonstration for live presentation.
run_presentation_demo() {
    local output_file attack_pid tampering_pid user_pid demo_file
    demo_file="/tmp/hids-demo-sensitive.conf"
    if [[ $(id -u) -ne 0 ]]; then
        printf '%sThe guided demo requires root privileges. Run: sudo ./menu%s\n' "$C_RED" "$C_RESET"
        press_enter
        return
    fi

    clear_screen
    print_header
    printf '%sGuided HIDS presentation%s\n' "$C_BOLD" "$C_RESET"
    printf 'Each pause tells you exactly what to explain or show.\n'

    presentation_pause 'Step 1/10: We capture a clean baseline before monitoring.'
    printf 'demo baseline file\n' > "$demo_file"
    chmod 600 "$demo_file"
    "$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --baseline --no-color

    presentation_pause 'Step 2/10: We run a clean full scan and explain the four modules.'
    "$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --no-color

    presentation_pause 'Step 3/10: We show the automatic schedulers that launch HIDS every 15 minutes.'
    printf 'Short explanation: cron and systemd timer automate execution; they do not detect threats themselves.\n\n'
    printf '%sCron configuration%s\n' "$C_BOLD" "$C_RESET"
    if crontab_line="$(crontab -l 2>/dev/null | grep -F "$HIDS_SCRIPT" || true)" && [[ -n "$crontab_line" ]]; then
        printf '%s\n' "$crontab_line"
    else
        printf '%sNo user cron entry found.%s\n' "$C_YELLOW" "$C_RESET"
    fi
    printf '\n%sSystemd timer%s\n' "$C_BOLD" "$C_RESET"
    systemctl list-timers hids.timer --no-legend 2>/dev/null || printf '%sSystemd timer unavailable.%s\n' "$C_YELLOW" "$C_RESET"
    printf '\n%sService chain:%s hids.timer -> hids.service -> hids.sh\n' "$C_DIM" "$C_RESET"

    presentation_pause 'Step 4/10: Start the simulated process in /tmp, then we scan Module 3.'
    "$SCRIPT_DIR/tools/simulate_attack.sh" --prepare-only &
    attack_pid=$!
    sleep 2
    "$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --module 3
    wait "$attack_pid" 2>/dev/null || true

    presentation_pause 'Step 5/10: We change a sensitive file permission, then scan Module 4.'
    "$SCRIPT_DIR/tools/demo_file_tampering.sh" &
    tampering_pid=$!
    sleep 2
    "$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --module 4
    wait "$tampering_pid" 2>/dev/null || true

    presentation_pause 'Step 6/10: We create a low-UID interactive account, then scan Module 2.'
    "$SCRIPT_DIR/tools/demo_suspicious_user.sh" &
    user_pid=$!
    sleep 2
    "$HIDS_SCRIPT" --config "$SCRIPT_DIR/hids.demo.conf" --module 2
    wait "$user_pid" 2>/dev/null || true

    presentation_pause 'Step 7/10: We display the latest human-readable alerts.'
    view_alerts

    presentation_pause 'Step 8/10: We confirm that HIGH and CRITICAL alerts are sent by email.'
    printf 'Short explanation: the demo email threshold is HIGH, so the detected scenarios can notify Gmail.\n'
    if command -v mail >/dev/null 2>&1 && [[ -r /root/.config/msmtp/config ]]; then
        printf '%sEmail transport: configured%s\n' "$C_GREEN" "$C_RESET"
        printf 'Recipient: %s\nMinimum severity: HIGH\n' "$ALERT_EMAIL"
        printf 'Check delivery details with: sudo journalctl -t msmtp -n 10 --no-pager\n'
    else
        printf '%sEmail transport is not configured; alerts remain in local logs.%s\n' "$C_YELLOW" "$C_RESET"
    fi

    presentation_pause 'Step 9/10: We show the machine-readable JSONL alerts and their severity.'
    if [[ -r "$ALERT_JSON" ]]; then
        tail -10 "$ALERT_JSON"
    else
        printf '%sNo JSON alert log found at %s%s\n' "$C_YELLOW" "$ALERT_JSON" "$C_RESET"
    fi
    press_enter

    presentation_pause 'Step 10/10: We conclude with the exit-code model: 0 clean, 1 review, 2 critical.'
    printf '%sGuided presentation complete.%s\n' "$C_GREEN" "$C_RESET"
    printf 'Mention that this is periodic host monitoring, not automatic blocking.\n'
    rm -f "$demo_file"
    press_enter
}

# run_hids_command: execute an hids.sh command and show result
run_hids_command() {
    local description="$1"
    local output_file exit_code
    shift
    
    clear_screen
    print_header
    printf "${C_BOLD}▶ %s${C_RESET}\n" "$description"
    echo ""
    
    if [[ -x "$HIDS_SCRIPT" ]]; then
        # Preserve the complete colored module report inside the menu.
        output_file="$(mktemp)" || {
            printf "${C_RED}✗ Unable to capture command output${C_RESET}\n"
            press_enter
            return
        }
        FORCE_COLOR=1 "$HIDS_SCRIPT" "$@" 2>&1 | tee "$output_file"
        exit_code=${PIPESTATUS[0]}
        if grep -Eq '^  \[!\] Module [0-9]+ failed \(code [0-9]+\)$' "$output_file"; then
            exit_code=3
        fi
        rm -f "$output_file"
        
        echo ""
        if [[ $exit_code -eq 0 ]]; then
            printf "${C_GREEN}✓ Operation completed successfully${C_RESET}\n"
        elif [[ $exit_code -eq 1 ]]; then
            printf "${C_YELLOW}⚠ Operation completed with MEDIUM/HIGH alerts${C_RESET}\n"
        elif [[ $exit_code -eq 2 ]]; then
            printf "${C_RED}✗ Operation completed with CRITICAL alerts${C_RESET}\n"
        elif [[ $exit_code -eq 3 ]]; then
            printf "${C_RED}✗ Operation failed: one or more modules could not complete${C_RESET}\n"
        else
            printf "${C_RED}✗ Operation failed (exit code: $exit_code)${C_RESET}\n"
        fi
    else
        printf "${C_RED}✗ Error: hids.sh is not executable${C_RESET}\n"
    fi
    
    press_enter
}

# view_alerts: display latest alerts from the log
view_alerts() {
    clear_screen
    print_header
    printf "${C_BOLD}▶ Latest Alerts${C_RESET}\n"
    echo ""
    
    if [[ -f "$ALERT_LOG" ]]; then
        if [[ -s "$ALERT_LOG" ]]; then
            printf "${C_BOLD}--- Last 20 alerts ---${C_RESET}\n"
            tail -20 "$ALERT_LOG"
        else
            printf "${C_GREEN}✓ No alerts in the log${C_RESET}\n"
        fi
        printf "\n${C_DIM}Log file: $ALERT_LOG${C_RESET}\n"
    else
        printf "${C_YELLOW}⚠ No alerts log found yet${C_RESET}\n"
        printf "${C_DIM}Log file: $ALERT_LOG${C_RESET}\n"
    fi
    
    press_enter
}

# view_config: display hids.conf
view_config() {
    clear_screen
    print_header
    printf "${C_BOLD}▶ Current Configuration${C_RESET}\n"
    echo ""
    
    if [[ -f "$CONFIG_FILE" ]]; then
        printf "${C_BOLD}--- Configuration File: $CONFIG_FILE ---${C_RESET}\n"
        # Display config file with syntax highlighting for key=value pairs
        grep -v "^#" "$CONFIG_FILE" | grep -v "^$" | sed 's/^/  /'
        echo ""
        printf "${C_BOLD}--- Loaded Paths ---${C_RESET}\n"
        printf "  ${C_DIM}LOG_DIR:${C_RESET} %s\n" "$LOG_DIR"
        printf "  ${C_DIM}STATE_DIR:${C_RESET} %s\n" "$STATE_DIR"
        printf "  ${C_DIM}ALERT_LOG:${C_RESET} %s\n" "$ALERT_LOG"
        printf "  ${C_DIM}BASELINE_DIR:${C_RESET} %s\n" "$BASELINE_DIR"
    else
        printf "${C_YELLOW}⚠ Configuration file not found: $CONFIG_FILE${C_RESET}\n"
    fi
    
    press_enter
}

# show_help: display help information
show_help() {
    clear_screen
    print_header
    printf "${C_BOLD}▶ Help and Documentation${C_RESET}\n"
    echo ""
    
    cat <<EOF
${C_BOLD}HIDS Interactive Menu${C_RESET}

This interactive menu provides easy access to HIDS functionality:

${C_BOLD}Analysis Modes:${C_RESET}
  • Full Analysis:         Runs all 4 security modules
  • System Health:         Checks CPU, memory, disk usage
    • User Activity:         Detects SSH attacks, account changes, UID/GID
                                                     anomalies, shadow changes and sudo/wheel changes
  • Process & Network:     Reviews running processes and listening ports
    • File Integrity:        Verifies hashes, metadata, links, permissions,
                                                     SUID/SGID files and startup persistence

${C_BOLD}Enhanced Module Reports:${C_RESET}
    • Module 2 shows authentication source and collection coverage
    • Module 2 reports parsed SSH records, sessions, accounts and findings
    • Module 4 shows readable, missing and inaccessible watched paths
    • Module 4 reports privileged files, findings and collection coverage

${C_BOLD}Management Operations:${C_RESET}
  • View Alerts:           Shows recent security alerts
  • Capture Baseline:      Records current system state as reference
  • View Configuration:    Displays current HIDS settings

${C_BOLD}Exit Codes:${C_RESET}
  • 0: No issues detected
  • 1: MEDIUM or HIGH severity alerts found
  • 2: CRITICAL severity alerts found

${C_BOLD}Direct Usage:${C_RESET}
  ./hids.sh                 # Full run
  ./hids.sh --module 1      # Run single module (1-4)
  ./hids.sh --baseline      # Capture baseline
  ./hids.sh --no-color      # Disable colors
  ./hids.sh --help          # Show help

${C_BOLD}Alert Locations:${C_RESET}
  • Human log:             $ALERT_LOG
  • JSON log:              $ALERT_JSON
  • Baseline state:        $BASELINE_DIR/

EOF
    
    press_enter
}

# ==============================================================================
# MAIN MENU LOOP
# ==============================================================================

main_loop() {
    while true; do
        clear_screen
        print_header
        print_menu
        
        printf "${C_BOLD}Enter your choice (0-10):${C_RESET} "
        if ! IFS= read -r choice; then
            printf '\n%sNo more input. Exiting menu.%s\n' "$C_YELLOW" "$C_RESET"
            exit 0
        fi
        choice="${choice//[[:space:]]/}"
        
        case "$choice" in
            1)
                run_hids_command \
                    "Running Full Analysis..."
                ;;
            2)
                run_hids_command \
                    "Running System Health Check (Module 1)..." \
                    --module 1
                ;;
            3)
                run_hids_command \
                    "Running User & Authentication Analysis (Module 2)..." \
                    --module 2
                ;;
            4)
                run_hids_command \
                    "Running Process & Network Check (Module 3)..." \
                    --module 3
                ;;
            5)
                run_hids_command \
                    "Running Advanced File Integrity Check (Module 4)..." \
                    --module 4
                ;;
            6)
                view_alerts
                ;;
            7)
                run_hids_command \
                    "Capturing Baseline State..." \
                    --baseline
                ;;
            8)
                view_config
                ;;
            9)
                show_help
                ;;
            10)
                run_presentation_demo
                ;;
            0)
                clear_screen
                printf "${C_GREEN}✓ Goodbye!${C_RESET}\n"
                exit 0
                ;;
            *)
                printf "${C_RED}✗ Invalid choice. Press ENTER to try again.${C_RESET}\n"
                read -r
                ;;
        esac
    done
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

# Check if running as root (some features require it)
if [[ $(id -u) -ne 0 ]]; then
    clear_screen
    print_header
    printf "${C_YELLOW}⚠ Warning: Not running as root${C_RESET}\n"
    printf "Some security checks may be incomplete or unavailable.\n"
    printf "For full functionality, run: ${C_BOLD}sudo ./menu.sh${C_RESET}\n"
    press_enter
fi

main_loop
