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
   ${C_GREEN}3${C_RESET}) Run User Activity Check (Module 2)
   ${C_GREEN}4${C_RESET}) Run Process & Network Check (Module 3)
   ${C_GREEN}5${C_RESET}) Run File Integrity Check (Module 4)
   
   ${C_BLUE}6${C_RESET}) View Latest Alerts
   ${C_BLUE}7${C_RESET}) Capture Baseline State
   ${C_BLUE}8${C_RESET}) View Configuration
   
   ${C_YELLOW}9${C_RESET}) View Help
   ${C_RED}0${C_RESET}) Exit

EOF
}

# run_hids_command: execute an hids.sh command and show result
run_hids_command() {
    local cmd="$1"
    local description="$2"
    
    clear_screen
    print_header
    printf "${C_BOLD}▶ %s${C_RESET}\n" "$description"
    echo ""
    
    if [[ -x "$HIDS_SCRIPT" ]]; then
        # Execute the command
        eval "$cmd"
        local exit_code=$?
        
        echo ""
        if [[ $exit_code -eq 0 ]]; then
            printf "${C_GREEN}✓ Operation completed successfully${C_RESET}\n"
        elif [[ $exit_code -eq 1 ]]; then
            printf "${C_YELLOW}⚠ Operation completed with MEDIUM/HIGH alerts${C_RESET}\n"
        elif [[ $exit_code -eq 2 ]]; then
            printf "${C_RED}✗ Operation completed with CRITICAL alerts${C_RESET}\n"
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
  • User Activity:         Monitors login attempts and user sessions
  • Process & Network:     Reviews running processes and listening ports
  • File Integrity:        Verifies critical system files

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
        
        printf "${C_BOLD}Enter your choice (0-9):${C_RESET} "
        read -r choice
        
        case "$choice" in
            1)
                run_hids_command \
                    "\"$HIDS_SCRIPT\"" \
                    "Running Full Analysis..."
                ;;
            2)
                run_hids_command \
                    "\"$HIDS_SCRIPT\" --module 1" \
                    "Running System Health Check (Module 1)..."
                ;;
            3)
                run_hids_command \
                    "\"$HIDS_SCRIPT\" --module 2" \
                    "Running User Activity Check (Module 2)..."
                ;;
            4)
                run_hids_command \
                    "\"$HIDS_SCRIPT\" --module 3" \
                    "Running Process & Network Check (Module 3)..."
                ;;
            5)
                run_hids_command \
                    "\"$HIDS_SCRIPT\" --module 4" \
                    "Running File Integrity Check (Module 4)..."
                ;;
            6)
                view_alerts
                ;;
            7)
                run_hids_command \
                    "\"$HIDS_SCRIPT\" --baseline" \
                    "Capturing Baseline State..."
                ;;
            8)
                view_config
                ;;
            9)
                show_help
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
