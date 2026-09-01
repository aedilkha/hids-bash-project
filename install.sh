#!/bin/bash
# ==============================================================================
# install.sh — Set up HIDS for automatic execution
# 
# This script:
#   1. Creates log and state directories
#   2. Sets up a cron job for periodic scanning
#   3. (Optional) Creates a systemd timer as an alternative
#
# Usage: sudo ./install.sh
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HIDS_SCRIPT="$SCRIPT_DIR/hids.sh"

# Colors
C_BOLD='\033[1m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_RESET='\033[0m'

error() {
    printf '%sERROR: %s%s\n' "$C_RED" "$1" "$C_RESET" >&2
    exit 1
}

success() {
    printf '%s✓ %s%s\n' "$C_GREEN" "$1" "$C_RESET"
}

info() {
    printf '%s→%s %s\n' "$C_YELLOW" "$C_RESET" "$1"
}

header() {
    printf '\n%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"
}

# Check for root
if [[ $(id -u) -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

header "HIDS Installation Setup"

# Step 1: Create directories
info "Creating system directories for logs and state..."
mkdir -p /var/log/hids /var/lib/hids || error "Could not create directories"
chmod 755 /var/log/hids /var/lib/hids
success "Directories created"

# Step 2: Create baseline
info "Creating initial baseline (this may take a minute)..."
cd "$SCRIPT_DIR"
"$HIDS_SCRIPT" --baseline >/dev/null 2>&1 || error "Baseline creation failed"
success "Baseline captured"

# Step 3: Offer scheduling options
header "Choose your scheduling method"
printf '\n1) Cron (simple, traditional)\n'
printf '2) Systemd timer (modern, cleaner logs)\n'
printf '3) Both\n'
printf '4) Skip (manual runs only)\n\n'

read -p "Enter choice [1-4]: " choice

case "$choice" in
    1|3)
        info "Setting up cron job..."
        
        # Remove any existing HIDS cron entry
        (crontab -l 2>/dev/null | grep -v hids.sh || true) | crontab - 2>/dev/null
        
        # Add the new entry
        (crontab -l 2>/dev/null || true; echo "*/15 * * * * $HIDS_SCRIPT --no-color >> /var/log/hids/cron.log 2>&1") | crontab -
        success "Cron job added (runs every 15 minutes)"
        ;;
esac

case "$choice" in
    2|3)
        info "Setting up systemd timer..."
        
        # Create service file
        cat > /etc/systemd/system/hids.service <<EOF
[Unit]
Description=HIDS security scan
After=network.target

[Service]
Type=oneshot
ExecStart=$HIDS_SCRIPT --no-color
StandardOutput=journal
StandardError=journal
EOF
        
        # Create timer file
        cat > /etc/systemd/system/hids.timer <<EOF
[Unit]
Description=Run HIDS every 15 minutes
Requires=hids.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
        
        # Enable and start
        systemctl daemon-reload
        systemctl enable hids.timer
        systemctl start hids.timer
        
        success "Systemd timer configured and started"
        info "Check status: systemctl list-timers hids.timer"
        info "View logs: journalctl -u hids.service -f"
        ;;
esac

header "Installation Complete"

printf '\n%sNext steps:%s\n' "$C_BOLD" "$C_RESET"
printf '  1. Test the HIDS: sudo ./hids.sh\n'
printf '  2. Run the demo: sudo ./demo.sh\n'
printf '  3. Check logs: sudo tail -f /var/log/hids/alerts.log\n'
printf '  4. Parse JSON: jq . /var/log/hids/alerts.jsonl\n\n'

printf '%sDocumentation:%s\n' "$C_BOLD" "$C_RESET"
printf '  - README.md for usage and customization\n'
printf '  - research.md for technical background\n'
printf '  - hids.conf to adjust thresholds and whitelists\n\n'

success "Setup finished successfully"
