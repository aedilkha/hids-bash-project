#!/bin/bash
# Configure a root-only msmtp profile for HIDS email notifications.
set -u

recipient="${1:-alvi.sama28469@gmail.com}"
sender="${2:-$recipient}"
config_dir="/root/.config/msmtp"
config_file="$config_dir/config"

if [[ $(id -u) -ne 0 ]]; then
    printf 'Run this script as root: sudo ./tools/setup_gmail.sh\n' >&2
    exit 1
fi
if ! command -v msmtp >/dev/null 2>&1 || ! command -v mail >/dev/null 2>&1; then
    printf 'Missing msmtp or mail. Install them first:\n' >&2
    printf '  apt-get install msmtp msmtp-mta bsd-mailx\n' >&2
    exit 1
fi

printf 'Gmail sender [%s]: ' "$sender"
IFS= read -r entered_sender
[[ -n "$entered_sender" ]] && sender="$entered_sender"
printf 'Gmail app password (input hidden): '
IFS= read -r -s app_password
printf '\n'
[[ -n "$app_password" ]] || { printf 'An app password is required.\n' >&2; exit 1; }

install -d -o root -g root -m 700 "$config_dir"
umask 077
cat > "$config_file" <<EOF
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/msmtp.log

account gmail
host smtp.gmail.com
port 587
from $sender
user $sender
password $app_password

account default : gmail
EOF
chown root:root "$config_file"
chmod 600 "$config_file"

printf 'Gmail SMTP profile installed for %s.\n' "$sender"
printf 'HIDS recipient: %s\n' "$recipient"
printf 'Test with: echo "HIDS test" | mail -s "HIDS test" "%s"\n' "$recipient"