# HIDS — Host Intrusion Detection System

A Bash-based Host Intrusion Detection System. It monitors a Linux host across
five areas — system health, user activity, processes & network, file integrity,
and alerting — using only native Linux tools. No third-party software.

## Requirements

- Linux (tested on Ubuntu 22.04)
- Bash 4+
- root recommended (some checks are partial without it)

## Quick start

    # First run: capture the reference state of the machine
    sudo ./hids.sh --baseline

    # Normal run: full scan of all five modules
    sudo ./hids.sh

    # Run a single module (1-4)
    sudo ./hids.sh --module 3

    # Output without colors (for a file or an email)
    sudo ./hids.sh --no-color

The repository also includes a safe demonstration that starts a temporary copy
of `sleep`, detects its executable under `/tmp`, and removes it automatically:

    ./tools/simulate_attack.sh

## What each module checks

- Module 1 — System health: Is this system healthy right now?
- Module 2 — User activity: Who has been active, and does anything look off?
- Module 3 — Process & network: Is anything running or listening that should not be?
- Module 4 — File integrity: Has anything important been modified?
- Module 5 — Alerting: (built into the core) how findings are logged and surfaced.

## Reading the output

Every finding has a severity:
- INFO — context, not a problem
- MEDIUM — worth a look
- HIGH — likely malicious, investigate
- CRITICAL — act now

Each alert also carries a stable code (e.g. SYS-001, USR-001) that identifies
the type of finding regardless of the wording.

## Where alerts are stored

- logs/alerts.log — human-readable, timestamped
- logs/alerts.jsonl — one JSON object per line, for jq or a SIEM

(When run as root these go to /var/log/hids/ instead.)

## Customizing thresholds

All thresholds and whitelists live in hids.conf. You never edit the scripts to
tune the tool.

Examples:

    # Your server gets legitimate brute-force noise from bots on the internet.
    # Raise the threshold so only real attack volumes trigger an alert.
    FAILED_LOGIN_CRIT=100

    # You run a Minecraft server on port 25565. Add it so it stops being
    # flagged as an unexpected listening port.
    PORT_WHITELIST="22 53 80 443 631 25565"

    # A backup script legitimately runs rsync from a temp directory.
    # Add its process name so it's not flagged as suspicious.
    PROCESS_WHITELIST="rsync tar gzip apt dpkg unattended-upgrade my-backup-tool"

    # Your team works evenings; extend the "normal" login window.
    WORK_HOURS_START=6
    WORK_HOURS_END=23

## Automatic execution

The tool is meant to run on a schedule, not by hand every time. Two options:

### Option A — cron (simplest)

    sudo crontab -e

Add this line to run a full scan every 15 minutes, writing output to a log
instead of the terminal:

    */15 * * * * /path/to/hids.sh --no-color >> /var/log/hids/cron_run.log 2>&1

### Option B — systemd timer (cleaner logs, easier to inspect with journalctl)

Create `/etc/systemd/system/hids.service`:

    [Unit]
    Description=HIDS security scan

    [Service]
    Type=oneshot
    ExecStart=/path/to/hids.sh --no-color

Create `/etc/systemd/system/hids.timer`:

    [Unit]
    Description=Run HIDS every 15 minutes

    [Timer]
    OnBootSec=2min
    OnUnitActiveSec=15min

    [Install]
    WantedBy=timers.target

Then enable it:

    sudo systemctl enable --now hids.timer
    sudo systemctl list-timers hids.timer   # confirm it's scheduled
    journalctl -u hids.service              # see past runs

## Live demo: triggering detections

To see the HIDS in action, use the automated demo:

    sudo ./demos/demo.sh

This orchestrates three threat scenarios sequentially:
- **PRC-001**: Detects a process executable copied into /tmp
- **FIM-001**: Detects a permission change on a watched file
- **USR-002**: Detects a suspicious user account creation (optional)

Each scenario runs, the HIDS scans, you see the alert, and cleanup happens
automatically. The file-tampering scenario uses a temporary demo file rather
than changing `/etc/ssh/sshd_config`, so it is repeatable across distributions.

### Running individual scenarios

If you want to test one threat at a time:

    # Scenario A: malicious process
    sudo ./tools/simulate_attack.sh

    # Scenario B: file tampering
    sudo ./tools/demo_file_tampering.sh

    # Scenario C: suspicious user
    sudo ./tools/demo_suspicious_user.sh

Then run the corresponding module scan:

    sudo ./hids.sh --module 3    # See PRC alerts
    sudo ./hids.sh --module 4    # See FIM alerts
    sudo ./hids.sh --module 2    # See USR alerts

## Alert log integrity

Human-readable alerts are stored in `/var/log/hids/alerts.log` and structured
alerts in `alerts.jsonl`. Each emitted alert is also added to the chained
SHA-256 file `alerts.sha256`. Verify the chain with:

    sudo ./tools/verify_logs.sh

The hash chain detects changes to records, but it is not protection against an
attacker with root access who can rewrite both the logs and the chain.

## Troubleshooting the demo

**"No alerts detected"**
- Ensure you've run `sudo ./hids.sh --baseline` first to establish the reference state.
- Some alerts may be cached by ALERT_COOLDOWN. Wait or change that value in hids.conf.

**"Permission denied" on file tampering**
- demo_file_tampering.sh modifies system files and must run as root.

**"User already exists"**
- Remove any leftover demo user: `sudo userdel -r hids_demo_user`

## Project layout

    hids.sh          Orchestrator (entry point)
    hids.conf        Thresholds and whitelists
    libs/common.sh   Core: alerting, dedup, baseline, colors
    modules/         One file per module
    tools/           Helper scripts (attack simulation for the demo)
    demos/           Interactive demo launchers
    docs/            User, implementation and presentation documentation

## Operational hardening

The current implementation validates configuration before scanning, writes
baseline files atomically, and uses `flock` to prevent overlapping scans when
cron and systemd are both enabled. Syslog forwarding is optional with
`SYSLOG_ENABLED=1`, and `etc/logrotate.d/hids` provides local log rotation.

Run the non-destructive smoke test with:

    ./tests/smoke.sh

Run the isolated integration suite with:

    ./tests/integration.sh

This suite uses temporary logs, state, authentication fixtures, user database
fixtures, watched files and a temporary process. It verifies the real command
path from `hids.sh` through the modules and `alert()`, including JSONL output
and severity. It requires no root privileges and cleans up on exit. The suite
covers deterministic alert scenarios; host-dependent checks such as disk
capacity, reboot state, kernel telemetry and live service ownership still need
environment-specific tests.

For a foreground continuous monitor, use a positive interval in seconds:

    sudo ./hids.sh --watch 60 --no-color

Optional integrations can be enabled in `hids.conf` with
`SYSLOG_ENABLED=1`. Set `SYSLOG_SERVER` and `SYSLOG_PORT` for a remote syslog
receiver, or set `ALERT_EMAIL` when a local `mail` command is configured. These
integrations require the corresponding system service and are disabled by
default.

For Gmail notifications, install `msmtp`, `msmtp-mta` and `bsd-mailx`, then run
the setup helper. It asks for the Gmail app password only in the terminal and
stores it in `/root/.config/msmtp/config` with mode 600; it is never committed:

    sudo apt-get install msmtp msmtp-mta bsd-mailx
    sudo ./tools/setup_gmail.sh alvi.sama28469@gmail.com
    echo "HIDS test" | mail -s "HIDS test" alvi.sama28469@gmail.com

Use one scheduler in normal operation. Systemd timer is recommended because
its status and output are easy to inspect:

    systemctl list-timers hids.timer
    journalctl -u hids.service

## Production-readiness status

This is a hardened educational prototype, not a replacement for an EDR,
auditd or Wazuh. Before production use, review the target distribution and
threat model, install under a root-owned directory such as `/opt/hids`, tune
all whitelists, and test every detection scenario.

The baseline and local logs remain modifiable by root. Local hash chaining is
tamper-evident, not tamper-proof. A production deployment should sign or store
the baseline elsewhere, forward alerts to a remote syslog or SIEM, configure
critical notifications, and define an incident response procedure.