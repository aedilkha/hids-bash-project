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

## Project layout

    hids.sh          Orchestrator (entry point)
    hids.conf        Thresholds and whitelists
    libs/common.sh   Core: alerting, dedup, baseline, colors
    modules/         One file per module
    tools/           Helper scripts (attack simulation for the demo)