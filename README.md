# HIDS — Host Intrusion Detection System

> [TO COMPLETE — owned by Jakub]
> End-user document, written for someone who did NOT build the tool. This
> starter fixes the structure; each [TODO] is completed as the modules land.

A Bash-based Host Intrusion Detection System. It monitors a Linux host across
five areas — system health, user activity, processes & network, file integrity,
and alerting — using only native Linux tools. No third-party software.

## Requirements

- Linux (tested on Ubuntu 22.04)
- Bash 4+
- bc (for the load-average calculation): sudo apt install bc
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
tune the tool. [TODO: Tom, Jakub concrete examples once the modules are done, e.g.
raising FAILED_LOGIN_CRIT, adding a port to PORT_WHITELIST.]

## Automatic execution

[TODO — Alvi, day 6: document the cron entry or systemd timer here.]

## Project layout

    hids.sh          Orchestrator (entry point)
    hids.conf        Thresholds and whitelists
    lib/common.sh    Core: alerting, dedup, baseline, colors
    modules/         One file per module
    tools/           Helper scripts (attack simulation for the demo)