# HIDS Demo — Quick Reference Card

For use during live demonstration. Print or keep on second monitor.

---

## 30-Second Setup

```bash
cd ~/hids
sudo ./hids.sh --baseline          # Capture clean state (~1 min)
sudo ./hids.sh                     # Verify no alerts
sudo ./demo.sh                     # Run full demo (~3 min)
```

---

## 3-Scenario Breakdown

### Scenario A: Malicious Process (2 min)

```bash
# Terminal 1
sudo ./tools/simulate_attack.sh

# Terminal 2 (while running)
sudo ./hids.sh --module 3 | grep -A1 "PRC-001"
```

**Detects**: Process running from /tmp → **[HIGH] PRC-001**

**Why it matters**: Temp directories are world-writable. Only attacker-spawned
binaries run from there.

---

### Scenario B: File Tampering (2 min)

```bash
# Terminal 1
sudo ./tools/demo_file_tampering.sh

# Terminal 2 (while running)
sudo ./hids.sh --module 4 | grep -A1 "FIM-"
```

**Detects**: Permission change on /etc/ssh/sshd_config → **[HIGH] FIM-001**

**Why it matters**: SSH config should be root-only (600). Attacker made it
world-readable to extract information.

---

### Scenario C: Backdoor User (2 min)

```bash
# Terminal 1
sudo ./tools/demo_suspicious_user.sh

# Terminal 2 (while running)
sudo ./hids.sh --module 2 | grep -A1 "USR-"
```

**Detects**: New account with low UID (system account range) → **[MEDIUM] USR-002**

**Why it matters**: Attacker created a root-like account to maintain access
without visible interactive login.

---

## Key Talking Points

| Point | Explanation | Demo It |
|---|---|---|
| **No 3rd party** | Only Bash + kernel tools (/proc, etc.) | Show: `which auditd` → not installed |
| **Baseline matters** | Catches deviations, not just absolute thresholds | Show: `/var/lib/hids/baseline/` directory |
| **Severity levels** | Not all alerts are equal; reduces noise | Show: `grep CRITICAL /var/log/hids/alerts.log` |
| **Structured logging** | Both human AND machine-readable | Show: `cat alerts.log` vs. `jq . alerts.jsonl` |
| **Runs automatically** | Via cron or systemd (not manual) | Show: `crontab -l` or `systemctl list-timers hids.timer` |

---

## Live Demo Commands (Copy-Paste Ready)

```bash
# Prepare
sudo ./hids.sh --baseline

# Full orchestrated demo (recommended)
sudo ./demo.sh

# OR run scenarios individually:

# A: Process detection
sudo ./tools/simulate_attack.sh &
sleep 2
sudo ./hids.sh --module 3 | tail -30

# B: File tampering
sudo ./tools/demo_file_tampering.sh &
sleep 2
sudo ./hids.sh --module 4 | tail -30

# C: User detection
sudo ./tools/demo_suspicious_user.sh &
sleep 2
sudo ./hids.sh --module 2 | tail -30

# Inspect logs
tail -20 /var/log/hids/alerts.log
jq '.alert_code, .severity' /var/log/hids/alerts.jsonl | head -20
```

---

## Answers to 6 Review Questions (TL;DR)

### 1. "Where does each piece of data come from?"
- CPU/memory/disk: `/proc/` and `df -hP`
- Users: `/var/log/auth.log`, `last`, `faillog`
- Processes: `ps -eo`, `/proc/[pid]/`
- Ports: `ss -tlunp` (or `/proc/net/tcp` directly)
- File integrity: `sha256sum` (baseline first run)

### 2. "HIDS vs NIDS?"
- **HIDS**: Host-based, sees internal state (processes, files, users)
- **NIDS**: Network-based, sees traffic (packets, flows)
- **Use both**: NIDS catches attack traffic; HIDS catches what they do after

### 3. "How would a sophisticated attacker evade this?"
- Delete HIDS → we checksum it (Module 4)
- Clear logs → configure remote syslog
- Modify baseline → we detect that as anomaly (FIM-003)
- **Bottom line**: Defense in depth; no single tool is perfect

### 4. "Hardest design decision?"
- Baseline vs. absolute thresholds
- **Solution**: Both! Absolute for system health (dynamic), baseline for files (static)
- **Lesson**: Different detection problems need different approaches

### 5. "How do you reduce false positives?"
- **Whitelists**: PORT_WHITELIST, PROCESS_WHITELIST, SUID_WHITELIST
- **Cooldown**: ALERT_COOLDOWN (don't spam same alert)
- **Baselines**: Compare to known-good state
- **Severity**: High/Medium/Low → tune thresholds per environment

### 6. "What's next in 2 weeks?"
- **Trending**: Daily snapshots, show rise/fall over time
- **Remote logging**: syslog to SIEM (attacker can't erase)
- **Ticketing**: Auto-create issues for CRITICAL alerts
- **Rootkit detection**: Auditd hooks, LKM syscall monitoring
- **DNS anomalies**: Baseline DNS, alert on NEW domains

---

## Environment Info to Have Ready

```bash
# Show when asked "What Linux are you testing on?"
lsb_release -a

# Show when asked "Can you run this on any system?"
bash --version

# Show when asked "What does the baseline look like?"
ls -la /var/lib/hids/baseline/
head /var/lib/hids/baseline/file_hashes

# Show when asked "How many alerts did you detect?"
wc -l /var/log/hids/alerts.log
cat /var/log/hids/alerts.log | cut -d' ' -f4 | sort | uniq -c
```

---

## Estimated Timeline

| Phase | Duration | What Happens |
|---|---|---|
| Setup | 1-2 min | Run `--baseline`, verify clean state |
| Demo A | 1 min | Trigger PRC-001, show detection |
| Demo B | 1 min | Trigger FIM-001, show detection |
| Demo C | 1 min | Trigger USR-002, show detection |
| Questions | 5 min | Answer the 6 review questions |
| **Total** | **~10 min** | Full presentation |

---

## If Demo Fails...

| Issue | Fix | Fallback |
|---|---|---|
| Alert not showing | Run `--baseline` first (no baseline = no alerts) | Show pre-recorded alerts: `cat /var/log/hids/alerts.log` |
| File tampering needs root | Already sudo'd? Check install.sh | Explain the code, don't run it |
| User creation fails | Remove old one: `sudo userdel -r hids_demo_user` | Explain the detection logic |
| Cooldown preventing alert | Edit hids.conf: `ALERT_COOLDOWN=0` | Explain cooldown design decision |
| Can't find output | Check: `ls -la /var/log/hids/` | Show logs from saved session |

---

## Handout / Next Steps for Audience

```
To use HIDS on your own system:

1. Clone / install: git clone [url] && cd hids
2. Setup: sudo ./install.sh
3. Run: sudo ./hids.sh (manually or automated)
4. Check logs: tail /var/log/hids/alerts.log
5. Customize: edit hids.conf for your environment

Documentation:
  - README.md     → How to use
  - research.md   → Why we built it this way
  - DEMO.md       → Detailed walkthrough
  - hids.conf     → All tuning options
```
