# HIDS Demo Guide

This document guides you through running the HIDS demonstration and answers
the key questions you must be able to answer during review.

---

## Running the Full Automated Demo

The simplest way to see everything at once:

```bash
sudo ./demos/demo.sh
```

This runs three detection scenarios in sequence, with explanations and cleanup.

---

## Running Individual Scenarios

If you prefer to run them one at a time to explain each step:

### Scenario A: Process from /tmp (PRC-001)

**Simulates**: An attacker copying a binary to /tmp and executing it.

```bash
# Terminal 1: Start the attack simulation
sudo ./tools/simulate_attack.sh

# Terminal 2: While it's running, scan for it
sudo ./hids.sh --module 3
```

**Expected Alert**:
```
[HIGH    ] PRC-001 Process from a temp dir: pid XXXX, user root, cmd: /tmp/hids-demo-process 30
```

**Why this matters**: Executables in /tmp or /dev/shm are a classic attacker move.
They're world-writable and often excluded from backup/integrity checks. The HIDS
flags any process running from these locations as HIGH priority.

---

### Scenario B: File Tampering (FIM-001)

**Simulates**: An attacker modifying a critical system file's permissions.

```bash
# Terminal 1: Trigger the file modification
sudo ./tools/demo_file_tampering.sh

# Terminal 2: While that runs, scan for the change
sudo ./hids.sh --module 4
```

**Expected Alert**:
```
[HIGH    ] FIM-001 Permissions on /etc/ssh/sshd_config too broad: 644 (expected at most 600)
```

**Why this matters**: File integrity is the second line of defense. SSH config
should only be readable by root (600). If an attacker makes it world-readable,
they can extract defaults, timing information, or hints about configuration.

---

### Scenario C: Suspicious User (USR-002)

**Simulates**: An attacker creating a backdoor account that looks like a system account.

```bash
# Terminal 1: Create the backdoor user
sudo ./tools/demo_suspicious_user.sh

# Terminal 2: While that runs, scan for new users
sudo ./hids.sh --module 2
```

**Expected Alert**:
```
[MEDIUM  ] USR-002 Suspicious account XXXX has low UID (XXX) but is not in sudoers
```

**Why this matters**: System accounts (UID < 1000) should not be able to log in
interactively. This account breaks that pattern and would be invisible to a
careless audit.

---

## Answers to the 6 Demo Questions

### 1. "For each piece of information your tool collects: where exactly on the system does it come from?"

| Information | Source | Command |
|---|---|---|
| CPU load, memory, disk | /proc/loadavg, /proc/meminfo, df -hP | `cat /proc/loadavg && free -m && df -hP` |
| User logins | /var/log/auth.log, /var/log/wtmp | `last`, `faillog` |
| Running processes | /proc, ps output | `ps -eo ...` |
| Listening ports | /proc/net/tcp, /proc/net/udp, netstat | `ss -tlunp` or `netstat -tulpn` |
| File hashes | Computed on first run (baseline) | `sha256sum /etc/passwd` |
| File permissions | stat output | `stat /etc/ssh/sshd_config` |
| SUID binaries | `find / -perm -4000` | `find / -perm -4000 -type f` |
| System boot time | /proc/stat | `cat /proc/stat \| grep btime` |

**Key point**: Everything comes from the kernel (/proc), the filesystem, or
standard Linux commands. No third-party tools. This means the HIDS will work
on **any** Linux system with Bash 4+.

---

### 2. "What is the difference between a HIDS and a NIDS?"

| HIDS | NIDS |
|---|---|
| **H**ost-based | **N**etwork-based |
| Runs **on** the machine being monitored | Runs on a network tap or monitor port |
| Sees **internal** system state: processes, files, users, disk | Sees **external** network traffic: packets, flows |
| Cannot be evaded by clearing logs (has baseline) | Can be evaded by encrypted traffic |
| Detects when **files change** or **processes run** | Detects when suspicious **traffic occurs** |
| Example: This tool | Examples: Suricata, Zeek |

**In practice**: A good security strategy uses BOTH. NIDS catches attack traffic
entering/leaving. HIDS catches what the attacker does after they get in.

---

### 3. "A sophisticated attacker knows your tool is running. How might they try to evade it?"

| Evasion Technique | HIDS Defense | Residual Risk |
|---|---|---|
| Delete the HIDS script | We can checksum it with Module 4 | Attacker can modify checksum baseline |
| Clear /var/log/hids/* | Logs can be sent to remote syslog/SIEM | But if network is compromised, that fails |
| Use only whitelisted ports | Whitelist is in config; attacker must compromise it | Defense: store config remotely, or sign it |
| Run from a mount with noexec | HIDS will not see it (it won't run) | But physical intrusion visible in network/hardware logs |
| Modify /proc to hide process | Kernel prevents this; /proc is read-only except by kernel | But they can use rootkit to hide from /proc |
| Corrupt file baseline | HIDS detects the corruption as an anomaly (FIM-003) | Attacker then knows they're detected |

**Key answer**: No tool is perfect. This HIDS:
- Is good for detecting common attacks (malware, misconfig, privilege escalation)
- Requires **defense in depth** (NIDS, firewall, EDR, logging to remote server)
- **Earns trust** by not flooding you with false positives (tuned thresholds, cooldown)

---

### 4. "What was the hardest design decision your team made, and why?"

**Hardest decision: Baseline vs. Absolute Thresholds**

**The problem**: Should we say "high CPU load is bad" or "high CPU load for THIS
machine at THIS time is bad"?

**Why it was hard**:
- Absolute thresholds (CPU > 2.0) are simple but noisy (false positives on gaming rigs)
- Baseline approach (compare to first run) is accurate but requires a clean system at baseline

**Decision**: We made BOTH configurable:
- Module 1 uses absolute thresholds (CPU load, memory %)
- Module 4 uses baseline (file hashes, SUID binaries, services running)

**Why this works**: System health is naturally dynamic, so we alert on extreme
values. File integrity should never change unexpectedly, so we baseline-compare.

**Lesson**: Different detection problems need different approaches.

---

### 5. "How do you distinguish a real alert from a false positive? How did you tune your tool to reduce noise?"

**Strategies we implemented**:

| Strategy | How It Works | Example |
|---|---|---|
| **Whitelisting** | Exclude known-good entries from alerts | PORT_WHITELIST="22 53 80 443" → no alert for web server |
| **Cooldown** | Don't repeat the same alert within N seconds | ALERT_COOLDOWN=3600 → same alert not repeated for 1 hour |
| **Severity levels** | Not all alerts are equal | System slightly over-memory is MEDIUM; encrypted shell is CRITICAL |
| **Baseline comparison** | Only flag deviations from known-good state | File hash changes, new SUID binaries |
| **Multiple signals** | Require multiple indicators before alerting | Flag a process only if it's BOTH from /tmp AND abnormal size |
| **Contextual thresholds** | Different standards for different scenarios | Per-core load (scales with CPU count) vs. absolute disk % |

**Tuning for YOUR environment**:
Edit `hids.conf` and adjust:
```bash
# Your server handles legitimate traffic spikes
CPU_LOAD_WARN=2.0        # Don't warn until 2x per core (was 1.0)

# You run a web server; add its port
PORT_WHITELIST="22 53 80 443 3000 5000"

# Your team legitimately logs in from home
WORK_HOURS_START=6       # Earlier start time
WORK_HOURS_END=23        # Later end time
```

**False positive example that taught us**:
- Early version: flagged every DNS query as "outbound connection to public IP"
- Solution: Only flag if it's a SHELL holding the connection (shells shouldn't talk out)

---

### 6. "If you had two more weeks, what would you build next?"

**Priority 1 — Real-world impact (1 week)**:
- **Persistence tracking**: Store daily snapshots and show trends
  - "Load average rising over time → resource leak?"
  - "New SUID binaries appearing weekly → supply chain compromise?"
- **Remote logging**: Send alerts to syslog/SIEM so attacker can't erase local logs
  - "HIDS detected FILE MODIFICATION but logs were deleted" → already in central store
- **Integration with ticketing**: Auto-create Jira/GitLab issues for CRITICAL alerts
  - Enables SOC workflow; audit trail; assignment

**Priority 2 — Detection depth (1 week)**:
- **Kernel module detection**: Hooks in to LKM syscalls (like auditd does)
  - Catches rootkits that hide in /proc
- **DNS anomaly detection**: Baseline DNS lookups, alert on NEW domains queried
  - "Process suddenly resolving to attacker's C&C" → caught
- **Behavioral process analysis**: ML model of "normal process behavior"
  - "nginx suddenly makes network calls" → suspicious
  - "bash opens 1000 files and deletes them" → wiping?

**Priority 3 — Usability (if time)**:
- **Live dashboard**: Real-time view of all metrics (like Grafana/Prometheus)
  - Watch security status live instead of interval scans
- **Configuration wizard**: Interactive setup instead of editing .conf
  - "Do you run web server? → add port 80 to whitelist automatically"
- **Incident playbook**: When critical alert fires, auto-run remediation scripts
  - "Suspicious process detected → kill it and preserve memory dump"

**What we learned**:
Building a HIDS is 10% detection logic, 90% dealing with the real world:
false positives, missing context, operational burden. Mature tools like Wazuh
spend most of their code on these problems, not on the detections themselves.

---

## Presentation Checklist

- [ ] Show a baseline capture (`sudo ./hids.sh --baseline`)
- [ ] Show a clean scan result (no alerts)
- [ ] Run Scenario A, show PRC-001 alert
- [ ] Run Scenario B, show FIM-001 alert
- [ ] Show the log format (`cat /var/log/hids/alerts.log`)
- [ ] Show JSON parsing (`jq .severity /var/log/hids/alerts.jsonl | sort | uniq -c`)
- [ ] Answer the 6 questions (see above)
- [ ] Explain a design decision with confidence

---

## Troubleshooting

**Q: "Alert not triggered"**
A: Check ALERT_COOLDOWN in hids.conf. If an alert fired recently, it won't fire
again until the cooldown expires. Modify the value or restart the tool.

**Q: "Too many alerts"**
A: This HIDS is in a development environment with many services running.
In production, you'd tune PORT_WHITELIST, PROCESS_WHITELIST, and WORK_HOURS
to match your exact environment.

**Q: "Module X runs but shows nothing"**
A: Some modules need root to see all data. Run with `sudo`.

**Q: "File tampering demo doesn't alert"**
A: Ensure you've run `sudo ./hids.sh --baseline` BEFORE the tampering. Module 4
needs a baseline to compare against.

---

## Resources

- [Wazuh Agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) — Similar tool, commercial
- [OSSEC](https://www.ossec.net/) — Open source HIDS, more features
- [Auditd](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing) — Kernel-level audit framework
- [Tripwire](https://www.tripwire.com/) — File integrity gold standard
