# START HERE 🚀

Welcome to the HIDS (Host Intrusion Detection System) project. This file tells you exactly what to do to run the demonstration.

---

## TL;DR — Just Run The Demo

```bash
cd ~/hids
sudo ./demo.sh
```

That's it. Done in 3 minutes. Demonstrates all threat detection capabilities.

---

## If You Have 5 Minutes

```bash
# 1. Prepare
cd ~/hids
sudo ./hids.sh --baseline          # Capture clean state (1 min)

# 2. Run automated demo
sudo ./demo.sh                     # Shows all scenarios (2 min)

# 3. See the alerts
tail /var/log/hids/alerts.log      # 30 seconds to review
```

---

## If You Have 10 Minutes (Interactive Demo)

```bash
cd ~/hids
sudo ./hids.sh --baseline          # Prepare

# Terminal 1: Watch logs
tail -f /var/log/hids/alerts.log

# Terminal 2: Run scenarios
sudo ./tools/simulate_attack.sh &      # Scenario A: malware
sudo ./tools/demo_file_tampering.sh &  # Scenario B: tampering
sudo ./tools/demo_suspicious_user.sh & # Scenario C: backdoor

# Watch Terminal 1 — see alerts appear in real-time
# Both windows show the detection happening live
```

---

## If You Need To Answer 6 Questions

Read **DEMO.md** — it has complete answers to:
1. Where does each data point come from?
2. What's the difference between HIDS and NIDS?
3. How would an attacker evade this?
4. What was the hardest design decision?
5. How do you reduce false positives?
6. What would you build next?

**Located**: `cat DEMO.md | grep "^###"` (shows all 6)

---

## If You Need A Pre-Demo Checklist

Run this the day before:
```bash
cat READYFOR_PRESENTATION.md
```

It has:
- ✅ What to test
- ✅ Commands to run
- ✅ Troubleshooting
- ✅ Backup plans if live demo fails

---

## What This Tool Does (30 seconds)

A **HIDS** monitors one computer for signs of attack. This one checks:

1. **System Health** — Is the system under stress? (CPU, memory, disk)
2. **User Activity** — Who logged in? Are there suspicious accounts?
3. **Processes** — Are there malicious processes or unexpected ports?
4. **File Integrity** — Have critical files been modified?
5. **Alerting** — Write all findings to logs for review

**Built entirely in Bash.** No third-party tools. Runs on any Linux system.

---

## The 3 Demo Scenarios

### Scenario A: Malware Staging 🦠
**Problem**: Attacker copies a binary to `/tmp` and runs it  
**Detection**: PRC-001 alert → "Process from /tmp detected"  
**Demo**: `sudo ./tools/simulate_attack.sh`

### Scenario B: Config Tampering 🔧
**Problem**: Attacker makes SSH config world-readable to extract info  
**Detection**: FIM-001 alert → "File permissions too broad"  
**Demo**: `sudo ./tools/demo_file_tampering.sh`

### Scenario C: Backdoor Account 🚪
**Problem**: Attacker creates root-like account to maintain access  
**Detection**: USR-002 alert → "Suspicious account with low UID"  
**Demo**: `sudo ./tools/demo_suspicious_user.sh`

---

## Project Files at a Glance

```
hids/
├── demo.sh                ← Run this to see everything
├── hids.sh                ← The actual HIDS tool
├── README.md              ← How to use & customize
├── DEMO.md                ← Demo walkthrough & Q&A answers
├── READYFOR_PRESENTATION.md ← Pre-demo checklist
├── FILE_MANIFEST.txt      ← What each file does
├── modules/               ← 4 detection modules
├── tools/                 ← Demo scripts
└── logs/                  ← Alert output (alerts.log, alerts.jsonl)
```

**For more detail**: Read `FILE_MANIFEST.txt`

---

## Quick Troubleshooting

| Problem | Fix |
|---|---|
| "Permission denied" | Add `sudo` before commands |
| "No alerts detected" | Run `sudo ./hids.sh --baseline` first |
| "Alert doesn't repeat" | Wait 60 seconds (cooldown) or edit hids.conf |
| "Text too small" | Zoom terminal or use `stty cols 200 rows 50` |

**For more help**: See `READYFOR_PRESENTATION.md` → "Potential Issues & Fixes"

---

## Next Steps

### To Run Demo
```
sudo ./demo.sh
```

### To Use in Production
```
sudo ./install.sh
```

### To Learn More
```
cat README.md           # How to use
cat DEMO.md             # Demo details
cat research.md         # Why we built it this way
cat IMPLEMENTATION.md   # What was built
```

---

## Success Looks Like

After running `sudo ./demo.sh`, you'll see:

```
✓ Baseline created
✓ Clean system confirmed - no alerts
✓ PRC-001 DETECTED: Process from temp directory
✓ FIM-001 DETECTED: File permission violation
✓ Demo concluded successfully
```

And in the logs:
```
[HIGH] PRC-001 Process from a temp dir: pid XXXX
[HIGH] FIM-001 Permissions on /etc/ssh/sshd_config too broad
```

---

## You're Ready To Start

**Run the demo now:**
```bash
cd ~/hids && sudo ./demo.sh
```

**Questions after the demo?** Check DEMO.md (the 6 Q&A answers are there)

**Help with anything?** → `READYFOR_PRESENTATION.md`

Good luck! 🚀
