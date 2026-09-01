# HIDS Project — Presentation Readiness Checklist

Check this list before your demo to ensure everything works.

---

## Pre-Demo Checklist (Day Before)

- [ ] **Code Review**: All modules are clean and commented
  ```bash
  grep -c "^#" hids.sh libs/common.sh modules/*.sh
  # Should show reasonable comment density
  ```

- [ ] **Documentation Complete**:
  - [ ] README.md — How to use the tool
  - [ ] research.md — Why we built it this way
  - [ ] DEMO.md — Detailed walkthrough + answers
  - [ ] hids.conf — All options documented
  - [ ] IMPLEMENTATION.md — What was built

- [ ] **Test Each Scenario**:
  ```bash
  sudo ./hids.sh --baseline      # Baseline works
  sudo ./hids.sh                 # Clean scan works
  sudo ./tools/simulate_attack.sh &
  sudo ./hids.sh --module 3      # Detects PRC-001
  sudo ./tools/demo_file_tampering.sh &
  sudo ./hids.sh --module 4      # Detects FIM-001
  ```

- [ ] **Demo Script Works**:
  ```bash
  sudo ./demo.sh
  # Should complete without errors
  ```

- [ ] **Logs Are Readable**:
  ```bash
  cat /var/log/hids/alerts.log       # Human format
  jq . /var/log/hids/alerts.jsonl    # Machine format
  ```

---

## Day-Of Preparation (30 minutes before)

### 1. Fresh System State
```bash
cd ~/hids

# Remove old alerts and baseline
rm -f logs/* state/baseline/*

# Create a clean baseline
sudo ./hids.sh --baseline

# Verify no alerts
sudo ./hids.sh
# Should show: "No anomaly detected on this run."
```

### 2. Configure Presentation Environment
```bash
# Make sure you have at least 2 terminals open:
# Terminal 1: Run demos
# Terminal 2: Show logs in real-time

# Optional: Watch logs in real-time
tail -f /var/log/hids/alerts.log    # Terminal 2

# Or: Watch with color
watch -n 2 'tail -20 /var/log/hids/alerts.log'
```

### 3. Test Audio/Video
- [ ] Screen recording is working (if recording)
- [ ] Audio levels are good
- [ ] Text is large enough for audience (18pt+ in terminal)

### 4. Have Backup Logs Ready
```bash
# Save a log from a successful demo run
cp /var/log/hids/alerts.log alerts_backup.log

# If live demo fails, you can show this:
cat alerts_backup.log
```

---

## Presentation Flow (10 minutes total)

### Timeline: 0:00-0:30 — Setup & Introduction
- [ ] Explain what HIDS is (Host Intrusion Detection System)
- [ ] Show the project structure: `tree -L 2 hids/`
- [ ] Mention: "Written in pure Bash, no third-party tools"

### Timeline: 0:30-1:30 — Run Automated Demo
```bash
sudo ./demo.sh
```
- [ ] Baseline capture
- [ ] Clean scan verification
- [ ] Scenario A: Process from /tmp → PRC-001 alert
- [ ] Scenario B: File tampering → FIM-001 alert
- [ ] Scenario C: Suspicious user → USR-002 alert
- [ ] Show consolidated logs

### Timeline: 1:30-2:00 — Show Alert Details
```bash
# Show human-readable format
tail -20 /var/log/hids/alerts.log

# Show machine-readable format
jq '.' /var/log/hids/alerts.jsonl | head -30

# Explain severity levels
jq '.severity' /var/log/hids/alerts.jsonl | sort | uniq -c
```

### Timeline: 2:00-5:00 — Answer Review Questions
Use DEMO.md for detailed answers to:

1. **"Where exactly does the data come from?"**
   ```bash
   # Show sources
   cat /proc/loadavg          # System load
   last -10                   # User logins
   ps -eo pid,user,cmd        # Running processes
   ss -tlunp                  # Listening ports
   ls -la /var/log/hids/baseline/  # Baseline files
   ```

2. **"What's the difference between HIDS and NIDS?"**
   - HIDS = Host-based (what's running inside)
   - NIDS = Network-based (what's coming over the wire)

3. **"How would an attacker evade this?"**
   - Clear logs → we have cooldown + baseline
   - Modify config → we detect file changes
   - Use rootkit → we check /proc carefully

4. **"Hardest design decision?"**
   - Baseline vs. absolute thresholds
   - Solution: Use both where appropriate

5. **"How do you reduce false positives?"**
   - Whitelists (PORT_WHITELIST, PROCESS_WHITELIST)
   - Cooldown mechanism (ALERT_COOLDOWN)
   - Baselines (compare to known-good state)

6. **"What would you build next?"**
   - Trending (daily snapshots)
   - Remote logging (SIEM integration)
   - Kernel-level detection (rootkit hunting)

---

## What to Have Ready at Your Desk

### Physical/Digital Aids
- [ ] DEMO_CHEATSHEET.md (printed or on 2nd monitor)
- [ ] This checklist
- [ ] alerts_backup.log (in case live demo fails)
- [ ] Slides/notes with the 6 Q&A answers
- [ ] Code samples to show (if explaining detection logic)

### Command Quick-Reference
```bash
# If things go wrong:
sudo ./hids.sh --baseline              # Reset baseline
rm /var/log/hids/*                     # Clear logs
sudo ./hids.sh --config hids.demo.conf # Run with demo config
```

---

## Potential Issues & Fixes

| Problem | Fix | Fallback |
|---|---|---|
| Alert didn't show up | Wait 60+ seconds (cooldown) or edit ALERT_COOLDOWN=0 | Show logs: `cat /var/log/hids/alerts.log` |
| File tampering needs permission | Already running sudo? Check permissions | Explain the code; don't execute |
| User creation fails | `sudo userdel -r hids_demo_user` first | Show the detection logic in the code |
| Can't find alerts.log | Check: `sudo ls -la /var/log/hids/` | Show backup: `cat alerts_backup.log` |
| Terminal text too small | Use: `stty cols 200 rows 50` or zoom terminal | Move closer or use projector zoom |

---

## Post-Demo (Thank You Slide)

```
Key Takeaways:
  • HIDS catches what NIDS can't (internal state)
  • Baseline approach is more powerful than thresholds
  • Reducing false positives is 90% of the work
  • Defense in depth: use HIDS + NIDS + firewall + EDR

Try It Yourself:
  • https://github.com/[your-repo]/hids
  • sudo ./install.sh to set up
  • Edit hids.conf for your environment
  • Run: sudo ./hids.sh (or via cron)

Questions?
```

---

## Success Criteria

After the demo, you should be able to confirm:

- [ ] Demonstrated all 3 threat scenarios
- [ ] Showed real alerts being written to logs
- [ ] Answered all 6 review questions
- [ ] Explained design decisions with confidence
- [ ] Showed both human and machine-readable output
- [ ] Confirmed the tool runs without third-party dependencies
- [ ] Discussed what you'd improve with more time

---

## Scoring Checklist (For Evaluators)

Does the project demonstrate:

- [ ] **Completeness**: All 5 modules present and functional
- [ ] **Research**: research.md shows pre-coding investigation
- [ ] **Code Quality**: Clean, commented, follows patterns
- [ ] **Documentation**: README for end users, README for reviewers
- [ ] **Detection**: Live demo shows real threats being detected
- [ ] **Logging**: Structured, parsable alert output
- [ ] **Configuration**: Thresholds and whitelists externalized
- [ ] **Automation**: Runs on schedule (cron or systemd)
- [ ] **Design Rationale**: Team can explain key decisions
- [ ] **Going Beyond**: Extra features (baseline, multi-output, etc.)

---

## Emergency Contact List

If something breaks:

1. **Logs not showing?** → Check `/var/log/hids/` exists and is writable
2. **Module failing?** → Test individually: `sudo ./hids.sh --module 1`
3. **Baseline gone?** → Recreate: `sudo ./hids.sh --baseline`
4. **Forgot admin password?** → Use demo version: `./tools/simulate_attack.sh`
5. **Time running out?** → Skip scenario C, focus on A & B (PRC-001 + FIM-001)

---

## Final Reminder

> "The HIDS is not a finished product — it's a learning tool. You understand
> how real security tools (Wazuh, OSSEC, Auditd) work because you built
> a simpler version. That's the point."

Good luck with your presentation! 🚀
