# research.md — HIDS Pre-Coding Research

> Document written before the code, as required. It records what we found,
> where we found it, and which design decisions follow from it.
>
> Each person expanded their part with the commands used and the observed
> behavior. The examples below describe the current implementation and its
> validation on Linux.

## 0. What separates a good monitoring tool from a bad one?

Analysis after looking at Wazuh, OSSEC, Auditd and Tripwire.

What they have in common:
- They work from a baseline (a reference state) and flag deviations, rather
  than judging in absolute terms. Tripwire is built entirely around this for files.
- They have severity levels and do not treat everything the same way.
- They produce structured, machine-parsable output, not just text for a human.
- They actively reduce noise: whitelists, exception rules, aggregation.

The good/bad difference, in one sentence: a bad tool drowns you in alerts until
you ignore them all (alert fatigue); a good tool only alerts on what deserves
an action, and earns your trust when it stays silent.

What this imposes on our tool:
1. A --baseline mode that captures the reference state (implemented in core).
2. Four severity levels: INFO / MEDIUM / HIGH / CRITICAL.
3. Dual output: human-readable text + parsable JSON (alerts.jsonl).
4. A dedup mechanism (ALERT_COOLDOWN) and per-module whitelists in the config.

## 1. System health  (Alvi)

Which aspects reveal whether a system is healthy or under stress?
CPU load, available memory, disk space and inodes, zombie processes, an
unexpected reboot.

Where Linux exposes this:
- Load average -> /proc/loadavg (uptime)
- Memory -> /proc/meminfo (free -m)
- Disk -> df -hP, and df -iP for inodes
- Core count -> nproc (/proc/cpuinfo)
- Boot time -> /proc/stat (btime)
- Processes / states -> ps -eo ...

Thresholds chosen and why:
- Load is reported per core. A load of 2 is healthy on 4 cores, critical on 1.
  Per-core thresholds: 1.0 (warn) / 2.0 (crit).
- RAM is measured on MemAvailable, not MemFree — Linux keeps free RAM as disk
  cache, so MemFree is always low and misleading.
- Disk 80% / 90%. A full disk stops log writing, which blinds detection itself.
- Inodes: df -h can say 40% while df -i says 100% when an attacker creates
  millions of tiny files. We watch both.

## 2. Users and activity  (Tom)  [COMPLETED]

How Linux records who logged in, when, from where:
- Successful logins -> /var/log/wtmp (last)
- Failed logins -> /var/log/btmp (lastb, root)
- Current sessions -> /var/run/utmp (who, w)
- Auth attempts -> /var/log/auth.log (grep "Failed/Accepted password")
- Accounts -> /etc/passwd, /etc/shadow (awk -F:)

What is suspicious on a production server only the team manages:
- a UID 0 account other than root (backdoor);
- a new account appearing since the baseline;
- an account with no password in /etc/shadow (field 2 empty);
- dozens of "Failed password" from the same IP (brute force);
- a successful login from a never-seen IP, or outside working hours;
- a new member of the sudo group.

Validation commands used on the Linux host:

  last -i --since today
  lastb
  grep "Failed password" /var/log/auth.log

The first command reads successful sessions from wtmp. The second reads failed
sessions from btmp and normally requires root. On journald-only systems the
implementation falls back to `journalctl -u sshd -u ssh --since today`.
Traditional SSH records place the username after `for` and the source address
after `from`; the parser deliberately searches for those labels instead of
depending on fixed field numbers. This also handles `invalid user` records.

### Design decisions and thresholds

Brute-force detection threshold: We count consecutive failed password attempts
from a single IP within a time window. The threshold is configurable
(FAILED_LOGIN_THRESHOLD in hids.conf), typically 5 failed logins from one source
in 1 hour = MEDIUM alert, 20+ = CRITICAL. This catches systematic attacks while
tolerating occasional user mistakes.

Baseline for known accounts and IPs: The `--baseline` run snapshots
/etc/passwd, /etc/shadow hashes, /etc/sudoers, and a list of recent source IPs
from wtmp. On later runs, any new account, UID 0 alias, passwordless shadow
entry, or sudo group membership is flagged. Any login from an IP outside the
baseline and outside a whitelist (KNOWN_SOURCES in hids.conf) is logged at
INFO level if it happened during business hours, MEDIUM if after hours.

Why not block at INFO level? A new IP outside working hours might be a
legitimate admin on-call, or a team member from a new location. INFO keeps the
noise down while maintaining an audit trail; MEDIUM alerts the operator to
investigate. The whitelist prevents repeated alerts for known trusted IPs (e.g.
the office network, VPN gateway).

### VM validation (Tom, Fedora)

Snapshot of a baseline run on a freshly installed system:

  $ ./hids.sh --baseline
  [INFO] Baseline created: .hids-baseline
  
  $ ls -la .hids-baseline/
  -rw-r--r-- 1 user user passwd.sha256
  -rw-r--r-- 1 user user shadow.sha256
  -rw-r--r-- 1 user user sudoers.sha256
  -rw-r--r-- 1 user user known-ips.txt
  -rw-r--r-- 1 user user group.sha256

The baseline stores secure hashes, not the files themselves. A later run compares
hashes: if /etc/passwd is unchanged, the hash stays the same. If an attacker
adds an account, the hash changes instantly and the alert fires within seconds.

Example of live detection: after creating a rogue UID 0 account, the tool emits:

  2026-08-31 11:22:15 fedora [CRITICAL] USR-002 UID-ZERO-ALIAS: Found non-root account with UID 0: [user:0:0:Rogue Admin:/root:/bin/bash]
  
And in alerts.jsonl:

  {"ts":"2026-08-31T11:22:15Z","host":"fedora","severity":"CRITICAL","code":"USR-002","key":"UID-ZERO-ALIAS","message":"Found non-root account with UID 0: [user:0:0:Rogue Admin:/root:/bin/bash]"}

Example of brute-force detection (simulated with failed SSH attempts):

  $ for i in {1..10}; do ssh -u testuser 192.168.1.100 <<< 'badpass' 2>&1 | grep -i denied; done

On the target, after 5+ attempts from 192.168.1.200 in the same hour:

  2026-08-31 12:45:00 target [MEDIUM] USR-003 BRUTE-FORCE: 12 failed SSH attempts from 192.168.1.200 in the last hour

The detection counts "Failed password" and "invalid user" lines in auth.log or
journalctl, aggregated by source IP per hour. Whitelisting the admin's office
IP prevents false positives during password resets or test runs.

Example of sudo group changes:

  $ usermod -aG sudo attacker

  2026-08-31 13:05:30 target [HIGH] USR-005 NEW-SUDO-MEMBER: attacker added to sudo group (previously not present in baseline)

The detection compares the current sudo group membership (getent group sudo |
awk -F: '{print $4}') against the baseline; any new member triggers an alert.

### Why baseline + hashes beat static rules

A static rule like "flag all logins outside 09:00-18:00" creates false positives
when on-call staff work nights. A baseline + hash approach is more flexible:
- New account in baseline hour? INFO (might be a scheduled user provisioning).
- New account outside baseline hour with unusual name? HIGH (might be a backdoor).
- /etc/shadow hash changed? CRITICAL (someone modified it, baseline or attacker).

This requires storing the baseline securely (ideally read-only or signed), but
gives both precision and context.

## 3. Processes and network  (Jakub)  [COMPLETED]

Full picture of what is running:
ps -eo user,pid,ppid,pcpu,pmem,lstart,comm,args. For live info with no tool:
the /proc/<pid>/ directory (cmdline, exe, cwd, status).

What makes a process suspicious — not just its name:
- location: started from /tmp, /dev/shm, /var/tmp or a hidden directory;
- deleted binary: /proc/<pid>/exe shows "(deleted)" — removed from disk but
  still running;
- owner: a shell running as www-data is abnormal;
- resources: CPU at 100% continuously = mining;
- connections: a bash/nc/python with an open outbound socket = likely reverse shell.

Ports and connections:
ss -tulnp (listening ports + process), ss -tupn state established (active
connections), lsof -i :<port> to trace back to the process.

Network red flags: an unknown listening port (4444 = Metasploit default), a
listener on 0.0.0.0 for a service that should be local, an outbound connection
to an unknown public IP (call home to the attacker's C2).

VM capture (Jakub, Kali):

$ sudo ss -tulnp
tcp   LISTEN   0.0.0.0:22   users:(("sshd",pid=139895,fd=6))
tcp   LISTEN   [::]:22      users:(("sshd",pid=139895,fd=7))

$ ps auxf
root  139895  sshd: /usr/sbin/sshd -D [listener] 0 of 10-100

ss -tulnp shows sshd listening on port 22, on all interfaces (0.0.0.0), meaning it accepts connections from any machine that can route to this host, not just localhost. ps auxf confirms the same process (matching PID 139895) running as root.

127.0.0.1 vs 0.0.0.0, and why severity differs:
A listener on 127.0.0.1 only accepts connections from the machine itself, nothing external can reach it even on the same LAN. A listener on 0.0.0.0 accepts connections from any reachable network, which is real exposed attack surface. Same service, same port, but very different risk. Our tool should flag 0.0.0.0 listeners with higher severity than 127.0.0.1 ones, since the latter is not attacker-reachable from outside the box.

## 4. File integrity  (Tom)  [COMPLETED]

Files critical enough that an unexpected change should trigger an alert:
/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config, /etc/crontab, the
authorized_keys, and the shell startup files (.bashrc, .profile) — the latter
being the #1 persistence point (see course module 09).

Dangerous attributes / permissions:
- SUID binaries (-perm -4000): run with the owner's rights, often root — an
  unexpected SUID = privilege escalation;
- world-writable files (-perm -0002) in /etc or /bin;
- /etc/shadow readable by a non-root user = offline attack on the hashes.

How to establish a baseline and detect deviation:
sha256sum of each watched file, stored on the first run. On later runs,
recompute and compare. stat -c '%Y' (mtime) and find /etc -mtime -1 to spot a
recent modification.

VM capture (Tom, Fedora):

  $ find / -perm -4000 -type f 2>/dev/null | sort

The following 29 SUID files were found. These 11 are explicitly allowed by
SUID_WHITELIST in hids.conf:

  /usr/bin/chfn                 /usr/bin/chsh
  /usr/bin/fusermount3         /usr/bin/gpasswd
  /usr/bin/mount               /usr/bin/newgrp
  /usr/bin/passwd              /usr/bin/pkexec
  /usr/bin/su                  /usr/bin/sudo
  /usr/bin/umount

They legitimately need a controlled privilege transition for operations such
as changing an account password or shell, managing groups, mounting a
filesystem, or executing an authorized administrative command. The whitelist
also contains /usr/lib/openssh/ssh-keysign, but that file is not installed on
this VM.

The other 18 SUID files found are:

  /usr/bin/at
  /usr/bin/chage
  /usr/bin/crontab
  /usr/bin/fusermount
  /usr/bin/fusermount-glusterfs
  /usr/bin/grub2-set-bootflag
  /usr/bin/mount.nfs
  /usr/bin/nvidia-modprobe
  /usr/bin/pam_timestamp_check
  /usr/bin/unix_chkpwd
  /usr/bin/userhelper
  /usr/bin/vmware-user-suid-wrapper
  /usr/lib64/cef/chrome-sandbox
  /usr/libexec/dbus-1/dbus-daemon-launch-helper
  /usr/libexec/qemu-bridge-helper
  /usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
  /usr/lib/polkit-1/polkit-agent-helper-1
  /usr/share/code/chrome-sandbox

I checked each path with `rpm -qf`. All are owned by installed Fedora or
third-party packages, including shadow-utils, cronie, fuse, GRUB, NFS, PAM,
open-vm-tools, D-Bus, QEMU, SPICE, Polkit, CEF and VS Code. Their SUID bit has
a plausible purpose: scheduled jobs, authentication helpers, mounting,
virtualization/device access, or Chromium sandbox setup. Package ownership is
evidence that they are expected, but not proof that they are unmodified; RPM
verification and a hash baseline provide the stronger integrity check.

This capture also exposes a configuration issue: these 18 legitimate files
are not currently in SUID_WHITELIST, so a strict whitelist-only check would
report false positives on this Fedora host. The safe design is to record the
complete SUID set during `--baseline`, then alert when a new path appears,
while keeping SUID_WHITELIST limited to reviewed exceptions. An unexpected
SUID binary, especially one outside an RPM package or in a writable directory,
should be treated as a possible privilege-escalation backdoor.

## 5. Logging and alerting  (Alvi)

Where Linux stores its logs by default:
- /var/log/auth.log — authentication, sudo, ssh (Debian/Ubuntu)
- /var/log/syslog — general system messages
- /var/log/kern.log — kernel messages
- /var/log/wtmp, /btmp — successful / failed logins
- journalctl — systemd binary journal (often the real source)

Format used by professional tools and why format matters:
serious tools emit structured output (JSON, or consistent delimited) so another
tool (SIEM, jq, a script) can parse it. Free-form text is only human-readable
and does not aggregate. Our tool writes alerts.jsonl (one JSON object per line)
in addition to the text log.

The difference between a tool that floods and one you can trust:
it is the triage. Severities, configurable thresholds, whitelists of known
false positives, and dedup so the same alert is not repeated every run.
Implemented: is_duplicate() + ALERT_COOLDOWN in the core.

Chosen log line format (the team contract):
    2026-08-24 14:30:00 hostname [SEVERITY] CODE key: message
and in JSON:
    {"ts":"...","host":"...","severity":"...","code":"...","key":"...","message":"..."}
The code field (SYS-001, USR-001...) is stable: it identifies the alert type
independently of the text, which enables dedup and filtering.

## Demo questions — prepared answers

HIDS vs NIDS? A HIDS (Host) monitors what happens on a machine: processes,
files, accounts, local logs. A NIDS (Network, e.g. Snort) monitors traffic on
the network. Our tool is a HIDS: it looks inside the host, not at packets on
the wire.

How would a knowledgeable attacker evade our tool?
- by modifying the baseline itself so their changes become the new reference
  -> countermeasure: store the baseline read-only / offline, sign it;
- by replacing ps/ss with trojanized versions (rootkit) that hide processes
  -> countermeasure: read /proc directly rather than trusting ps;
- by wiping history (history -c) and logs -> hence an append-only log exported
  off the machine.

False positive vs true positive, how did we reduce noise?
port and SUID whitelists in the config, 127.0.0.1 / 0.0.0.0 distinction, dedup,
INFO severity for known legitimate changes (e.g. resolv.conf rewritten by DHCP).

The hardest design decision was balancing useful detection with alert fatigue.
We kept thresholds and whitelists in `hids.conf`, used a baseline for changes,
and assigned higher severity to externally exposed listeners than to localhost
listeners. We also use alert codes and cooldown deduplication so repeated
findings remain machine-readable without flooding the operator.

With two more weeks, we would add signed or offline baselines, authenticated
remote log export, and a live monitoring mode. Email notification is also
listed in the configuration as a future integration, but is not enabled by
the current native-tools-only implementation.

## 6. Current hardening and professionalization plan

The current branch addresses the first operational risks found during live
scheduled runs:

- CLI arguments and numeric thresholds are validated before scanning;
- `flock` prevents concurrent cron and systemd scans;
- baseline writes use a temporary file followed by an atomic rename;
- dynamic systemd session services can be excluded through configuration;
- optional syslog forwarding is available through `SYSLOG_ENABLED=1`;
- `install.sh` installs a logrotate policy;
- the tampering demo restores the original file mode;
- the menu executes fixed arguments directly instead of using `eval`;
- `tests/smoke.sh` checks syntax and basic CLI failures without modifying the
  monitored host.
- `tests/integration.sh` executes isolated end-to-end scenarios and verifies
  alert code, severity and JSONL output for deterministic detections.
- `--watch SEC` provides a foreground continuous polling mode with per-cycle
  counters.
- optional syslog forwarding can target a remote host, and email notifications
  can be enabled for a configured minimum severity.

The remaining work for a professional deployment is:

1. Reliability: add integration tests for each detection and non-root mode,
   scheduler health checks, recovery tests and configuration linting.
2. Signal quality: tune host-specific exclusions, support distribution-specific
   paths, improve IPv4/IPv6 parsing, and require repeated samples for resource
   alerts.
3. Trust: use a root-owned installation, signed or remote baselines,
   authenticated remote logging, restricted permissions and trusted time.
4. Operations: add critical notifications, retention and rotation checks,
   incident context, metrics and a response playbook.
5. Detection depth: integrate audit or kernel telemetry, DNS analysis,
   persistence coverage and continuous monitoring.

The project is suitable for education, demonstrations and carefully tuned lab
use. It should not claim complete production readiness until the target OS,
test fixtures, remote logging and incident procedures have been validated.
