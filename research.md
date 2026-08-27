# research.md — HIDS Pre-Coding Research

> Document written before the code, as required. It records what we found,
> where we found it, and which design decisions follow from it.
>
> Sections marked [TO COMPLETE]: to be finished by the responsible member.
> Each person expands their part with what they actually tested on their VM
> (command captures, observed values). A grader wants to see that YOU handled
> the system, not that you copied.

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

## 2. Users and activity  (Tom)  [TO COMPLETE]

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

[TO COMPLETE]: run last, lastb, and grep "Failed password" /var/log/auth.log on
your VM. Paste 2-3 real lines and explain the structure of a line (fields,
position of the IP and the user for awk).

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

The hardest design decision? [TO COMPLETE as a team — answer honestly, e.g.
"hard-coding thresholds vs config" or "trusting ps vs reading /proc"]

With two more weeks? [TO COMPLETE — e.g. live monitoring mode, email
notification, web dashboard, baseline signing]
