#!/bin/bash
# ==============================================================================
# Module 4 — File Integrity                                      [TO COMPLETE]
# Answers: "has anything important been touched that should not have been?"
#
# CONTRACT (do not modify):
#   - public function: run_file_integrity
#   - alert code prefix: FIM-xxx
#   - anomalies -> alert(), context -> kv()/ok()
#   - watched files list lives in hids.conf, not in the script
#
# THE BASELINE IS THE HEART OF THIS MODULE:
#   --baseline run: sha256sum each watched file, store via baseline_set().
#   later runs: recompute, compare, alert on difference.
#   Use baseline_exists() before comparing; with no baseline, don't alert —
#   print a message inviting ./hids.sh --baseline.
#
# WHERE TO FIND THE INFO:
#   sha256sum <file>              content fingerprint
#   stat -c '%A %U %G %s %Y' <f>  perms, owner, size, mtime
#   find / -perm -4000 -type f    SUID binaries (run as owner, often root)
#   find / -perm -0002 -type f    world-writable files
#   find /etc -mtime -1           config changed < 24h
#
# WATCH FIRST: /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config
#   /etc/crontab, authorized_keys, and .bashrc/.profile (persistence, module 09:
#   look for "bash -i", "/dev/tcp/", "nohup", "curl", "wget", "&$")
#
# CHECKLIST — each ticked box = one commented function
#   [ ] build_baseline           compute+store hashes (--baseline mode)
#   [ ] check_file_hashes        compare hashes to the baseline
#   [ ] check_permissions        dangerous perms on sensitive files      (DONE)
#   [ ] check_suid_binaries      new SUID vs baseline + SUID_WHITELIST
#   [ ] check_world_writable     world-writable in /etc, /bin
#   [ ] check_recent_changes     /etc files changed within 24h
#   [ ] check_startup_files      persistence patterns in .bashrc/.profile
#
# PITFALLS:
#   - some files change legitimately (resolv.conf via DHCP): INFO or exclude
#   - find / is slow: exclude /proc /sys /dev /run and network mounts
#   - the baseline itself is a target (mention in demo: evasion)
#   - /etc/shadow is root-only: handle the non-root case
# ==============================================================================

# REFERENCE EXAMPLE — keep and complete the rest.
# check_permissions: some perms are dangerous regardless of context. A
# world-readable /etc/shadow allows an offline attack on all password hashes.
# Source: stat -c '%a' (octal perms).
check_permissions() {
    local file expected actual
    local -a rules=(
        "/etc/shadow:640"
        "/etc/gshadow:640"
        "/etc/passwd:644"
        "/etc/group:644"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
    )
    for rule in "${rules[@]}"; do
        file="${rule%%:*}"
        expected="${rule##*:}"
        [[ -e "$file" ]] || continue
        actual="$(stat -c '%a' "$file" 2>/dev/null)" || continue
        if [[ "$actual" != "$expected" ]]; then
            if (( 10#$actual > 10#$expected )); then
                alert HIGH "FIM-001" "$file" "Permissions on $file too broad: $actual (expected $expected)"
            else
                kv "$file" "$actual (more restrictive than $expected)"
            fi
        fi
    done
    return 0
}

# run_file_integrity: PUBLIC ENTRY POINT.
run_file_integrity() {
    section "MODULE 4 - FILE INTEGRITY"
    check_permissions
    # TODO: add the other calls as you write them
    return 0
}