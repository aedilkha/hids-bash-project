#!/bin/bash
# ==============================================================================
# Module 4 — File Integrity                                      [COMPLETED]
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
#   [x] build_baseline           compute+store hashes (--baseline mode)
#   [x] check_file_hashes        compare hashes to the baseline
#   [x] check_permissions        dangerous perms on sensitive files
#   [x] check_suid_binaries      new SUID vs baseline + SUID_WHITELIST
#   [x] check_world_writable     world-writable in /etc, /bin
#   [x] check_recent_changes     /etc files changed within 24h
#   [x] check_startup_files      persistence patterns in .bashrc/.profile
#
# PITFALLS:
#   - some files change legitimately (resolv.conf via DHCP): INFO or exclude
#   - find / is slow: exclude /proc /sys /dev /run and network mounts
#   - the baseline itself is a target (mention in demo: evasion)
#   - /etc/shadow is root-only: handle the non-root case
# ==============================================================================

# file_hash_snapshot: emit a stable record for every configured watched path.
# Missing files are recorded so their later creation can also be detected.
file_hash_snapshot() {
    local file digest
    for file in $WATCHED_FILES; do
        if [[ ! -e "$file" ]]; then
            printf 'MISSING||%s\n' "$file"
        elif [[ ! -r "$file" ]]; then
            printf 'UNREADABLE||%s\n' "$file"
        elif digest="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')" && [[ -n "$digest" ]]; then
            printf 'PRESENT|%s|%s\n' "$digest" "$file"
        else
            printf 'UNREADABLE||%s\n' "$file"
        fi
    done
}

# find_excluding: run find on the root filesystem while pruning configured
# virtual, transient and container paths. -xdev avoids network mounts.
find_excluding() {
    local excluded first=1
    local -a args=(/ -xdev)

    if [[ -n "${FIND_EXCLUDE:-}" ]]; then
        args+=("(")
        for excluded in $FIND_EXCLUDE; do
            (( first == 0 )) && args+=(-o)
            args+=("(" -path "$excluded" -o -path "$excluded/*" ")")
            first=0
        done
        args+=(")" -prune -o)
    fi
    find "${args[@]}" "$@"
}

# suid_snapshot: list SUID executables in a deterministic order.
suid_snapshot() {
    find_excluding -type f -perm -4000 -print 2>/dev/null | sort -u
}

# build_baseline: capture watched-file hashes and the current SUID set.
build_baseline() {
    file_hash_snapshot | baseline_set "file_hashes"
    suid_snapshot | baseline_set "suid_binaries"
    ok "Baseline: watched-file hashes recorded"
    ok "Baseline: SUID binary list recorded"
}

# check_file_hashes: compare every configured path with its baseline record.
check_file_hashes() {
    local baseline current_record old_record
    local status digest file old_status old_digest found=0

    if ! baseline_exists "file_hashes"; then
        kv "File hash comparison" "no baseline yet - run ./hids.sh --baseline"
        return 0
    fi

    baseline="$(baseline_get "file_hashes")"
    while IFS= read -r current_record; do
        IFS='|' read -r status digest file <<< "$current_record"
        old_record="$(awk -F'|' -v path="$file" '$3 == path {print; exit}' <<< "$baseline")"
        if [[ -z "$old_record" ]]; then
            alert HIGH "FIM-002" "$file" "Watched path '$file' was not recorded in the baseline"
            found=1
            continue
        fi
        old_status="${old_record%%|*}"
        old_digest="${old_record#*|}"
        old_digest="${old_digest%%|*}"
        [[ "$current_record" == "$old_record" ]] && continue

        if [[ "$old_status" == "PRESENT" && "$status" == "MISSING" ]]; then
            alert HIGH "FIM-002" "$file" "Watched file '$file' was removed after the baseline"
        elif [[ "$old_status" == "MISSING" && "$status" == "PRESENT" ]]; then
            alert HIGH "FIM-002" "$file" "Watched file '$file' was created after the baseline"
        elif [[ "$old_status" == "PRESENT" && "$status" == "PRESENT" && "$digest" != "$old_digest" ]]; then
            alert HIGH "FIM-002" "$file" "Contents of watched file '$file' differ from the baseline"
        else
            alert MEDIUM "FIM-002" "$file" "Availability of watched file '$file' changed: $old_status -> $status"
        fi
        found=1
    done < <(file_hash_snapshot)

    (( found == 0 )) && ok "All watched files match the hash baseline"
}

# check_permissions: some perms are dangerous regardless of context. A
# world-readable /etc/shadow allows an offline attack on all password hashes.
# Source: stat -c '%a' (octal perms).
check_permissions() {
    local file expected actual expected_mode actual_mode found=0
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
        expected_mode=$((8#$expected))
        actual_mode=$((8#$actual))
        if (( (actual_mode & ~expected_mode & 0777) != 0 )); then
            alert HIGH "FIM-001" "$file" "Permissions on $file too broad: $actual (expected at most $expected)"
            found=1
        elif [[ "$actual" != "$expected" ]]; then
            kv "$file" "$actual (more restrictive than $expected)"
        fi
    done
    (( found == 0 )) && ok "Sensitive-file permissions are not broader than expected"
    return 0
}

# check_suid_binaries: report SUID files added after the baseline unless they
# are explicit, reviewed exceptions in SUID_WHITELIST.
check_suid_binaries() {
    local current baseline file found=0
    current="$(suid_snapshot)"

    if ! baseline_exists "suid_binaries"; then
        kv "SUID comparison" "no baseline yet - run ./hids.sh --baseline"
        return 0
    fi

    baseline="$(baseline_get "suid_binaries")"
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        grep -Fxq "$file" <<< "$baseline" && continue
        if [[ " $SUID_WHITELIST " == *" $file "* ]]; then
            kv "New SUID (whitelisted)" "$file"
        else
            alert HIGH "FIM-003" "$file" "New SUID binary absent from the baseline: $file"
            found=1
        fi
    done <<< "$current"
    (( found == 0 )) && ok "No unexpected SUID binary appeared after the baseline"
}

# check_world_writable: regular files writable by every user in sensitive
# configuration and executable directories are direct tampering opportunities.
check_world_writable() {
    local file found=0
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        alert HIGH "FIM-004" "$file" "World-writable file in a sensitive directory: $file"
        found=1
    done < <(find -H /etc /bin -xdev -type f -perm -0002 -print 2>/dev/null | sort -u)
    (( found == 0 )) && ok "No world-writable regular file found in /etc or /bin"
}

# check_recent_changes: recent /etc edits are useful investigation context but
# are not anomalous on their own. Limit detail to keep reports readable.
check_recent_changes() {
    local file count=0 shown=0
    local -a recent=()
    mapfile -t recent < <(find /etc -xdev -type f -mtime -1 -print 2>/dev/null | sort)
    count="${#recent[@]}"
    kv "Recent /etc changes" "$count file(s) modified in the last 24 hours"
    for file in "${recent[@]}"; do
        (( shown >= 10 )) && break
        kv "Recent file" "$file"
        ((shown++))
    done
    (( count > shown )) && kv "Recent file" "$((count - shown)) additional file(s) not displayed"
}

# check_startup_files: inspect configured shell and SSH startup files for common
# persistence and download/execute patterns.
check_startup_files() {
    local file line_number content found=0
    for file in $WATCHED_FILES; do
        case "$file" in
            */.bashrc|*/.profile|*/authorized_keys) ;;
            *) continue ;;
        esac
        [[ -r "$file" ]] || continue
        while IFS=: read -r line_number content; do
            [[ -z "$line_number" ]] && continue
            alert HIGH "FIM-005" "$file:$line_number" \
                "Suspicious persistence pattern in $file at line $line_number: ${content:0:100}"
            found=1
        done < <(grep -En 'bash[[:space:]]+-i|/dev/(tcp|udp)/|nohup|curl|wget|(^|[;&|[:space:]])(nc|ncat|netcat)[[:space:]]|&[[:space:]]*$' "$file" 2>/dev/null)
    done
    (( found == 0 )) && ok "No suspicious pattern found in configured startup files"
}

# run_file_integrity: PUBLIC ENTRY POINT.
run_file_integrity() {
    section "MODULE 4 - FILE INTEGRITY"
    if [[ $BASELINE_MODE -eq 1 ]]; then
        build_baseline
        return 0
    fi

    check_file_hashes
    check_permissions
    check_suid_binaries
    check_world_writable
    check_recent_changes
    check_startup_files
    return 0
}