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

# Snapshot format version. Versioning prevents unsafe comparisons with an old
# baseline after the recorded metadata schema changes.
readonly FIM_SNAPSHOT_VERSION="2"
FIM_WATCHED_TOTAL=0
FIM_READABLE_TOTAL=0
FIM_MISSING_TOTAL=0
FIM_UNREADABLE_TOTAL=0
FIM_SUID_TOTAL=0
FIM_FIND_PARTIAL=0
FIM_ALERT_TOTAL=0

# config_words: parse a shell-style list without evaluating it as code. Quoted
# or escaped entries allow configured paths containing spaces.
config_words() {
    local input="$1" character token="" quote="" escaped=0 index
    for ((index = 0; index < ${#input}; index++)); do
        character="${input:index:1}"
        if (( escaped )); then
            token+="$character"
            escaped=0
        elif [[ "$character" == "\\" ]]; then
            escaped=1
        elif [[ -n "$quote" ]]; then
            if [[ "$character" == "$quote" ]]; then quote=""; else token+="$character"; fi
        elif [[ "$character" == "'" || "$character" == '"' ]]; then
            quote="$character"
        elif [[ "$character" =~ [[:space:]] ]]; then
            [[ -n "$token" ]] && { printf '%s\n' "$token"; token=""; }
        else
            token+="$character"
        fi
    done
    (( escaped )) && token+="\\"
    [[ -n "$token" ]] && printf '%s\n' "$token"
    [[ -z "$quote" ]]
}

# encode_field/decode_field: preserve spaces and delimiters in snapshot paths.
encode_field() { printf '%s' "$1" | base64 -w0; }
decode_field() { printf '%s' "$1" | base64 -d 2>/dev/null; }

# check_dependencies: report missing native commands and stop only this module.
check_dependencies() {
    local command missing=0
    for command in sha256sum stat find sort awk grep base64 mktemp mv readlink \
        dirname wc chmod sed cat rm; do
        if ! command -v "$command" >/dev/null 2>&1; then
            kv "Missing dependency" "$command"
            missing=1
        fi
    done
    (( missing == 0 ))
}

# file_record: record state, hash, ownership, mode, size, mtime, type and link.
file_record() {
    local file="$1" status digest="-" mode="-" uid="-" gid="-" size="-"
    local mtime="-" type="missing" target="" metadata

    if [[ -L "$file" ]]; then
        status="SYMLINK"
        target="$(readlink -- "$file" 2>/dev/null || true)"
        metadata="$(stat -c '%a|%u|%g|%s|%Y' -- "$file" 2>/dev/null || true)"
        [[ -n "$metadata" ]] && IFS='|' read -r mode uid gid size mtime <<< "$metadata"
        type="symbolic-link"
    elif [[ ! -e "$file" ]]; then
        status="MISSING"
    elif [[ ! -f "$file" ]]; then
        status="SPECIAL"
        metadata="$(stat -c '%a|%u|%g|%s|%Y|%F' -- "$file" 2>/dev/null || true)"
        IFS='|' read -r mode uid gid size mtime type <<< "$metadata"
    elif [[ ! -r "$file" ]]; then
        status="UNREADABLE"
        metadata="$(stat -c '%a|%u|%g|%s|%Y' -- "$file" 2>/dev/null || true)"
        [[ -n "$metadata" ]] && IFS='|' read -r mode uid gid size mtime <<< "$metadata"
        type="regular-file"
    elif digest="$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}')" && [[ -n "$digest" ]]; then
        status="PRESENT"
        metadata="$(stat -c '%a|%u|%g|%s|%Y' -- "$file" 2>/dev/null || true)"
        [[ -n "$metadata" ]] && IFS='|' read -r mode uid gid size mtime <<< "$metadata"
        type="regular-file"
    else
        status="UNREADABLE"
        digest="-"
        type="regular-file"
    fi

    printf 'FILE|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$status" "$digest" "$mode" "$uid" "$gid" "$size" "$mtime" \
        "$type" "$(encode_field "$target")" "$(encode_field "$file")"
}

# file_hash_snapshot: emit a deterministic, versioned record for each path.
file_hash_snapshot() {
    local file
    printf 'VERSION|%s|FILES\n' "$FIM_SNAPSHOT_VERSION"
    while IFS= read -r file; do
        [[ -n "$file" ]] && file_record "$file"
    done < <(config_words "${WATCHED_FILES:-}")
}

# find_excluding: search one filesystem and prune configured transient paths.
find_excluding() {
    local excluded first=1
    local -a args=(/ -xdev)
    if [[ -n "${FIND_EXCLUDE:-}" ]]; then
        args+=("(")
        while IFS= read -r excluded; do
            [[ -z "$excluded" ]] && continue
            (( first == 0 )) && args+=(-o)
            args+=("(" -path "$excluded" -o -path "$excluded/*" ")")
            first=0
        done < <(config_words "$FIND_EXCLUDE")
        args+=(")" -prune -o)
    fi
    find "${args[@]}" "$@"
}

# suid_snapshot: record hash, owner and mode for every SUID/SGID executable.
suid_snapshot() {
    local file digest metadata uid mode list_file error_file error_count
    list_file="$(mktemp)" || return 1
    error_file="$(mktemp)" || { rm -f "$list_file"; return 1; }
    printf 'VERSION|%s|PRIVILEGED\n' "$FIM_SNAPSHOT_VERSION"
    find_excluding -type f \( -perm -4000 -o -perm -2000 \) -print \
        > "$list_file" 2> "$error_file" || true
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        digest="$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}')"
        metadata="$(stat -c '%u|%a' -- "$file" 2>/dev/null)" || continue
        IFS='|' read -r uid mode <<< "$metadata"
        printf 'PRIV|%s|%s|%s|%s\n' "${digest:--}" "$uid" "$mode" "$(encode_field "$file")"
    done < <(sort -u "$list_file")
    error_count="$(wc -l < "$error_file")"
    (( error_count > 0 )) && printf 'COLLECTION|PARTIAL|%s\n' "$error_count"
    rm -f "$list_file" "$error_file"
}

# atomic_baseline_write: validate a snapshot, then replace one baseline by mv.
atomic_baseline_write() {
    local name="$1" source="$2" destination temporary
    destination="$BASELINE_DIR/$name"
    [[ -s "$source" ]] || return 1
    grep -Fxq "VERSION|$FIM_SNAPSHOT_VERSION|${3}" "$source" || return 1
    temporary="$(mktemp "$BASELINE_DIR/.${name}.XXXXXX")" || return 1
    if ! cat "$source" > "$temporary"; then rm -f "$temporary"; return 1; fi
    chmod 600 "$temporary" 2>/dev/null || true
    mv -f -- "$temporary" "$destination"
}

# build_baseline: collect both snapshots fully before atomically publishing them.
build_baseline() {
    local file_snapshot suid_file
    if [[ ! -d "$BASELINE_DIR" || ! -w "$BASELINE_DIR" ]]; then
        kv "Baseline" "$BASELINE_DIR is not writable; run as root"
        return 1
    fi
    file_snapshot="$(mktemp)" || { kv "Baseline" "cannot create temporary file"; return 1; }
    suid_file="$(mktemp)" || { rm -f "$file_snapshot"; kv "Baseline" "cannot create temporary file"; return 1; }

    if ! file_hash_snapshot > "$file_snapshot" || ! suid_snapshot > "$suid_file"; then
        rm -f "$file_snapshot" "$suid_file"
        kv "Baseline" "collection failed; previous baseline preserved"
        return 1
    fi
    if ! grep -q '^FILE|' "$file_snapshot"; then
        kv "Baseline" "WATCHED_FILES produced no valid path; previous baseline preserved"
        rm -f "$file_snapshot" "$suid_file"
        return 1
    fi
    if atomic_baseline_write "file_hashes" "$file_snapshot" "FILES" \
        && atomic_baseline_write "suid_binaries" "$suid_file" "PRIVILEGED"; then
        ok "Baseline: file metadata and hashes recorded atomically"
        if grep -q '^COLLECTION|PARTIAL|' "$suid_file"; then
            kv "Baseline: SUID/SGID" "recorded with partial collection coverage"
        else
            ok "Baseline: SUID/SGID metadata recorded atomically"
        fi
    else
        kv "Baseline" "validation failed; invalid snapshot was not installed"
        rm -f "$file_snapshot" "$suid_file"
        return 1
    fi
    rm -f "$file_snapshot" "$suid_file"
}

# valid_baseline: reject absent or legacy snapshots and request recapture.
valid_baseline() {
    local name="$1" kind="$2"
    if ! baseline_exists "$name"; then
        kv "$kind comparison" "no baseline yet - run ./hids.sh --baseline"
        return 1
    fi
    if [[ "$(baseline_get "$name" | sed -n '1p')" != "VERSION|$FIM_SNAPSHOT_VERSION|$kind" ]]; then
        kv "$kind comparison" "baseline format is obsolete - recapture it"
        return 1
    fi
}

# classify_file_change: explain exactly which property changed for one path.
classify_file_change() {
    local old="$1" current="$2"
    local old_status old_digest old_mode old_uid old_gid old_size old_mtime old_type old_target path_encoded
    local current_status current_digest current_mode current_uid current_gid current_size current_mtime current_type current_target
    local file
    IFS='|' read -r _ old_status old_digest old_mode old_uid old_gid old_size old_mtime old_type old_target path_encoded <<< "$old"
    IFS='|' read -r _ current_status current_digest current_mode current_uid current_gid current_size current_mtime current_type current_target _ <<< "$current"
    file="$(decode_field "$path_encoded")"
    [[ "$old" == "$current" ]] && return 1

    if [[ "$old_status" != "$current_status" ]]; then
        alert HIGH "FIM-002" "$file" "State changed for '$file': $old_status -> $current_status"
    elif [[ "$old_type" != "$current_type" || "$old_target" != "$current_target" ]]; then
        alert HIGH "FIM-006" "$file" "File type or symbolic-link target changed for '$file'"
    elif [[ "$old_uid" != "$current_uid" || "$old_gid" != "$current_gid" ]]; then
        alert HIGH "FIM-007" "$file" "Ownership changed for '$file': $old_uid:$old_gid -> $current_uid:$current_gid"
    elif [[ "$old_mode" != "$current_mode" ]]; then
        alert HIGH "FIM-008" "$file" "Mode changed for '$file': $old_mode -> $current_mode"
    elif [[ "$old_digest" != "$current_digest" ]]; then
        alert HIGH "FIM-002" "$file" "Contents of watched file '$file' differ from the baseline"
    elif [[ "$old_size" != "$current_size" || "$old_mtime" != "$current_mtime" ]]; then
        alert MEDIUM "FIM-009" "$file" "Metadata changed for '$file' without a hash change"
    fi
    ((FIM_ALERT_TOTAL++))
    return 0
}

# check_file_hashes: compare current records in both directions with baseline.
check_file_hashes() {
    local baseline current current_record old_record path_encoded file found=0
    valid_baseline "file_hashes" "FILES" || return 0
    baseline="$(baseline_get "file_hashes")"
    current="$(file_hash_snapshot)"

    while IFS= read -r current_record; do
        [[ "$current_record" == FILE\|* ]] || continue
        path_encoded="${current_record##*|}"
        old_record="$(awk -F'|' -v path="$path_encoded" '$1 == "FILE" && $11 == path {print; exit}' <<< "$baseline")"
        file="$(decode_field "$path_encoded")"
        ((FIM_WATCHED_TOTAL++))
        case "${current_record#FILE|}" in
            PRESENT\|*) ((FIM_READABLE_TOTAL++)) ;;
            MISSING\|*) ((FIM_MISSING_TOTAL++)) ;;
            UNREADABLE\|*) ((FIM_UNREADABLE_TOTAL++)); FIM_FIND_PARTIAL=1 ;;
        esac
        if [[ -z "$old_record" ]]; then
            alert HIGH "FIM-002" "$file" "Watched path '$file' was not recorded in the baseline"
            ((FIM_ALERT_TOTAL++)); found=1
        elif classify_file_change "$old_record" "$current_record"; then
            found=1
        fi
    done <<< "$current"

    while IFS= read -r old_record; do
        [[ "$old_record" == FILE\|* ]] || continue
        path_encoded="${old_record##*|}"
        if ! awk -F'|' -v path="$path_encoded" '$1 == "FILE" && $11 == path {found=1} END {exit !found}' <<< "$current"; then
            file="$(decode_field "$path_encoded")"
            alert MEDIUM "FIM-010" "$file" "Path '$file' was removed from WATCHED_FILES after the baseline"
            ((FIM_ALERT_TOTAL++)); found=1
        fi
    done <<< "$baseline"
    (( found == 0 && FIM_UNREADABLE_TOTAL == 0 )) && ok "All watched files match content and metadata baseline"
}

# check_permissions: compare configured maximum modes using stat metadata.
check_permissions() {
    local rule file expected actual expected_mode actual_mode found=0 checked=0
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        file="${rule%:*}"; expected="${rule##*:}"
        [[ -e "$file" || -L "$file" ]] || { kv "Permission check skipped" "$file is missing"; continue; }
        if ! actual="$(stat -Lc '%a' -- "$file" 2>/dev/null)"; then
            kv "Permission check partial" "cannot stat $file"; FIM_FIND_PARTIAL=1; continue
        fi
        ((checked++)); expected_mode=$((8#$expected)); actual_mode=$((8#$actual))
        if (( (actual_mode & ~expected_mode & 0777) != 0 )); then
            alert HIGH "FIM-001" "$file" "Permissions on $file too broad: $actual (expected at most $expected)"
            ((FIM_ALERT_TOTAL++)); found=1
        elif [[ "$actual" != "$expected" ]]; then
            kv "$file" "$actual (more restrictive than $expected)"
        fi
    done < <(config_words "${SENSITIVE_FILE_MODES:-}")
    (( checked == 0 )) && kv "Permission check" "no configured path could be checked"
    (( found == 0 && checked > 0 )) && ok "Sensitive-file permissions are not broader than expected"
}

# whitelisted_suid: compare a path safely with configured reviewed exceptions.
whitelisted_suid() {
    local candidate="$1" allowed
    while IFS= read -r allowed; do [[ "$candidate" == "$allowed" ]] && return 0; done \
        < <(config_words "${SUID_WHITELIST:-}")
    return 1
}

# check_suid_binaries: detect added, removed or altered SUID/SGID executables.
check_suid_binaries() {
    local baseline current record old_record path_encoded file found=0
    local digest uid mode mode_value directory directory_mode partial=0
    valid_baseline "suid_binaries" "PRIVILEGED" || return 0
    baseline="$(baseline_get "suid_binaries")"; current="$(suid_snapshot)"
    if grep -q '^COLLECTION|PARTIAL|' <<< "$current"; then
        kv "SUID/SGID scan" "collection had permission errors; result is partial"
        FIM_FIND_PARTIAL=1
        partial=1
    fi
    while IFS= read -r record; do
        [[ "$record" == PRIV\|* ]] || continue
        path_encoded="${record##*|}"; file="$(decode_field "$path_encoded")"; ((FIM_SUID_TOTAL++))
        IFS='|' read -r _ digest uid mode path_encoded <<< "$record"
        mode_value=$((8#$mode))
        if (( (mode_value & 0111) == 0 )); then
            alert HIGH "FIM-013" "$file" "SUID/SGID file has no executable bit: $file"
            ((FIM_ALERT_TOTAL++)); found=1
        fi
        directory="$(dirname -- "$file")"
        directory_mode="$(stat -c '%a' -- "$directory" 2>/dev/null || true)"
        if [[ -n "$directory_mode" ]] && (( (8#$directory_mode & 0022) != 0 )); then
            alert HIGH "FIM-014" "$file" "Privileged executable is inside a group/world-writable directory: $directory"
            ((FIM_ALERT_TOTAL++)); found=1
        fi
        old_record="$(awk -F'|' -v path="$path_encoded" '$1 == "PRIV" && $5 == path {print; exit}' <<< "$baseline")"
        if [[ -z "$old_record" ]]; then
            if whitelisted_suid "$file"; then kv "New privileged file (allowed)" "$file"
            else alert HIGH "FIM-003" "$file" "New SUID/SGID executable absent from baseline: $file"; ((FIM_ALERT_TOTAL++)); found=1
            fi
        elif [[ "$record" != "$old_record" ]]; then
            alert HIGH "FIM-011" "$file" "Hash, owner or mode changed for privileged executable: $file"
            ((FIM_ALERT_TOTAL++)); found=1
        fi
    done <<< "$current"
    if (( partial == 0 )); then
        while IFS= read -r record; do
            [[ "$record" == PRIV\|* ]] || continue
            path_encoded="${record##*|}"
            if ! awk -F'|' -v path="$path_encoded" '$1 == "PRIV" && $5 == path {found=1} END {exit !found}' <<< "$current"; then
                file="$(decode_field "$path_encoded")"
                alert MEDIUM "FIM-012" "$file" "SUID/SGID executable disappeared after baseline: $file"
                ((FIM_ALERT_TOTAL++)); found=1
            fi
        done <<< "$baseline"
    fi
    (( found == 0 && partial == 0 )) && ok "SUID/SGID executables match the baseline"
}

# sensitive_directories: derive world-writable scan roots from configured paths.
sensitive_directories() {
    local file
    while IFS= read -r file; do [[ -n "$file" ]] && dirname -- "$file"; done \
        < <(config_words "${WATCHED_FILES:-}") | sort -u
}

# check_world_writable: scan configured sensitive directories, not hard-coded ones.
check_world_writable() {
    local directory file errors found=0 checked=0 error_file
    error_file="$(mktemp)" || { kv "World-writable scan" "cannot create error file"; return 0; }
    while IFS= read -r directory; do
        [[ -d "$directory" ]] || continue; ((checked++))
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            alert HIGH "FIM-004" "$file" "World-writable file in configured sensitive directory: $file"
            ((FIM_ALERT_TOTAL++)); found=1
        done < <(find -H "$directory" -xdev -type f -perm -0002 -print 2>>"$error_file")
    done < <(sensitive_directories)
    errors="$(wc -l < "$error_file")"; rm -f "$error_file"
    (( errors > 0 )) && { kv "World-writable scan" "$errors collection error(s); result is partial"; FIM_FIND_PARTIAL=1; }
    (( checked == 0 )) && kv "World-writable scan" "no configured directory was available"
    (( found == 0 && errors == 0 && checked > 0 )) && ok "No world-writable file found in configured sensitive directories"
}

# check_recent_changes: report watched paths whose baseline mtime has changed.
check_recent_changes() {
    local baseline record path_encoded file old_mtime current_mtime count=0
    valid_baseline "file_hashes" "FILES" || return 0
    baseline="$(baseline_get "file_hashes")"
    while IFS= read -r record; do
        [[ "$record" == FILE\|* ]] || continue
        path_encoded="${record##*|}"; file="$(decode_field "$path_encoded")"
        old_mtime="$(awk -F'|' -v path="$path_encoded" '$1 == "FILE" && $11 == path {print $8; exit}' <<< "$baseline")"
        current_mtime="$(stat -c '%Y' -- "$file" 2>/dev/null || true)"
        if [[ -n "$current_mtime" && "$old_mtime" != "$current_mtime" ]]; then
            kv "Changed since baseline" "$file"; ((count++))
        fi
    done < <(file_hash_snapshot)
    kv "Baseline mtime changes" "$count watched path(s)"
}

# suspicious_startup_lines: detect high-signal execution and SSH key controls.
suspicious_startup_lines() {
    grep -En '((curl|wget).*[|][[:space:]]*(ba)?sh|(curl|wget).*(;|&&)[[:space:]]*(ba)?sh|bash[[:space:]]+-i.*(/dev/(tcp|udp)/)|(/dev/(tcp|udp)/).*bash[[:space:]]+-i|(nc|ncat|netcat)[[:space:]].*(-e|--exec)|base64[[:space:]].*-d.*([|]|;|&&)[[:space:]]*(ba)?sh|(^|[[:space:],])(command|environment|permitopen)=)' "$1" 2>/dev/null \
        | grep -Ev '^[0-9]+:[[:space:]]*#'
}

# check_startup_files: inspect configured startup files and ignore comments.
check_startup_files() {
    local file line_number content found=0 checked=0
    while IFS= read -r file; do
        case "$file" in */.bashrc|*/.profile|*/authorized_keys) ;; *) continue ;; esac
        [[ -r "$file" ]] || { kv "Startup file skipped" "$file is missing or unreadable"; continue; }
        ((checked++))
        while IFS=: read -r line_number content; do
            [[ -z "$line_number" ]] && continue
            alert HIGH "FIM-005" "$file:$line_number" "Suspicious persistence pattern in $file at line $line_number: $content"
            ((FIM_ALERT_TOTAL++)); found=1
        done < <(suspicious_startup_lines "$file")
    done < <(config_words "${WATCHED_FILES:-}")
    (( checked == 0 )) && kv "Startup-file scan" "no configured startup file was readable"
    (( found == 0 && checked > 0 )) && ok "No high-risk persistence pattern found in startup files"
}

# print_fim_summary: show actual coverage so partial scans cannot look complete.
print_fim_summary() {
    kv "Watched paths checked" "$FIM_WATCHED_TOTAL"
    kv "Readable regular files" "$FIM_READABLE_TOTAL"
    kv "Missing watched paths" "$FIM_MISSING_TOTAL"
    kv "Unreadable watched paths" "$FIM_UNREADABLE_TOTAL"
    kv "SUID/SGID checked" "$FIM_SUID_TOTAL"
    kv "Module findings" "$FIM_ALERT_TOTAL"
    kv "Collection coverage" "$([[ $FIM_FIND_PARTIAL -eq 0 ]] && printf complete || printf partial)"
}

# run_file_integrity: PUBLIC ENTRY POINT.
run_file_integrity() {
    section "MODULE 4 - FILE INTEGRITY"
    FIM_WATCHED_TOTAL=0
    FIM_READABLE_TOTAL=0
    FIM_MISSING_TOTAL=0
    FIM_UNREADABLE_TOTAL=0
    FIM_SUID_TOTAL=0
    FIM_FIND_PARTIAL=0
    FIM_ALERT_TOTAL=0
    if ! check_dependencies; then
        kv "File integrity module" "required commands are missing; analysis stopped"
        return 1
    fi
    if [[ $BASELINE_MODE -eq 1 ]]; then
        build_baseline
        return $?
    fi
    check_file_hashes
    check_permissions
    check_suid_binaries
    check_world_writable
    check_recent_changes
    check_startup_files
    print_fim_summary
    return 0
}