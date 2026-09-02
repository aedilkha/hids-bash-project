#!/bin/bash
# ==============================================================================
# Module 2 — User Activity                                       [COMPLETED]
# Answers: "who has been active on this system, and does anything look off?"
#
# CONTRACT (do not modify):
#   - public function: run_user_activity
#   - alert code prefix: USR-xxx
#   - anomalies -> alert(), context -> kv()/ok(), no direct log writes
#   - no hard-coded thresholds: add them to hids.conf
#
# WHERE TO FIND THE INFO:
#   /var/log/auth.log   "Failed password", "Accepted password", "Invalid user"
#   /var/log/wtmp       successful logins -> `last`
#   /var/log/btmp       failed logins     -> `lastb` (root)
#   /var/run/utmp       current sessions  -> `who`, `w`
#   /etc/passwd         accounts (field 3 = UID; 0 = root)
#   /etc/shadow         field 2 empty = no password
#   /etc/group          sudo / wheel / docker membership
#
# CHECKLIST
#   [x] failed and successful SSH logins (auth.log or journald)
#   [x] current sessions and recent wtmp history
#   [x] UID 0, new accounts and empty passwords
#   [x] new sudo/wheel members
#   [x] new source IPs and SSH logins outside working hours
#
# PITFALLS:
#   - auth.log may be absent on journald-only systems -> fallback journalctl -u ssh
#   - lastb needs root: handle non-root (kv "not available")
#   - `last` includes reboot / "wtmp begins": filter them out
#   - first run has no baseline: use baseline_exists() before comparing
# ==============================================================================

# Internal state and versioned baseline schema.
readonly USER_BASELINE_VERSION="2"
USER_AUTH_EVENTS=""
USER_AUTH_SOURCE="unavailable"
USER_AUTH_STATUS="unavailable"
USER_AUTH_PARSED=0
USER_AUTH_UNPARSED=0
USER_SESSION_TOTAL=0
USER_ACCOUNT_TOTAL=0
USER_PRIVILEGED_TOTAL=0
USER_FINDING_TOTAL=0
USER_COVERAGE_PARTIAL=0

# user_check_dependencies: verify native commands required by this module.
user_check_dependencies() {
    local command missing=0
    for command in awk grep sed sort uniq wc mktemp mv chmod cat rm date cut tr comm getent; do
        if ! command -v "$command" >/dev/null 2>&1; then
            kv "Missing dependency" "$command"
            missing=1
        fi
    done
    (( missing == 0 ))
}

# user_validate_config: reject absent or malformed configurable thresholds.
user_validate_config() {
    local name value invalid=0
    for name in FAILED_LOGIN_WARN FAILED_LOGIN_CRIT WORK_HOURS_START WORK_HOURS_END; do
        value="${!name:-}"
        if [[ ! "$value" =~ ^[0-9]+$ ]]; then
            kv "Invalid configuration" "$name must be a non-negative integer"
            invalid=1
        fi
    done
    if (( invalid == 0 )) && (( FAILED_LOGIN_WARN > FAILED_LOGIN_CRIT )); then
        kv "Invalid configuration" "FAILED_LOGIN_WARN exceeds FAILED_LOGIN_CRIT"
        invalid=1
    fi
    if (( invalid == 0 )) && (( WORK_HOURS_START > 23 || WORK_HOURS_END > 24 )); then
        kv "Invalid configuration" "working hours must be between 0 and 24"
        invalid=1
    fi
    (( invalid == 0 ))
}

# user_atomic_baseline: publish a validated snapshot with an atomic rename.
user_atomic_baseline() {
    local name="$1" kind="$2" content="$3" temporary
    if [[ ! -d "$BASELINE_DIR" || ! -w "$BASELINE_DIR" ]]; then
        kv "Baseline" "$BASELINE_DIR is not writable; run as root"
        return 1
    fi
    [[ "$content" == "VERSION|$USER_BASELINE_VERSION|$kind"* ]] || return 1
    temporary="$(mktemp "$BASELINE_DIR/.${name}.XXXXXX")" || return 1
    if ! printf '%s\n' "$content" > "$temporary"; then
        rm -f "$temporary"
        return 1
    fi
    chmod 600 "$temporary" 2>/dev/null || true
    mv -f -- "$temporary" "$BASELINE_DIR/$name"
}

# user_valid_baseline: require the current schema before comparing snapshots.
user_valid_baseline() {
    local name="$1" kind="$2" first
    if ! baseline_exists "$name"; then
        kv "$kind comparison" "baseline not captured"
        return 1
    fi
    first="$(baseline_get "$name" | sed -n '1p')"
    if [[ "$first" != "VERSION|$USER_BASELINE_VERSION|$kind" ]]; then
        kv "$kind comparison" "baseline format is obsolete - recapture it"
        return 1
    fi
}

# user_load_auth_events: collect SSH records and expose collection failures.
user_load_auth_events() {
    local auth_log="${AUTH_LOG:-}" today_prefix output error_file status
    USER_AUTH_EVENTS=""
    USER_AUTH_SOURCE="unavailable"
    USER_AUTH_STATUS="unavailable"
    error_file="$(mktemp)" || { kv "Authentication source" "cannot create temporary file"; return 1; }

    if [[ -n "$auth_log" && -r "$auth_log" ]]; then
        USER_AUTH_SOURCE="$auth_log"
        if [[ $BASELINE_MODE -eq 1 ]]; then
            output="$(cat -- "$auth_log" 2>"$error_file")"; status=$?
        else
            today_prefix="$(LC_ALL=C date '+%b %e')"
            output="$(LC_ALL=C awk -v day="$today_prefix" \
                'substr($0, 1, length(day)) == day' "$auth_log" 2>"$error_file")"; status=$?
        fi
    elif command -v journalctl >/dev/null 2>&1; then
        USER_AUTH_SOURCE="systemd journal (sshd/ssh)"
        if [[ $BASELINE_MODE -eq 1 ]]; then
            output="$(journalctl -q --no-pager -o short-iso -u sshd -u ssh 2>"$error_file")"; status=$?
        else
            output="$(journalctl -q --no-pager -o short-iso -u sshd -u ssh --since today 2>"$error_file")"; status=$?
        fi
    else
        status=127
    fi

    if (( status == 0 )); then
        USER_AUTH_EVENTS="$output"
        USER_AUTH_STATUS="$([[ -n "$output" ]] && printf readable || printf empty)"
    else
        USER_AUTH_STATUS="error"
        USER_COVERAGE_PARTIAL=1
        kv "Authentication error" "$(tr '\n' ' ' < "$error_file")"
    fi
    rm -f "$error_file"
    kv "Authentication source" "$USER_AUTH_SOURCE ($USER_AUTH_STATUS)"
}

# user_ip_from_line: extract and validate IPv4 or IPv6 after an SSH "from".
user_ip_from_line() {
    local candidate
    candidate="$(awk '{
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^rhost=/) {sub(/^rhost=/, "", $i); print $i; exit}
            if ($i == "by" && $(i+1) ~ /^(invalid|authenticating)$/ && $(i+2) == "user") {
                print $(i+4); exit
            }
            if ($i != "from") continue
            if ($(i+1) ~ /^(invalid|authenticating)$/ && $(i+2) == "user") print $(i+4)
            else print $(i+1)
            exit
        }
    }' <<< "$1")"
    if [[ "$candidate" == *:* && "$candidate" =~ ^[0-9A-Fa-f:]+$ ]]; then
        printf '%s\n' "$candidate"
    elif awk -F. 'NF == 4 {for (i=1;i<=4;i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1; exit 0} {exit 1}' <<< "$candidate"; then
        printf '%s\n' "$candidate"
    fi
}

# user_name_from_line: extract the target account from common OpenSSH forms.
user_name_from_line() {
    awk '{
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^user=/) {sub(/^user=/, "", $i); print $i; exit}
            if ($i == "Invalid" && $(i + 1) == "user") {print $(i + 2); exit}
            if (($i == "for" || $i == "from" || $i == "by") && \
                $(i + 1) ~ /^(invalid|authenticating)$/ && $(i + 2) == "user") {
                print $(i + 3); exit
            }
            if ($i == "for") {print $(i + 1); exit}
        }
    }' <<< "$1"
}

# user_hour_from_line: parse journald ISO or traditional syslog timestamps.
user_hour_from_line() {
    local line="$1"
    if [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T([0-9]{2}): ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[A-Z][a-z]{2}[[:space:]]+[0-9]+[[:space:]]+([0-9]{2}): ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

# user_auth_records: normalize unique suspicious and successful SSH log lines.
user_auth_records() {
    local line ip user method hour kind
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        kind=""
        if [[ "$line" =~ Accepted[[:space:]]+(password|publickey|keyboard-interactive) ]]; then
            kind="SUCCESS"; method="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ Failed[[:space:]]+password|Invalid[[:space:]]+user|authentication[[:space:]]+failure|maximum[[:space:]]+authentication[[:space:]]+attempts[[:space:]]+exceeded|Connection[[:space:]]+closed[[:space:]]+by[[:space:]]+(invalid|authenticating)[[:space:]]+user|Disconnected[[:space:]]+from[[:space:]]+(invalid|authenticating)[[:space:]]+user ]]; then
            kind="FAIL"; method="event"
        else
            continue
        fi
        ip="$(user_ip_from_line "$line")"; user="$(user_name_from_line "$line")"
        if [[ -z "$ip" || -z "$user" ]]; then
            printf 'UNPARSED||||\n'
            continue
        fi
        hour="$(user_hour_from_line "$line")"
        printf '%s|%s|%s|%s|%s\n' "$kind" "$user" "$ip" "$method" "$hour"
    done <<< "$USER_AUTH_EVENTS"
}

# user_alert_failed_logins: detect per-IP, global and distributed SSH attacks.
user_alert_failed_logins() {
    local records="$1" count ip user distinct severity total
    total="$(awk -F'|' '$1 == "FAIL" {count++} END {print count + 0}' <<< "$records")"
    kv "Suspicious SSH events" "$total"
    (( total == 0 )) && { ok "No suspicious SSH authentication event"; return 0; }

    while read -r count ip; do
        [[ -z "${ip:-}" ]] && continue; severity=""
        (( count >= FAILED_LOGIN_CRIT )) && severity="CRITICAL"
        [[ -z "$severity" ]] && (( count >= FAILED_LOGIN_WARN )) && severity="HIGH"
        if [[ $BASELINE_MODE -eq 0 && -n "$severity" ]]; then
            alert "$severity" "USR-002" "$ip" "$count suspicious SSH authentication events from $ip"
            ((USER_FINDING_TOTAL++))
        fi
    done < <(awk -F'|' '$1 == "FAIL" {print $3}' <<< "$records" | sort | uniq -c | sort -nr)

    if [[ $BASELINE_MODE -eq 0 ]]; then
        if (( total >= FAILED_LOGIN_CRIT )); then
            alert CRITICAL "USR-016" "all-sources" "$total suspicious SSH events across all source IPs"
            ((USER_FINDING_TOTAL++))
        elif (( total >= FAILED_LOGIN_WARN )); then
            alert HIGH "USR-016" "all-sources" "$total suspicious SSH events across all source IPs"
            ((USER_FINDING_TOTAL++))
        fi
    fi

    while read -r user distinct; do
        [[ -z "${user:-}" ]] && continue; severity=""
        (( distinct >= FAILED_LOGIN_CRIT )) && severity="CRITICAL"
        [[ -z "$severity" ]] && (( distinct >= FAILED_LOGIN_WARN )) && severity="HIGH"
        if [[ $BASELINE_MODE -eq 0 && -n "$severity" ]]; then
            alert "$severity" "USR-017" "$user" "$distinct distinct IPs targeted SSH account '$user'"
            ((USER_FINDING_TOTAL++))
        fi
    done < <(awk -F'|' '$1 == "FAIL" {print $2 "|" $3}' <<< "$records" | sort -u \
        | awk -F'|' '{count[$1]++} END {for (user in count) print user, count[user]}')
}

# user_check_login_history: aggregate wtmp/btmp without flooding the report.
user_check_login_history() {
    local output count users
    if command -v last >/dev/null 2>&1 && output="$(last -i --since today 2>/dev/null)"; then
        count="$(awk '$1 !~ /^(reboot|shutdown|wtmp|runlevel)$/ && NF {count++} END {print count + 0}' <<< "$output")"
        users="$(awk '$1 !~ /^(reboot|shutdown|wtmp|runlevel)$/ && NF {seen[$1]++} END {for (u in seen) printf "%s:%d ", u, seen[u]}' <<< "$output")"
        kv "Successful logins today" "$count${users:+ ($users)}"
    else
        kv "Successful login history" "unavailable"
        USER_COVERAGE_PARTIAL=1
    fi
    if command -v lastb >/dev/null 2>&1 && count="$(lastb 2>/dev/null | awk '$1 !~ /^(btmp|reboot|shutdown)$/ && NF {count++} END {print count + 0}')"; then
        kv "Failed login history" "$count record(s) in btmp"
    else
        kv "Failed login history" "unavailable (run as root to read btmp)"
        USER_COVERAGE_PARTIAL=1
    fi
}

# user_check_successful_logins: compare accepted SSH sources and working hours.
user_check_successful_logins() {
    local records="$1" line user ip hour observed baseline existing merged
    observed="$(awk -F'|' '$1 == "SUCCESS" {print $3}' <<< "$records" | sort -u)"
    while IFS='|' read -r _ user ip _ hour; do
        [[ -z "$user" ]] && continue
        if [[ -n "$hour" ]] && (( 10#$hour < WORK_HOURS_START || 10#$hour >= WORK_HOURS_END )) && [[ $BASELINE_MODE -eq 0 ]]; then
            alert MEDIUM "USR-007" "$user@$ip@$hour" "SSH login for '$user' from $ip outside working hours ($hour:00)"
            ((USER_FINDING_TOTAL++))
        fi
    done < <(grep '^SUCCESS|' <<< "$records" || true)

    if [[ $BASELINE_MODE -eq 1 ]]; then
        existing=""
        user_valid_baseline "user_login_ips" "LOGIN_IPS" && existing="$(baseline_get "user_login_ips" | sed '1d')"
        merged="$(printf '%s\n%s\n' "$existing" "$observed" | sed '/^$/d' | sort -u)"
        user_atomic_baseline "user_login_ips" "LOGIN_IPS" \
            "$(printf 'VERSION|%s|LOGIN_IPS\n%s' "$USER_BASELINE_VERSION" "$merged")" \
            && ok "Baseline: approved SSH source IPs recorded"
    elif user_valid_baseline "user_login_ips" "LOGIN_IPS"; then
        baseline="$(baseline_get "user_login_ips" | sed '1d')"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if ! grep -Fxq "$ip" <<< "$baseline"; then
                alert HIGH "USR-006" "$ip" "Successful SSH login from source IP absent from baseline: $ip"
                ((USER_FINDING_TOTAL++))
            fi
        done <<< "$observed"
    fi
}

# user_check_current_sessions: summarize active utmp sessions by user.
user_check_current_sessions() {
    local output summary
    if ! command -v who >/dev/null 2>&1 || ! output="$(who 2>/dev/null)"; then
        kv "Current sessions" "unavailable"
        USER_COVERAGE_PARTIAL=1
        return 0
    fi
    USER_SESSION_TOTAL="$(awk 'NF {count++} END {print count + 0}' <<< "$output")"
    summary="$(awk 'NF {count[$1]++} END {for (u in count) printf "%s:%d ", u, count[u]}' <<< "$output")"
    kv "Current sessions" "$USER_SESSION_TOTAL${summary:+ ($summary)}"
}

# user_account_snapshot: record name, UID, GID, home and shell from passwd.
user_account_snapshot() {
    printf 'VERSION|%s|ACCOUNTS\n' "$USER_BASELINE_VERSION"
    awk -F: '{print "ACCOUNT|" $1 "|" $3 "|" $4 "|" $6 "|" $7}' /etc/passwd | sort
}

# user_check_accounts: detect account additions, removals and property changes.
user_check_accounts() {
    local current baseline old name uid gid home shell old_uid old_gid old_home old_shell
    current="$(user_account_snapshot)"
    USER_ACCOUNT_TOTAL="$(grep -c '^ACCOUNT|' <<< "$current")"
    if [[ $BASELINE_MODE -eq 1 ]]; then
        user_atomic_baseline "user_accounts" "ACCOUNTS" "$current" && ok "Baseline: account properties recorded"
        return 0
    fi
    user_valid_baseline "user_accounts" "ACCOUNTS" || return 0
    baseline="$(baseline_get "user_accounts")"
    while IFS='|' read -r _ name uid gid home shell; do
        [[ -z "$name" ]] && continue
        old="$(awk -F'|' -v name="$name" '$1 == "ACCOUNT" && $2 == name {print; exit}' <<< "$baseline")"
        if [[ -z "$old" ]]; then
            alert HIGH "USR-003" "$name" "Account '$name' was created after baseline"
            ((USER_FINDING_TOTAL++)); continue
        fi
        IFS='|' read -r _ _ old_uid old_gid old_home old_shell <<< "$old"
        if [[ "$uid|$gid|$home|$shell" != "$old_uid|$old_gid|$old_home|$old_shell" ]]; then
            if [[ "$old_shell" =~ (nologin|false)$ && "$shell" =~ /(ba)?sh$ ]]; then
                alert HIGH "USR-009" "$name" "System account '$name' gained interactive shell $shell"
            else
                alert MEDIUM "USR-009" "$name" "Account properties changed for '$name' (UID/GID/home/shell)"
            fi
            ((USER_FINDING_TOTAL++))
        fi
    done < <(grep '^ACCOUNT|' <<< "$current")
    while IFS='|' read -r _ name _; do
        [[ -z "$name" ]] && continue
        if ! awk -F'|' -v name="$name" '$1 == "ACCOUNT" && $2 == name {found=1} END {exit !found}' <<< "$current"; then
            alert MEDIUM "USR-008" "$name" "Account '$name' was removed after baseline"
            ((USER_FINDING_TOTAL++))
        fi
    done < <(grep '^ACCOUNT|' <<< "$baseline")
}

# user_check_uid_gid_duplicates: detect duplicate account UIDs and group GIDs.
user_check_uid_gid_duplicates() {
    local id names
    [[ $BASELINE_MODE -eq 1 ]] && return 0
    while read -r id names; do
        [[ -z "${id:-}" ]] && continue
        alert HIGH "USR-012" "$id" "UID $id is shared by accounts: $names"
        ((USER_FINDING_TOTAL++))
    done < <(awk -F: '{names[$3]=names[$3] $1 " "; count[$3]++} END {for (id in count) if (count[id] > 1) print id, names[id]}' /etc/passwd)
    while read -r id names; do
        [[ -z "${id:-}" ]] && continue
        alert MEDIUM "USR-013" "$id" "GID $id is assigned to multiple group definitions: $names"
        ((USER_FINDING_TOTAL++))
    done < <(awk -F: '{names[$3]=names[$3] $1 " "; count[$3]++} END {for (id in count) if (count[id] > 1) print id, names[id]}' /etc/group)
}

# user_check_uid_zero: report every UID 0 account other than root.
user_check_uid_zero() {
    local account accounts
    accounts="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"
    while IFS= read -r account; do
        if [[ -n "$account" && "$account" != "root" && $BASELINE_MODE -eq 0 ]]; then
            alert CRITICAL "USR-001" "$account" "Account '$account' has full root privileges through UID 0"
            ((USER_FINDING_TOTAL++))
        fi
    done <<< "$accounts"
    kv "UID 0 accounts" "$(printf '%s\n' "$accounts" | tr '\n' ' ')"
}

# user_shadow_snapshot: store password state and aging metadata, never hashes.
user_shadow_snapshot() {
    printf 'VERSION|%s|SHADOW\n' "$USER_BASELINE_VERSION"
    awk -F: '{state=($2==""?"EMPTY":($2~/^[!*]/?"LOCKED":"ACTIVE")); print "SHADOW|" $1 "|" state "|" $3 "|" $5 "|" $8}' /etc/shadow | sort
}

# user_check_shadow: detect empty passwords, unlocks and relaxed expiration.
user_check_shadow() {
    local current baseline old name state maximum expiry old_state old_max old_expiry
    if [[ ! -r /etc/shadow ]]; then
        kv "Shadow checks" "unavailable (run as root)"
        USER_COVERAGE_PARTIAL=1
        return 0
    fi
    current="$(user_shadow_snapshot)"
    while IFS='|' read -r _ name state _; do
        if [[ "$state" == "EMPTY" && $BASELINE_MODE -eq 0 ]]; then
            alert CRITICAL "USR-004" "$name" "Account '$name' has an empty password field"
            ((USER_FINDING_TOTAL++))
        fi
    done < <(grep '^SHADOW|' <<< "$current")
    if [[ $BASELINE_MODE -eq 1 ]]; then
        user_atomic_baseline "user_shadow_state" "SHADOW" "$current" && ok "Baseline: password states and aging recorded"
        return 0
    fi
    user_valid_baseline "user_shadow_state" "SHADOW" || return 0
    baseline="$(baseline_get "user_shadow_state")"
    while IFS='|' read -r _ name state _ maximum expiry; do
        old="$(awk -F'|' -v name="$name" '$1 == "SHADOW" && $2 == name {print; exit}' <<< "$baseline")"
        [[ -z "$old" ]] && continue
        IFS='|' read -r _ _ old_state _ old_max old_expiry <<< "$old"
        if [[ "$old_state" == "LOCKED" && "$state" == "ACTIVE" ]]; then
            alert HIGH "USR-014" "$name" "Previously locked account '$name' is now active"
            ((USER_FINDING_TOTAL++))
        fi
        if [[ -n "$old_expiry" && -z "$expiry" ]] || [[ -n "$old_max" && -z "$maximum" ]]; then
            alert MEDIUM "USR-015" "$name" "Password expiration was relaxed for '$name'"
            ((USER_FINDING_TOTAL++))
        fi
    done < <(grep '^SHADOW|' <<< "$current")
}

# user_group_snapshot: record sudo/wheel existence, GID and complete membership.
user_group_snapshot() {
    local group entry gid members
    printf 'VERSION|%s|GROUPS\n' "$USER_BASELINE_VERSION"
    for group in sudo wheel; do
        entry="$(getent group "$group" 2>/dev/null || true)"
        if [[ -z "$entry" ]]; then
            printf 'GROUP|%s|MISSING|\n' "$group"; continue
        fi
        gid="$(cut -d: -f3 <<< "$entry")"
        members="$( { cut -d: -f4 <<< "$entry" | tr ',' '\n'; awk -F: -v gid="$gid" '$4 == gid {print $1}' /etc/passwd; } | sed '/^$/d' | sort -u | tr '\n' ',')"
        printf 'GROUP|%s|%s|%s\n' "$group" "$gid" "$members"
    done
}

# user_check_privileged_groups: detect group, GID and member changes both ways.
user_check_privileged_groups() {
    local current baseline group gid members old old_gid old_members member
    current="$(user_group_snapshot)"
    USER_PRIVILEGED_TOTAL="$(awk -F'|' '$1=="GROUP" && $3!="MISSING" {n=split($4,a,","); for(i=1;i<=n;i++) if(a[i]!="") seen[a[i]]=1} END {for(i in seen)c++; print c+0}' <<< "$current")"
    if [[ $BASELINE_MODE -eq 1 ]]; then
        user_atomic_baseline "user_privileged_members" "GROUPS" "$current" && ok "Baseline: sudo/wheel definitions recorded"
        return 0
    fi
    user_valid_baseline "user_privileged_members" "GROUPS" || return 0
    baseline="$(baseline_get "user_privileged_members")"
    while IFS='|' read -r _ group gid members; do
        old="$(awk -F'|' -v group="$group" '$1=="GROUP" && $2==group {print; exit}' <<< "$baseline")"
        IFS='|' read -r _ _ old_gid old_members <<< "$old"
        if [[ "$gid" != "$old_gid" ]]; then
            alert HIGH "USR-011" "$group" "Privileged group '$group' state/GID changed: $old_gid -> $gid"
            ((USER_FINDING_TOTAL++))
        fi
        while IFS= read -r member; do
            [[ -z "$member" ]] && continue
            if [[ ",$old_members" != *",$member,"* ]]; then
                alert HIGH "USR-005" "$member@$group" "User '$member' was added to privileged group '$group'"
                ((USER_FINDING_TOTAL++))
            fi
        done < <(tr ',' '\n' <<< "$members")
        while IFS= read -r member; do
            [[ -z "$member" ]] && continue
            if [[ ",$members" != *",$member,"* ]]; then
                alert MEDIUM "USR-010" "$member@$group" "User '$member' was removed from privileged group '$group'"
                ((USER_FINDING_TOTAL++))
            fi
        done < <(tr ',' '\n' <<< "$old_members")
    done < <(grep '^GROUP|' <<< "$current")
    kv "Privileged members" "$USER_PRIVILEGED_TOTAL"
}

# user_print_summary: make unavailable sources and actual coverage visible.
user_print_summary() {
    kv "SSH records parsed" "$USER_AUTH_PARSED"
    kv "SSH records unparsed" "$USER_AUTH_UNPARSED"
    kv "Current sessions checked" "$USER_SESSION_TOTAL"
    kv "Accounts checked" "$USER_ACCOUNT_TOTAL"
    kv "Privileged members" "$USER_PRIVILEGED_TOTAL"
    kv "Module findings" "$USER_FINDING_TOTAL"
    kv "Collection coverage" "$([[ $USER_COVERAGE_PARTIAL -eq 0 ]] && printf complete || printf partial)"
}

# run_user_activity: PUBLIC ENTRY POINT.
run_user_activity() {
    local auth_records raw_records
    section "MODULE 2 - USER ACTIVITY"
    USER_AUTH_PARSED=0; USER_AUTH_UNPARSED=0; USER_SESSION_TOTAL=0
    USER_ACCOUNT_TOTAL=0; USER_PRIVILEGED_TOTAL=0; USER_FINDING_TOTAL=0
    USER_COVERAGE_PARTIAL=0
    user_check_dependencies || { kv "User activity module" "required commands are missing"; return 1; }
    user_validate_config || return 1
    user_load_auth_events
    raw_records="$(user_auth_records)"
    USER_AUTH_PARSED="$(grep -Ec '^(FAIL|SUCCESS)\|' <<< "$raw_records")"
    USER_AUTH_UNPARSED="$(grep -c '^UNPARSED|' <<< "$raw_records")"
    auth_records="$(grep -E '^(FAIL|SUCCESS)\|' <<< "$raw_records" || true)"
    user_alert_failed_logins "$auth_records"
    user_check_login_history
    user_check_successful_logins "$auth_records"
    user_check_current_sessions
    user_check_uid_zero
    user_check_accounts
    user_check_uid_gid_duplicates
    user_check_shadow
    user_check_privileged_groups
    user_print_summary
    return 0
}