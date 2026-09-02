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

# Authentication events are loaded once. Fedora uses the sshd systemd unit;
# Debian/Ubuntu usually expose the same messages in /var/log/auth.log.
AUTH_EVENTS=""
AUTH_SOURCE="unavailable"

# load_auth_events: collect only today's sshd records from config or journald.
load_auth_events() {
    local auth_log="${AUTH_LOG:-}" today_prefix

    if [[ -n "$auth_log" && -r "$auth_log" ]]; then
        today_prefix="$(LC_ALL=C date '+%b %e')"
        AUTH_EVENTS="$(LC_ALL=C awk -v day="$today_prefix" \
            'substr($0, 1, length(day)) == day' "$auth_log")"
        AUTH_SOURCE="$auth_log"
    elif command -v journalctl >/dev/null 2>&1; then
        AUTH_EVENTS="$(journalctl -q --no-pager -o short-iso \
            -u sshd -u ssh --since today 2>/dev/null || true)"
        AUTH_SOURCE="systemd journal (sshd/ssh)"
    fi
    kv "Authentication source" "$AUTH_SOURCE"
}

# auth_ip_from_line: extract the value after "from" in an sshd log line.
auth_ip_from_line() {
    awk '{for (i = 1; i < NF; i++) if ($i == "from") {print $(i + 1); exit}}' <<< "$1"
}

# auth_user_from_line: extract the target account, including "invalid user" lines.
auth_user_from_line() {
    awk '{
        for (i = 1; i < NF; i++) {
            if ($i != "for") continue
            if ($(i + 1) == "invalid" && $(i + 2) == "user") print $(i + 3)
            else print $(i + 1)
            exit
        }
    }' <<< "$1"
}

# auth_hour_from_line: read the hour from journald ISO or traditional syslog time.
auth_hour_from_line() {
    local line="$1"
    if [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T([0-9]{2}): ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[A-Z][a-z]{2}[[:space:]]+[0-9]+[[:space:]]+([0-9]{2}): ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    fi
}

# check_failed_logins: aggregate SSH password failures by source and target.
check_failed_logins() {
    local line ip user records="" count severity account_summary total btmp_output

    while IFS= read -r line; do
        [[ "$line" != *"Failed password"* ]] && continue
        ip="$(auth_ip_from_line "$line")"
        user="$(auth_user_from_line "$line")"
        [[ -n "$ip" ]] && records+="$ip ${user:-unknown}"$'\n'
    done <<< "$AUTH_EVENTS"

    total="$(sed '/^$/d' <<< "$records" | wc -l)"
    kv "Failed SSH passwords" "$total today"

    if (( total == 0 )); then
        ok "No failed SSH password authentication today"
    else
        account_summary="$(awk '{print $2}' <<< "$records" | sort | uniq -c | sort -nr | xargs)"
        kv "Targeted accounts" "$account_summary"
        while read -r count ip; do
            [[ -z "${ip:-}" ]] && continue
            severity=""
            (( count >= FAILED_LOGIN_CRIT )) && severity="CRITICAL"
            [[ -z "$severity" ]] && (( count >= FAILED_LOGIN_WARN )) && severity="HIGH"
            [[ $BASELINE_MODE -eq 0 && -n "$severity" ]] && alert "$severity" "USR-002" "$ip" \
                "$count failed SSH password attempts from $ip today"
        done < <(awk '{print $1}' <<< "$records" | sort | uniq -c | sort -nr)
    fi

    if btmp_output="$(lastb 2>&1)"; then
        count="$(awk '$1 !~ /^(btmp|reboot|shutdown)$/ && NF {count++} END {print count + 0}' <<< "$btmp_output")"
        kv "Failed login history" "$count record(s) in btmp"
    else
        kv "Failed login history" "unavailable (run as root to read btmp)"
    fi
}

# check_successful_logins: show wtmp history and detect unusual SSH sources/times.
check_successful_logins() {
    local line ip user hour accepted_ips="" baseline_ips recent_count=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        kv "Recent login" "$line"
        ((recent_count++))
    done < <(last -i --since today 2>/dev/null | awk '$1 !~ /^(reboot|shutdown|wtmp|runlevel)$/ && NF')
    (( recent_count == 0 )) && kv "Recent logins" "none recorded in wtmp"

    while IFS= read -r line; do
        [[ ! "$line" =~ Accepted[[:space:]]+(password|publickey|keyboard-interactive) ]] && continue
        ip="$(auth_ip_from_line "$line")"
        user="$(auth_user_from_line "$line")"
        hour="$(auth_hour_from_line "$line")"
        [[ -n "$ip" ]] && accepted_ips+="$ip"$'\n'

        if [[ -n "$hour" ]] && (( 10#$hour < WORK_HOURS_START || 10#$hour >= WORK_HOURS_END )); then
            [[ $BASELINE_MODE -eq 0 ]] && alert MEDIUM "USR-007" "${user:-unknown}@$ip@$hour" \
                "SSH login for '${user:-unknown}' from ${ip:-unknown} outside working hours ($hour:00)"
        fi
    done <<< "$AUTH_EVENTS"

    accepted_ips="$(sed '/^$/d' <<< "$accepted_ips" | sort -u)"
    if [[ $BASELINE_MODE -eq 1 ]]; then
        printf '%s\n' "${accepted_ips:-<none>}" | baseline_set "user_login_ips"
        ok "Baseline: known SSH source IPs recorded"
    elif baseline_exists "user_login_ips"; then
        baseline_ips="$(baseline_get "user_login_ips")"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            grep -Fxq "$ip" <<< "$baseline_ips" || alert HIGH "USR-006" "$ip" \
                "Successful SSH login from source IP not present in the baseline: $ip"
        done <<< "$accepted_ips"
    else
        kv "Known SSH source IPs" "baseline not captured"
    fi
}

# check_current_sessions: report users currently represented in utmp.
check_current_sessions() {
    local line count=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        kv "Current session" "$line"
        ((count++))
    done < <(who 2>/dev/null)
    (( count == 0 )) && kv "Current sessions" "none"
}

# check_uid_zero: only root should have UID 0. A second UID 0 account is a
# classic, easily overlooked backdoor. Source: field 3 of /etc/passwd.
check_uid_zero() {
    local accounts
    accounts="$(awk -F: '$3 == 0 {print $1}' "${PASSWD_FILE:-/etc/passwd}")"
    while read -r account; do
        [[ -z "$account" ]] && continue
        if [[ "$account" != "root" && $BASELINE_MODE -eq 0 ]]; then
            alert CRITICAL "USR-001" "$account" "Account '$account' with UID 0 - full root privileges, likely backdoor"
        fi
    done <<< "$accounts"
    kv "UID 0 accounts" "$(echo "$accounts" | tr '\n' ' ')"
}

# check_new_accounts: compare account names with the reference passwd snapshot.
check_new_accounts() {
    local current account
    current="$(cut -d: -f1 "${PASSWD_FILE:-/etc/passwd}" | sort -u)"

    if [[ $BASELINE_MODE -eq 1 ]]; then
        printf '%s\n' "$current" | baseline_set "user_accounts"
        ok "Baseline: account list recorded"
    elif baseline_exists "user_accounts"; then
        while IFS= read -r account; do
            [[ -n "$account" ]] && alert HIGH "USR-003" "$account" \
                "Account '$account' was created after the baseline"
        done < <(comm -13 <(baseline_get "user_accounts" | sort -u) <(printf '%s\n' "$current"))
    else
        kv "Account comparison" "baseline not captured"
    fi
}

# check_low_uid_accounts: a newly created interactive account below the normal
# user UID range is suspicious, even when it does not have UID 0.
check_low_uid_accounts() {
    local account uid shell baseline current found=0
    current="$(awk -F: -v limit="$LOW_UID_THRESHOLD" '$3 < limit && $1 != "root" && $7 !~ /(nologin|false)$/ {print $1 "|" $3 "|" $7}' "${PASSWD_FILE:-/etc/passwd}")"

    if [[ $BASELINE_MODE -eq 1 ]]; then
        printf '%s\n' "${current:-<none>}" | baseline_set "low_uid_accounts"
        return 0
    fi
    if ! baseline_exists "low_uid_accounts"; then
        kv "Low-UID interactive accounts" "baseline not captured"
        return 0
    fi
    baseline="$(baseline_get "low_uid_accounts")"
    while IFS='|' read -r account uid shell; do
        [[ -z "$account" || "$account" == "<none>" ]] && continue
        if ! grep -Fqx "$account|$uid|$shell" <<< "$baseline"; then
            alert MEDIUM "USR-008" "$account" "New interactive account '$account' has low UID $uid and shell $shell"
            found=1
        fi
    done <<< "$current"
    (( found == 0 )) && ok "No new low-UID interactive account detected"
}

# check_empty_passwords: an empty shadow hash permits passwordless access.
check_empty_passwords() {
    local accounts account
    local shadow_file="${SHADOW_FILE:-/etc/shadow}"
    if [[ ! -r "$shadow_file" ]]; then
        kv "Empty password check" "unavailable (run as root to read /etc/shadow)"
        return 0
    fi

    accounts="$(awk -F: '$2 == "" {print $1}' "$shadow_file")"
    if [[ -z "$accounts" ]]; then
        ok "No account has an empty password field"
        return 0
    fi

    while IFS= read -r account; do
        [[ -n "$account" && $BASELINE_MODE -eq 0 ]] && alert CRITICAL "USR-004" "$account" \
            "Account '$account' has an empty password field in /etc/shadow"
    done <<< "$accounts"
    [[ $BASELINE_MODE -eq 1 ]] && kv "Empty password accounts" "$(tr '\n' ' ' <<< "$accounts")"
}

# privileged_members: list explicit and primary members of sudo/wheel groups.
privileged_members() {
    local group entry gid members
    for group in sudo wheel; do
        entry="$(getent group "$group" 2>/dev/null || true)"
        [[ -z "$entry" ]] && continue
        gid="$(cut -d: -f3 <<< "$entry")"
        members="$(cut -d: -f4 <<< "$entry" | tr ',' '\n')"
        printf '%s\n' "$members"
        awk -F: -v gid="$gid" '$4 == gid {print $1}' /etc/passwd
    done | sed '/^$/d' | sort -u
}

# check_sudo_group: Fedora uses wheel; Debian-family systems usually use sudo.
check_sudo_group() {
    local current baseline member
    current="$(privileged_members)"

    if [[ $BASELINE_MODE -eq 1 ]]; then
        printf '%s\n' "${current:-<none>}" | baseline_set "user_privileged_members"
        ok "Baseline: sudo/wheel membership recorded"
    elif baseline_exists "user_privileged_members"; then
        baseline="$(baseline_get "user_privileged_members")"
        while IFS= read -r member; do
            [[ -z "$member" ]] && continue
            grep -Fxq "$member" <<< "$baseline" || alert HIGH "USR-005" "$member" \
                "User '$member' was added to the sudo/wheel group after the baseline"
        done <<< "$current"
    else
        kv "Sudo/wheel comparison" "baseline not captured"
    fi
    kv "Sudo/wheel members" "${current//$'\n'/ }"
}

# run_user_activity: PUBLIC ENTRY POINT.
run_user_activity() {
    section "MODULE 2 - USER ACTIVITY"
    load_auth_events
    check_failed_logins
    check_successful_logins
    check_current_sessions
    check_uid_zero
    check_new_accounts
    check_low_uid_accounts
    check_empty_passwords
    check_sudo_group
    return 0
}