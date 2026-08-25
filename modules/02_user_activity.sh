#!/bin/bash
# ==============================================================================
# Module 2 — User Activity                                       [TO COMPLETE]
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
# CHECKLIST — each ticked box = one commented function
#   [ ] check_failed_logins      top IPs + top targeted accounts (auth.log)
#   [ ] check_successful_logins  recent successful logins, with source IP
#   [ ] check_current_sessions   who is logged in now (`who`)
#   [ ] check_uid_zero           any UID 0 other than root = CRITICAL   (DONE)
#   [ ] check_new_accounts       compare /etc/passwd to the baseline
#   [ ] check_empty_passwords    accounts with no password in /etc/shadow
#   [ ] check_sudo_group         new members of the sudo group
#   [ ] check_odd_hours          logins outside working hours (optional)
#
# PITFALLS:
#   - auth.log may be absent on journald-only systems -> fallback journalctl -u ssh
#   - lastb needs root: handle non-root (kv "not available")
#   - `last` includes reboot / "wtmp begins": filter them out
#   - first run has no baseline: use baseline_exists() before comparing
# ==============================================================================

# REFERENCE EXAMPLE — keep and complete the rest.
# check_uid_zero: only root should have UID 0. A second UID 0 account is a
# classic, easily overlooked backdoor. Source: field 3 of /etc/passwd.
check_uid_zero() {
    local accounts
    accounts="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"
    while read -r account; do
        [[ -z "$account" ]] && continue
        if [[ "$account" != "root" ]]; then
            alert CRITICAL "USR-001" "$account" "Account '$account' with UID 0 - full root privileges, likely backdoor"
        fi
    done <<< "$accounts"
    kv "UID 0 accounts" "$(echo "$accounts" | tr '\n' ' ')"
}

# run_user_activity: PUBLIC ENTRY POINT. Call the checklist functions here.
run_user_activity() {
    section "MODULE 2 - USER ACTIVITY"
    check_uid_zero
    # TODO: add the other calls as you write them
    return 0
}