#!/bin/bash
# ==============================================================================
# Module 3 — Process and Network Audit                           [TO COMPLETE]
# Answers: "is anything running or listening that should not be?"
#
# CONTRACT (do not modify):
#   - public function: run_process_network
#   - alert code prefixes: PRC-xxx (processes), NET-xxx (network)
#   - anomalies -> alert(), context -> kv()/ok()
#   - no hard-coded thresholds/whitelists: everything in hids.conf
#
# WHERE TO FIND THE INFO:
#   ps -eo user,pid,ppid,pcpu,pmem,lstart,comm,args
#   /proc/<pid>/exe      "(deleted)" = binary removed from disk (strong signal)
#   /proc/<pid>/cmdline  real command line
#   ss -tulnp            listening ports + owning process
#   ss -tupn state established   active outbound connections
#   systemctl list-units --type=service   ;   /etc/cron*, crontab -l
#
# CHECKLIST — each ticked box = one commented function
#   [ ] check_suspicious_paths   process from /tmp,/dev/shm,/var/tmp = HIGH (DONE)
#   [ ] check_deleted_binaries   /proc/<pid>/exe -> "(deleted)"
#   [ ] check_high_resource      abnormal CPU/RAM (mining)
#   [ ] check_listening_ports    listening ports vs PORT_WHITELIST
#   [ ] check_outbound           established connections to public IPs
#   [ ] check_reverse_shell      bash/sh/nc/python with a network socket
#   [ ] check_cron_jobs          cron with wget/curl/base64/| bash
#   [ ] check_new_services       systemd services absent from the baseline
#
# PITFALLS:
#   - ss -p needs root to see other users' owning process (say so if empty)
#   - PORT_WHITELIST is essential or the report screams about sshd, resolved, cups
#   - 127.0.0.1/::1 listeners are not network-exposed: lower severity than 0.0.0.0
#   - a legit process can run from /tmp (installer): prefer HIGH + context
# ==============================================================================

# REFERENCE EXAMPLE — keep and complete the rest.
# check_suspicious_paths: a process run from a world-writable temp dir is the
# most common post-compromise pattern. Source: /proc/<pid>/exe via readlink.
check_suspicious_paths() {
    local pid exe owner cmdline found=0
    for pid in $(ps -eo pid --no-headers 2>/dev/null); do
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" || continue
        [[ -z "$exe" ]] && continue
        case "$exe" in
            /tmp/*|/dev/shm/*|/var/tmp/*|/run/shm/*)
                owner="$(stat -c '%U' "/proc/$pid" 2>/dev/null)"
                cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
                alert HIGH "PRC-001" "$exe" "Process from a temp dir: pid $pid, user $owner, cmd: ${cmdline:0:80}"
                found=1
                ;;
        esac
    done
    (( found == 0 )) && ok "No process started from /tmp, /dev/shm or /var/tmp"
    return 0
}

# run_process_network: PUBLIC ENTRY POINT.
run_process_network() {
    section "MODULE 3 - PROCESS AND NETWORK"
    check_suspicious_paths
    # TODO: add the other calls as you write them
    return 0
}

# check_deleted_binaries: a process whose on-disk binary has been deleted
# is running purely from memory, hiding itself from file-based scans.
# Source: /proc/<pid>/exe symlink target via readlink.
check_deleted_binaries() {
    local pid exe owner cmdline found=0
    for pid in $(ps -eo pid --no-headers 2>/dev/null); do
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
        [[ -z "$exe" ]] && continue
        case "$exe" in
            *"(deleted)")
                owner="$(stat -c '%U' "/proc/$pid" 2>/dev/null)"
                cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
                alert HIGH "PRC-002" "$exe" "Deleted binary still running: pid $pid, user $owner, cmd: ${cmdline:0:80}"
                found=1
                ;;
        esac
    done
    (( found == 0 )) && ok "No process is running from a deleted binary"
    return 0
}
