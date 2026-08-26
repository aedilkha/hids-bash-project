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

# check_high_resource: a process pinned at high CPU or memory for a sustained
# period is a common sign of cryptomining or other malicious background load.
# Source: ps -eo pcpu,pmem (percent CPU / percent memory per process).
check_high_resource() {
    local pid user pcpu pmem cmdline found=0
    while read -r pid user pcpu pmem; do
        [[ "$pid" == "PID" ]] && continue
        cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        if (( $(echo "$pcpu >= $CPU_PROCESS_ALERT" | bc -l 2>/dev/null) )); then
            alert HIGH "PRC-003" "$pid" "High CPU usage: pid $pid, user $user, cpu ${pcpu}%, cmd: ${cmdline:0:80}"
            found=1
        elif (( $(echo "$pmem >= $MEM_PROCESS_ALERT" | bc -l 2>/dev/null) )); then
            alert HIGH "PRC-003" "$pid" "High memory usage: pid $pid, user $user, mem ${pmem}%, cmd: ${cmdline:0:80}"
            found=1
        fi
    done < <(ps -eo pid,user,pcpu,pmem --no-headers 2>/dev/null)
    (( found == 0 )) && ok "No process exceeding CPU/memory thresholds"
    return 0
}

# check_listening_ports: any listening port outside PORT_WHITELIST is a
# potential backdoor or unexpected service. 0.0.0.0 (network-exposed) is
# more severe than 127.0.0.1/::1 (localhost only).
# Source: ss -tulnp (listening TCP/UDP sockets + owning process).
check_listening_ports() {
    local proto localaddr port proc found=0
    while read -r proto _ _ _ localaddr _ proc; do
        [[ "$proto" == "Netid" ]] && continue
        [[ -z "$localaddr" ]] && continue
        port="${localaddr##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        if [[ ! " $PORT_WHITELIST " =~ " $port " ]]; then
            case "$localaddr" in
                127.0.0.1:*|\[::1\]:*)
                    alert MEDIUM "NET-001" "$port" "Unexpected port (localhost only): $localaddr, proto $proto, proc: ${proc:-unknown, needs sudo}"
                    ;;
                *)
                    alert HIGH "NET-001" "$port" "Unexpected port (network-exposed): $localaddr, proto $proto, proc: ${proc:-unknown, needs sudo}"
                    ;;
            esac
            found=1
        fi
    done < <(ss -tulnp 2>/dev/null)
    (( found == 0 )) && ok "No listening port outside PORT_WHITELIST"
    return 0
}

# run_process_network: PUBLIC ENTRY POINT.
run_process_network() {
    section "MODULE 3 - PROCESS AND NETWORK"
    check_suspicious_paths
    # TODO: add the other calls as you write them
    return 0
}

