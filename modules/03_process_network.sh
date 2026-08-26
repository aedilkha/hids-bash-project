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

# check_outbound: established connections to public IPs are logged as
# context (not alerts) — outbound traffic is normal, but a human reviewer
# should see the full list to judge if anything looks out of place.
# Source: ss -tupn state established (active TCP/UDP connections).
check_outbound() {
    local proto localaddr peeraddr proc peer_ip found=0
    while read -r proto _ _ localaddr peeraddr proc; do
        [[ "$proto" == "Netid" ]] && continue
        [[ -z "$peeraddr" ]] && continue
        peer_ip="${peeraddr%:*}"
        peer_ip="${peer_ip#\[}"
        peer_ip="${peer_ip%\]}"

        case "$peer_ip" in
            10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|127.*|::1)
                continue
                ;;
            *)
                kv "outbound" "Established connection to public IP: $peer_ip (local: $localaddr), proto $proto, proc: ${proc:-unknown, needs sudo}"
                found=1
                ;;
        esac
    done < <(ss -tupn state established 2>/dev/null)
    (( found == 0 )) && ok "No established outbound connections to public IPs"
    return 0
}

# check_reverse_shell: a shell-type process (bash, sh, nc, python, perl...)
# holding an active network connection is a classic reverse-shell pattern —
# legitimate shells talk to your terminal, not a remote socket.
# Source: ss -tupn (owning process) cross-referenced against shell binary names.
check_reverse_shell() {
    local proto localaddr peeraddr proc pid comm found=0
    while read -r proto _ _ localaddr peeraddr proc; do
        [[ "$proto" == "Netid" ]] && continue
        [[ -z "$proc" ]] && continue

        pid="$(grep -oP 'pid=\K[0-9]+' <<< "$proc")"
        [[ -z "$pid" ]] && continue
        comm="$(ps -o comm= -p "$pid" 2>/dev/null)"

        case "$comm" in
            bash|sh|dash|nc|ncat|netcat|python*|perl|ruby|php)
                alert HIGH "PRC-004" "$pid" "Shell-like process with network connection: comm=$comm, pid=$pid, local=$localaddr, peer=$peeraddr"
                found=1
                ;;
        esac
    done < <(ss -tupn 2>/dev/null)
    (( found == 0 )) && ok "No shell process holding an active network connection"
    return 0
}

# check_cron_jobs: cron entries containing wget/curl, base64, or a pipe into
# a shell are a common persistence mechanism — attacker code that re-downloads
# and re-executes itself on a schedule, surviving a manual cleanup.
# Source: /etc/cron* (system-wide) and crontab -l (per-user).
check_cron_jobs() {
    local line user found=0

    # System-wide cron files
    while read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        case "$line" in
            *wget*|*curl*|*base64*|*'| bash'*|*'|bash'*|*'| sh'*|*'|sh'*)
                alert HIGH "PRC-005" "system-cron" "Suspicious system cron entry: ${line:0:100}"
                found=1
                ;;
        esac
    done < <(cat /etc/crontab /etc/cron.d/* 2>/dev/null)

    # Per-user crontabs
    for user in $(cut -d: -f1 /etc/passwd); do
        while read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            case "$line" in
                *wget*|*curl*|*base64*|*'| bash'*|*'|bash'*|*'| sh'*|*'|sh'*)
                    alert HIGH "PRC-005" "$user" "Suspicious cron entry for user $user: ${line:0:100}"
                    found=1
                    ;;
            esac
        done < <(crontab -u "$user" -l 2>/dev/null)
    done

    (( found == 0 )) && ok "No suspicious cron entries found"
    return 0
}

# check_new_services: a systemd service present now but absent from a saved
# baseline snapshot is a common persistence mechanism — attacker installs a
# service so their code auto-starts on every boot.
# Source: systemctl list-units --type=service, compared against a saved
# baseline file (data/baseline_services.txt), created on first run.
check_new_services() {
    local baseline_file="data/baseline_services.txt"
    local current_services svc found=0

    mkdir -p "$(dirname "$baseline_file")" 2>/dev/null

    current_services="$(systemctl list-units --type=service --no-legend 2>/dev/null | awk '{print $1}' | sort)"

    if [[ ! -f "$baseline_file" ]]; then
        echo "$current_services" > "$baseline_file"
        ok "Baseline created with $(wc -l < "$baseline_file") services (first run, nothing to compare yet)"
        return 0
    fi

    while read -r svc; do
        [[ -z "$svc" ]] && continue
        if ! grep -qxF "$svc" "$baseline_file"; then
            alert MEDIUM "PRC-006" "$svc" "New systemd service not in baseline: $svc"
            found=1
        fi
    done <<< "$current_services"

    (( found == 0 )) && ok "No new systemd services since baseline"
    return 0
}

# run_process_network: PUBLIC ENTRY POINT.
run_process_network() {
    section "MODULE 3 - PROCESS AND NETWORK"
    check_suspicious_paths
    # TODO: add the other calls as you write them
    return 0
}

