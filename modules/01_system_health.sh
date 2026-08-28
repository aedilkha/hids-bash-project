#!/bin/bash
# ==============================================================================
# Module 1 — System Health
# Answers: "is this system healthy right now?"
#
# >>> STYLE REFERENCE FOR THE OTHER MODULES. <
#   - one function = one check, with a comment saying what and why
#   - raw data -> kv(), anomalies -> alert(), no direct log writes
#   - thresholds come from the config, never hard-coded
#   - in --baseline mode: show context (kv/ok) but never call alert()
# Alert codes reserved for this module: SYS-xxx
# ==============================================================================

# check_load_average: compare load to core count (load/4 is fine on 4 cores,
# critical on 1). Rising load with no visible process = mining/scan/fork bomb.
# Source: /proc/loadavg.
check_load_average() {
    local load1 load5 load15 cores ratio
    read -r load1 load5 load15 _ < /proc/loadavg
    cores="$(nproc 2>/dev/null || echo 1)"
    ratio="$(awk -v load_value="$load1" -v core_count="$cores" 'BEGIN { printf "%.2f", load_value / core_count }')"

    kv "Load (1/5/15 min)" "$load1 / $load5 / $load15  (${cores} cores)"
    kv "Load per core"     "$ratio"

    if [[ $BASELINE_MODE -eq 0 ]]; then
        if awk -v value="$ratio" -v threshold="$CPU_LOAD_CRIT" 'BEGIN { exit !(value >= threshold) }'; then
            alert CRITICAL "SYS-001" "loadavg" "Load per core at $ratio (crit $CPU_LOAD_CRIT) - system saturated"
        elif awk -v value="$ratio" -v threshold="$CPU_LOAD_WARN" 'BEGIN { exit !(value >= threshold) }'; then
            alert MEDIUM "SYS-001" "loadavg" "Load per core at $ratio (threshold $CPU_LOAD_WARN)"
        else
            ok "System load normal"
        fi
    fi
}

# check_memory: RAM and swap. Uses MemAvailable (not MemFree, which is always
# low because Linux caches with free RAM). Source: /proc/meminfo.
check_memory() {
    local total avail used_pct swap_total swap_free swap_pct
    total="$(awk '/^MemTotal:/     {print $2}' /proc/meminfo)"
    avail="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    used_pct=$(( (total - avail) * 100 / total ))

    kv "RAM used" "${used_pct}%  ($(( (total - avail) / 1024 )) MB / $(( total / 1024 )) MB)"

    if [[ $BASELINE_MODE -eq 0 ]]; then
        if (( used_pct >= MEM_USED_CRIT )); then
            alert CRITICAL "SYS-002" "memory" "RAM used at ${used_pct}% (threshold $MEM_USED_CRIT%)"
        elif (( used_pct >= MEM_USED_WARN )); then
            alert MEDIUM "SYS-002" "memory" "RAM used at ${used_pct}% (threshold $MEM_USED_WARN%)"
        else
            ok "Enough memory available"
        fi
    fi

    # Swap is checked independently of the block above: we always want to see
    # the swap figure, even in baseline mode, we just never alert on it there.
    swap_total="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
    swap_free="$(awk '/^SwapFree:/  {print $2}' /proc/meminfo)"
    if (( swap_total > 0 )); then
        swap_pct=$(( (swap_total - swap_free) * 100 / swap_total ))
        kv "Swap used" "${swap_pct}%"
        if [[ $BASELINE_MODE -eq 0 ]]; then
            (( swap_pct >= 50 )) && alert MEDIUM "SYS-003" "swap" "Swap used at ${swap_pct}%"
        fi
    fi
}

# check_disk: disk space per mount, plus inodes. A full disk stops log writing
# (blinds detection). Inodes trap: df -h says 40% but df -i says 100%.
#
# IMPORTANT: inside a `while read` loop, `return` would exit the WHOLE
# function on the first line read (it stops the loop AND everything after
# it). We only ever use `continue` inside these loops, and keep the
# baseline-mode guard as a plain `if` around the alert() call instead.
check_disk() {
    while read -r fs used_pct mount; do
        used_pct="${used_pct%\%}"
        kv "Disk $mount" "${used_pct}% used ($fs)"

        if [[ $BASELINE_MODE -eq 0 ]]; then
            if (( used_pct >= DISK_USED_CRIT )); then
                alert CRITICAL "SYS-004" "$mount" "Partition $mount full at ${used_pct}%"
            elif (( used_pct >= DISK_USED_WARN )); then
                alert MEDIUM "SYS-004" "$mount" "Partition $mount at ${used_pct}%"
            fi
        fi
    done < <(df -hP -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR>1 {print $1, $5, $6}')

    while read -r used_pct mount; do
        used_pct="${used_pct%\%}"
        [[ "$used_pct" =~ ^[0-9]+$ ]] || continue

        if [[ $BASELINE_MODE -eq 0 ]]; then
            (( used_pct >= DISK_USED_CRIT )) && \
                alert HIGH "SYS-005" "inodes:$mount" "Inodes exhausted at ${used_pct}% on $mount (writes blocked)"
        fi
    done < <(df -iP -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR>1 {print $5, $6}')
}

# check_top_processes: 5 most CPU-hungry processes, as context for the analyst.
check_top_processes() {
    printf '  %sTop 5 CPU:%s\n' "$C_DIM" "$C_RESET"
    ps -eo pcpu,pmem,user,pid,comm --sort=-pcpu --no-headers 2>/dev/null | head -5 | \
        while read -r cpu mem user pid comm; do
            printf '    %5s%% cpu  %5s%% mem  %-10s pid %-7s %s\n' "$cpu" "$mem" "$user" "$pid" "$comm"
        done
}

# check_zombies: many zombies = a parent not reaping children, often a sign of
# a broken program or an injected process that lost its parent.
check_zombies() {
    local count
    count="$(ps -eo stat --no-headers 2>/dev/null | grep -c '^Z')"
    kv "Zombie processes" "$count"

    if [[ $BASELINE_MODE -eq 0 ]]; then
        (( count > 10 )) && alert MEDIUM "SYS-006" "zombies" "$count zombie processes"
    fi
    return 0
}

# check_reboot: an unplanned reboot is a security event (load a kernel module,
# wipe memory traces). Compare current boot time to the baseline. Source: btime.
check_reboot() {
    local current previous
    current="$(awk '/^btime/ {print $2}' /proc/stat)"

    if [[ $BASELINE_MODE -eq 1 ]]; then
        echo "$current" | baseline_set "boot_time"
        ok "Baseline: boot time recorded"
        return 0
    fi

    previous="$(baseline_get 'boot_time')"
    if [[ -n "$previous" && "$current" != "$previous" ]]; then
        alert MEDIUM "SYS-007" "reboot" "The machine rebooted on $(date -d "@$current" '+%Y-%m-%d %H:%M')"
        echo "$current" | baseline_set "boot_time"
    fi
    return 0
}

# run_system_health: PUBLIC ENTRY POINT. The only function hids.sh calls.
run_system_health() {
    section "MODULE 1 - SYSTEM HEALTH"
    check_load_average
    check_memory
    check_disk
    check_zombies
    check_reboot
    [[ $QUIET -eq 0 ]] && check_top_processes
    return 0
}