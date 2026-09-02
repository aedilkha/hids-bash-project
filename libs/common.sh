#!/bin/bash
# ==============================================================================
# lib/common.sh — HIDS shared core (Module 5: Alerting)
#
# THIS FILE IS THE CONTRACT BETWEEN THE MODULES.
# Only one team member edits it (see TEAM.md). Modules use it, never rewrite it.
#
# Provides:
#   load_config, setup_colors, alert(), section(), kv(), ok(),
#   baseline_get(), baseline_set(), baseline_exists()
# ==============================================================================

# load_config: load hids.conf if present, then apply defaults for anything unset.
load_config() {
    local config_file="${1:-}"

    if [[ -n "$config_file" && -r "$config_file" ]]; then
        source "$config_file"
    fi

    # Paths
    LOG_DIR="${LOG_DIR:-/var/log/hids}"
    STATE_DIR="${STATE_DIR:-/var/lib/hids}"

    # Fall back to a local dir if not root (useful in development).
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        LOG_DIR="$(pwd)/logs"; mkdir -p "$LOG_DIR"
    fi
    if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
        STATE_DIR="$(pwd)/state"; mkdir -p "$STATE_DIR"
    fi

    ALERT_LOG="$LOG_DIR/alerts.log"        # human-readable
    ALERT_JSON="$LOG_DIR/alerts.jsonl"     # one JSON alert per line, parsable
    ALERT_HASH_CHAIN="$LOG_DIR/alerts.sha256"
    touch "$ALERT_LOG" "$ALERT_JSON" "$ALERT_HASH_CHAIN" 2>/dev/null || true
    BASELINE_DIR="$STATE_DIR/baseline"
    mkdir -p "$BASELINE_DIR"

    # Default thresholds (overridable in hids.conf)
    CPU_LOAD_WARN="${CPU_LOAD_WARN:-1.0}"
    CPU_LOAD_CRIT="${CPU_LOAD_CRIT:-2.0}"
    MEM_USED_WARN="${MEM_USED_WARN:-80}"
    MEM_USED_CRIT="${MEM_USED_CRIT:-92}"
    DISK_USED_WARN="${DISK_USED_WARN:-80}"
    DISK_USED_CRIT="${DISK_USED_CRIT:-90}"
    FAILED_LOGIN_WARN="${FAILED_LOGIN_WARN:-20}"
    FAILED_LOGIN_CRIT="${FAILED_LOGIN_CRIT:-50}"

    # Same alert (code + key) re-emitted only after this many seconds.
    ALERT_COOLDOWN="${ALERT_COOLDOWN:-3600}"

    HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
    ALERT_STATE_FILE="$STATE_DIR/alert_state"
    touch "$ALERT_STATE_FILE" 2>/dev/null || true
    touch "$ALERT_HASH_CHAIN" 2>/dev/null || true
    chmod 600 "$ALERT_LOG" "$ALERT_JSON" "$ALERT_HASH_CHAIN" "$ALERT_STATE_FILE" 2>/dev/null || true
}

# setup_colors: colors only if stdout is a terminal and --no-color wasn't passed.
setup_colors() {
    if [[ "${NO_COLOR:-0}" -eq 0 && ( -t 1 || "${FORCE_COLOR:-0}" -eq 1 ) ]]; then
        C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
        C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_GREEN=$'\033[32m'
        C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'
    else
        C_RESET=""; C_BOLD=""; C_DIM=""
        C_RED=""; C_YELLOW=""; C_GREEN=""; C_BLUE=""; C_MAGENTA=""
    fi
}

# json_escape: escape a string so it is safe inside JSON.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/ }"
    s="${s//$'\t'/ }"
    printf '%s' "$s"
}

# is_duplicate: true if this code+key was emitted < ALERT_COOLDOWN seconds ago.
# This is the anti-alert-fatigue mechanism.
is_duplicate() {
    local code="$1" key="$2" now last
    now="$(date +%s)"

    last="$(grep -F "${code}|${key}|" "$ALERT_STATE_FILE" 2>/dev/null | tail -1 | cut -d'|' -f3)"

    if [[ -n "$last" ]] && (( now - last < ALERT_COOLDOWN )); then
        return 0
    fi

    echo "${code}|${key}|${now}" >> "$ALERT_STATE_FILE"
    awk -F'|' -v now="$now" -v ttl="$((ALERT_COOLDOWN * 24))" \
        'now - $3 < ttl' "$ALERT_STATE_FILE" > "${ALERT_STATE_FILE}.tmp" 2>/dev/null \
        && mv "${ALERT_STATE_FILE}.tmp" "$ALERT_STATE_FILE"

    return 1
}

# alert: the single entry point for reporting anything abnormal.
# Usage: alert <SEVERITY> <CODE> <KEY> <MESSAGE>
#   SEVERITY: INFO | MEDIUM | HIGH | CRITICAL
#   CODE:     stable id, per-module prefix (SYS-001, USR-002, ...)
#   KEY:      object concerned (IP, PID, path) — used for dedup
#   MESSAGE:  human-readable sentence
alert() {
    local severity="$1" code="$2" key="$3" message="$4"
    local ts_human ts_iso color label

    ts_human="$(date '+%Y-%m-%d %H:%M:%S')"
    ts_iso="$(date -Iseconds)"

    # CRITICAL alerts are never deduped: we want them on every run until fixed.
    if [[ "$severity" != "CRITICAL" ]] && is_duplicate "$code" "$key"; then
        return 0
    fi

    case "$severity" in
        CRITICAL) color="$C_RED$C_BOLD"; label="CRITICAL" ;;
        HIGH)     color="$C_RED";        label="HIGH    " ;;
        MEDIUM)   color="$C_YELLOW";     label="MEDIUM  " ;;
        *)        color="$C_BLUE";       label="INFO    " ;;
    esac

    # 1. Terminal
    printf '  %s[%s]%s %s %s\n' "$color" "$label" "$C_RESET" "$C_DIM$code$C_RESET" "$message"
    # 2. Text log
    printf '%s %s [%s] %s %s: %s\n' \
        "$ts_human" "$HOSTNAME_FQDN" "$severity" "$code" "$key" "$message" >> "$ALERT_LOG"
    # 3. JSON log (one object per line)
    printf '{"ts":"%s","host":"%s","severity":"%s","code":"%s","key":"%s","message":"%s"}\n' \
        "$ts_iso" "$(json_escape "$HOSTNAME_FQDN")" "$severity" "$code" \
        "$(json_escape "$key")" "$(json_escape "$message")" >> "$ALERT_JSON"

    # 4. Append a tamper-evident SHA-256 chain for every alert record.
    local previous_hash payload encoded_payload record_hash
    previous_hash="$(tail -1 "$ALERT_HASH_CHAIN" 2>/dev/null | awk '{print $1}')"
    payload="${previous_hash}|${ts_iso}|${HOSTNAME_FQDN}|${severity}|${code}|${key}|${message}"
    record_hash="$(printf '%s' "$payload" | sha256sum | awk '{print $1}')"
    encoded_payload="$(printf '%s' "$payload" | base64 -w0)"
    printf '%s\t%s\n' "$record_hash" "$encoded_payload" >> "$ALERT_HASH_CHAIN"

    # 5. Counters for the summary
    case "$severity" in
        CRITICAL) ((ALERT_COUNT_CRITICAL++)) ;;
        HIGH)     ((ALERT_COUNT_HIGH++))     ;;
        MEDIUM)   ((ALERT_COUNT_MEDIUM++))   ;;
        *)        ((ALERT_COUNT_INFO++))     ;;
    esac
}

# section: a section title in the report.
section() {
    printf '\n%s==================================================================%s\n' "$C_BOLD" "$C_RESET"
    printf '%s  %s%s\n' "$C_BOLD" "$1" "$C_RESET"
    printf '%s==================================================================%s\n' "$C_BOLD" "$C_RESET"
}

# kv: an aligned "key   value" line for factual context (not an alert).
kv() {
    printf '  %-26s %s\n' "$1" "$2"
}

# ok: explicitly confirm a check passed.
ok() {
    printf '  %s[OK]%s      %s\n' "$C_GREEN" "$C_RESET" "$1"
}

# baseline_get / baseline_set: read/write a baseline file.
baseline_get() {
    local name="$1"
    [[ -r "$BASELINE_DIR/$name" ]] && cat "$BASELINE_DIR/$name"
}
baseline_set() {
    local name="$1"
    cat > "$BASELINE_DIR/$name"
}

# baseline_exists: true if the requested baseline was already captured.
baseline_exists() {
    [[ -s "$BASELINE_DIR/$1" ]]
}