#!/bin/bash
# ==============================================================================
# tools/compliance_report.sh — HTML report mapping alerts to ISO 27001 / NIS2
# No third-party dependency (no jq): parses alerts.jsonl with grep -oP, same
# tool already used in modules/03_process_network.sh.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/../hids.conf"

# Read LOG_DIR from the shared config instead of hard-coding the path here.
[[ -r "$CONFIG_FILE" ]] && source "$CONFIG_FILE"
LOG_DIR="${LOG_DIR:-/var/log/hids}"

ALERT_JSON="$LOG_DIR/alerts.jsonl"
[[ -r "$ALERT_JSON" ]] || ALERT_JSON="$SCRIPT_DIR/../logs/alerts.jsonl"
OUT_FILE="$SCRIPT_DIR/../compliance_report.html"

if [[ ! -r "$ALERT_JSON" ]]; then
    echo "No readable alerts.jsonl found (looked in $LOG_DIR and ./logs). Try: sudo $0" >&2
    exit 1
fi

declare -A MODULE_NAME=(
    [SYS]="System health" [USR]="User activity" [PRC]="Process audit"
    [NET]="Network audit" [FIM]="File integrity"
)
declare -A ISO_CONTROL=(
    [SYS]="A.8.16 Monitoring activities"
    [USR]="A.5.15 Access control / A.8.5 Secure authentication"
    [PRC]="A.8.7 Protection against malware"
    [NET]="A.8.20 Networks security"
    [FIM]="A.8.9 Configuration management / A.8.32 Change management"
)
declare -A NIS2_ARTICLE=(
    [SYS]="21(2)(f) effectiveness assessment"
    [USR]="21(2)(i) access control, HR security"
    [PRC]="21(2)(g) basic cyber hygiene"
    [NET]="21(2)(b) incident handling"
    [FIM]="21(2)(e) security in system maintenance"
)
declare -A SEV_COLOR=(
    [CRITICAL]="#b00020" [HIGH]="#e65100" [MEDIUM]="#f9a825" [INFO]="#1565c0"
)

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"

# extract_field: pull the value of a given JSON key from one alerts.jsonl line.
# Our JSON is always written by alert() in common.sh with the same flat shape,
# so a simple grep -oP is enough — no need for a real JSON parser.
extract_field() {
    local key="$1" line="$2"
    grep -oP "\"${key}\":\"\K[^\"]*" <<< "$line"
}

{
echo "<!DOCTYPE html><html><head><meta charset='utf-8'>"
echo "<title>HIDS Compliance Report</title>"
echo "<style>"
echo "body{font-family:Arial,sans-serif;margin:2em;color:#222}"
echo "h1{border-bottom:3px solid #333;padding-bottom:8px}"
echo "table{border-collapse:collapse;width:100%;margin:1em 0}"
echo "th,td{border:1px solid #ccc;padding:8px 12px;text-align:left}"
echo "th{background:#333;color:#fff}"
echo ".sev-badge{color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold}"
echo "</style></head><body>"
echo "<h1>HIDS Compliance Report</h1>"
echo "<p><b>Host:</b> $HOSTNAME_FQDN<br>"
echo "<b>Generated:</b> $(date '+%Y-%m-%d %H:%M:%S %Z')<br>"
echo "<b>Source:</b> $ALERT_JSON</p>"

echo "<h2>Severity Breakdown</h2><table><tr><th>Severity</th><th>Count</th></tr>"
while IFS= read -r line; do
    extract_field "severity" "$line"
done < "$ALERT_JSON" | sort | uniq -c | sort -rn | while read -r count sev; do
    color="${SEV_COLOR[$sev]:-#666}"
    echo "<tr><td><span class='sev-badge' style='background:$color'>$sev</span></td><td>$count</td></tr>"
done
echo "</table>"

echo "<h2>Module / Control Mapping</h2>"
echo "<table><tr><th>Prefix</th><th>Module</th><th>ISO 27001</th><th>NIS2 Art. 21(2)</th><th>Alerts</th></tr>"
while IFS= read -r line; do
    code="$(extract_field "code" "$line")"
    echo "${code%%-*}"
done < "$ALERT_JSON" | sort | uniq -c | while read -r count prefix; do
    echo "<tr><td>$prefix</td><td>${MODULE_NAME[$prefix]:-Unknown}</td><td>${ISO_CONTROL[$prefix]:-n/a}</td><td>${NIS2_ARTICLE[$prefix]:-n/a}</td><td>$count</td></tr>"
done
echo "</table></body></html>"
} > "$OUT_FILE"

echo "Report written to $OUT_FILE"