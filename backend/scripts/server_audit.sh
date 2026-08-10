#!/usr/bin/env bash
# =============================================================================
#  SERVER & WEB SECURITY AUDIT FRAMEWORK  v3.1
#  Covers: Lynis (infrastructure), OWASP ZAP (web), rkhunter (rootkits),
#          Nmap + custom checks (network), SSH, users/auth,
#          Linux service & OS health check (linux_health_check.sh)
#  Output: Single self-contained HTML dashboard report
#  Compatible: Linux (Debian/Ubuntu, RHEL/CentOS/Rocky/Alma/Fedora, SUSE, Arch)
#              and macOS 12+
#
#  PRODUCTION SAFETY:
#   - 100% READ-ONLY. Never modifies system config, never installs packages.
#   - Missing tools are detected and SKIPPED (never silently auto-installed).
#     Use ./install_tools.sh separately (dry-run by default) to stage tools.
#   - Every long-running check is wrapped in a timeout so a hang can never
#     block report generation.
#   - Nmap defaults to a safe top-1000-port / normal-timing scan. Full,
#     aggressive scanning is strictly opt-in via --full-scan.
# =============================================================================

set -uo pipefail

# Trap unexpected exits - still try to generate report with whatever data was collected
_emergency_report() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "" >&2
        echo "[ERROR] Script exited unexpectedly (code $exit_code). Attempting to generate partial report..." >&2
        [[ -d "${TMP_DIR:-}" ]] && generate_html_report 2>/dev/null || true
        echo "[INFO] Check log: ${LOG_FILE:-}" >&2
    fi
}
trap '_emergency_report' EXIT

# ─── CONFIGURATION ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="${SCRIPT_DIR}/audit_reports/${TIMESTAMP}"
HTML_REPORT="${REPORT_DIR}/security_audit_report_${TIMESTAMP}.html"
TMP_DIR="${REPORT_DIR}/tmp"
LOG_FILE="${REPORT_DIR}/audit_run.log"

# Web targets - populated interactively or via CLI flag
WEB_TARGETS=()

# Linux Health Check integration (bundled service/OS health script)
# Override the script location with HEALTH_SCRIPT=... if you keep it elsewhere.
HEALTH_SCRIPT="${HEALTH_SCRIPT:-}"
HEALTH_ENV_FILE=""

# Tool paths (auto-detected, never auto-installed)
LYNIS_BIN=""
ZAP_BIN=""
NMAP_BIN=""
RKHUNTER_BIN=""
TRIVY_BIN=""

# OS detection results (populated by detect_os)
OS_TYPE=""      # linux | darwin | unknown
OS_FAMILY=""    # debian | rhel | suse | arch | mac | unknown
OS_PRETTY=""
PKG_MGR=""      # apt | dnf | yum | zypper | pacman | brew

# Collected tool-status entries (rendered in the dashboard "Tools" tab)
TOOL_STATUS_JSON_ITEMS=()

# Colors for terminal output
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── LOGGING ────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${RESET} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*" | tee -a "$LOG_FILE"; }

# lowercase() without bash4-only ${var,,} so this also runs on macOS's
# stock /bin/bash (3.2, BSD-licensed, no ${var,,} support).
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ─── BANNER ─────────────────────────────────────────────────────────────────
print_banner() {
cat << 'EOF'
 ╔══════════════════════════════════════════════════════════╗
 ║       SERVER & WEB SECURITY AUDIT FRAMEWORK v3.1         ║
 ║  Lynis · ZAP · rkhunter · Nmap · Health · HTML Dashboard ║
 ║              Linux (all major distros) & macOS           ║
 ╚══════════════════════════════════════════════════════════╝
 Read-only. Never installs or changes anything on this system.
EOF
}

# ─── ROOT CHECK ─────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root/sudo (many checks need it: shadow, sudoers, SUID scan, etc)."
        err "Use: sudo $0"
        exit 1
    fi
}

# ─── OS DETECTION ───────────────────────────────────────────────────────────
detect_os() {
    local uname_s
    uname_s="$(uname -s)"
    case "$uname_s" in
        Linux)
            OS_TYPE="linux"
            if [[ -f /etc/os-release ]]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                OS_PRETTY="${PRETTY_NAME:-Linux}"
                local idlike
                idlike="$(lc "${ID:-}${ID_LIKE:-}")"
                case "$idlike" in
                    *debian*|*ubuntu*) OS_FAMILY="debian" ;;
                    *rhel*|*centos*|*fedora*|*rocky*|*alma*) OS_FAMILY="rhel" ;;
                    *suse*) OS_FAMILY="suse" ;;
                    *arch*) OS_FAMILY="arch" ;;
                    *) OS_FAMILY="unknown" ;;
                esac
            else
                OS_PRETTY="Linux (unrecognized distro)"
                OS_FAMILY="unknown"
            fi
            ;;
        Darwin)
            OS_TYPE="darwin"
            OS_FAMILY="mac"
            OS_PRETTY="macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown version')"
            ;;
        *)
            OS_TYPE="unknown"
            OS_FAMILY="unknown"
            OS_PRETTY="$uname_s (unsupported - best effort only)"
            ;;
    esac

    PKG_MGR=""
    case "$OS_FAMILY" in
        debian) command -v apt-get &>/dev/null && PKG_MGR="apt" ;;
        rhel)   command -v dnf &>/dev/null && PKG_MGR="dnf" || { command -v yum &>/dev/null && PKG_MGR="yum"; } ;;
        suse)   command -v zypper &>/dev/null && PKG_MGR="zypper" ;;
        arch)   command -v pacman &>/dev/null && PKG_MGR="pacman" ;;
        mac)    command -v brew &>/dev/null && PKG_MGR="brew" ;;
    esac
}

install_cmd_for() {
    local pkg="$1" brew_pkg="${2:-$1}"
    case "$PKG_MGR" in
        apt)    echo "sudo apt-get update && sudo apt-get install -y $pkg" ;;
        dnf)    echo "sudo dnf install -y $pkg" ;;
        yum)    echo "sudo yum install -y $pkg" ;;
        zypper) echo "sudo zypper install -y $pkg" ;;
        pacman) echo "sudo pacman -S --noconfirm $pkg" ;;
        brew)   echo "brew install $brew_pkg" ;;
        *)      echo "No supported package manager detected - install '$pkg' manually." ;;
    esac
}

# ─── TIMEOUT WRAPPER (portable: GNU timeout / gtimeout / manual fallback) ────
run_with_timeout() {
    local secs="$1"; shift
    if command -v timeout &>/dev/null; then
        timeout --kill-after=10 "$secs" "$@"
    elif command -v gtimeout &>/dev/null; then
        gtimeout --kill-after=10 "$secs" "$@"
    else
        "$@" &
        local pid=$!
        ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) &
        local watchdog=$!
        wait "$pid" 2>/dev/null
        local status=$?
        kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
        return $status
    fi
}

# ─── TOOL STATUS (feeds the dashboard "Tools" tab) ──────────────────────────
json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"
    printf '%s' "$s"
}

add_tool_status() {
    local name="$1" status="$2" path="$3" version="$4" reason="$5" install_cmd="$6"
    TOOL_STATUS_JSON_ITEMS+=("{\"name\":\"$(json_esc "$name")\",\"status\":\"$(json_esc "$status")\",\"path\":\"$(json_esc "$path")\",\"version\":\"$(json_esc "$version")\",\"reason\":\"$(json_esc "$reason")\",\"install_cmd\":\"$(json_esc "$install_cmd")\"}")
}

write_tool_status_json() {
    {
        echo "["
        local n=${#TOOL_STATUS_JSON_ITEMS[@]}
        for i in "${!TOOL_STATUS_JSON_ITEMS[@]}"; do
            printf '  %s' "${TOOL_STATUS_JSON_ITEMS[$i]}"
            [[ $i -lt $((n-1)) ]] && echo "," || echo ""
        done
        echo "]"
    } > "$TMP_DIR/tool_status.json"
    echo "{\"os_pretty\":\"$(json_esc "$OS_PRETTY")\",\"os_type\":\"$(json_esc "$OS_TYPE")\",\"os_family\":\"$(json_esc "$OS_FAMILY")\"}" > "$TMP_DIR/os_info.json"
}

print_tool_status_table() {
    echo ""
    echo -e "${BOLD}═══ Tool Availability (detected OS: ${OS_PRETTY}) ═══${RESET}"
    python3 - "$TMP_DIR/tool_status.json" <<'PYEOF'
import json, sys
data = json.load(open(sys.argv[1]))
for t in data:
    if t["status"] == "found":
        print(f"  [OK]      {t['name']:<12} {t.get('path') or ''} {t.get('version') or ''}".rstrip())
    else:
        print(f"  [SKIPPED] {t['name']:<12} install with: {t.get('install_cmd') or 'see docs'}")
PYEOF
    echo ""
}

# ─── DEPENDENCY DETECTION (never installs anything) ─────────────────────────
detect_tools() {
    has_jq() {
    command -v jq &>/dev/null
}

log "Detecting installed security tools on $OS_PRETTY ..."

    # Lynis
    for p in /usr/bin/lynis /usr/local/bin/lynis /usr/sbin/lynis /opt/homebrew/bin/lynis "$HOME/lynis/lynis"; do
        [[ -x "$p" ]] && { LYNIS_BIN="$p"; break; }
    done
    [[ -z "$LYNIS_BIN" ]] && command -v lynis &>/dev/null && LYNIS_BIN="$(command -v lynis)"
    if [[ -n "$LYNIS_BIN" ]]; then
        ok "Lynis found: $LYNIS_BIN"
        add_tool_status "Lynis" "found" "$LYNIS_BIN" "$("$LYNIS_BIN" --version 2>/dev/null || echo 'unknown')" "" ""
    else
        warn "Lynis not found - infrastructure hardening scan will be SKIPPED."
        add_tool_status "Lynis" "skipped" "" "" "Not installed" "$(install_cmd_for lynis lynis)"
    fi

    # Nmap
    command -v nmap &>/dev/null && NMAP_BIN="$(command -v nmap)"
    if [[ -n "$NMAP_BIN" ]]; then
        ok "Nmap found: $NMAP_BIN"
        add_tool_status "Nmap" "found" "$NMAP_BIN" "$("$NMAP_BIN" --version 2>/dev/null | head -1)" "" ""
    else
        warn "nmap not found - active port scan will be SKIPPED (listening-socket data still collected)."
        add_tool_status "Nmap" "skipped" "" "" "Not installed" "$(install_cmd_for nmap nmap)"
    fi

    # rkhunter (rootkit scan)
    if [[ -z "$RKHUNTER_BIN" ]]; then
        command -v rkhunter &>/dev/null && RKHUNTER_BIN="$(command -v rkhunter)"
    fi
    if [[ -n "$RKHUNTER_BIN" ]]; then
        ok "rkhunter found: $RKHUNTER_BIN"
        add_tool_status "rkhunter" "found" "$RKHUNTER_BIN" "" "" ""
    else
        warn "rkhunter not found - rootkit scan will be SKIPPED."
        add_tool_status "rkhunter" "skipped" "" "" "Not installed" "$(install_cmd_for rkhunter rkhunter)"
    fi

    # OWASP ZAP (native or docker)
    for p in /usr/bin/zap.sh /opt/zaproxy/zap.sh /usr/local/bin/zap.sh /usr/share/zaproxy/zap.sh \
             "$HOME/ZAP/zap.sh" /Applications/ZAP.app/Contents/Java/zap.sh /opt/homebrew/bin/zap.sh; do
        [[ -x "$p" ]] && { ZAP_BIN="$p"; break; }
    done
    if [[ -z "$ZAP_BIN" ]] && command -v docker &>/dev/null; then
        docker image inspect ghcr.io/zaproxy/zaproxy:stable &>/dev/null 2>&1 && ZAP_BIN="docker_zap"
    fi
    if [[ -n "$ZAP_BIN" ]]; then
        ok "OWASP ZAP found ($ZAP_BIN)"
        add_tool_status "OWASP ZAP" "found" "$ZAP_BIN" "" "" ""
    else
        warn "OWASP ZAP not found (native binary or docker image) - web app scan will be SKIPPED."
        local zap_hint
        if command -v docker &>/dev/null; then
            zap_hint="docker pull ghcr.io/zaproxy/zaproxy:stable"
        else
            zap_hint="Install Docker, then: docker pull ghcr.io/zaproxy/zaproxy:stable"
        fi
        add_tool_status "OWASP ZAP" "skipped" "" "" "No native binary or docker image" "$zap_hint"
    fi

    # Trivy (vulnerability scanner for kernel packages)
    command -v trivy &>/dev/null && TRIVY_BIN="$(command -v trivy)"
    if [[ -n "$TRIVY_BIN" ]]; then
        ok "Trivy found: $TRIVY_BIN"
        add_tool_status "Trivy" "found" "$TRIVY_BIN" "$("$TRIVY_BIN" --version 2>/dev/null | head -1)" "" ""
        if has_jq; then
            ok "jq found for filtering Trivy results"
            add_tool_status "jq" "found" "$(command -v jq)" "$(jq --version 2>/dev/null || echo 'unknown')" "" ""
        else
            warn "jq not found - Trivy kernel filtering requires jq (install with: $(install_cmd_for jq jq))"
            add_tool_status "jq" "skipped" "" "" "Not installed" "$(install_cmd_for jq jq)"
        fi
    else
        warn "Trivy not found - kernel vulnerability scan will be SKIPPED."
        add_tool_status "Trivy" "skipped" "" "" "Not installed" "$(install_cmd_for trivy trivy)"
    fi

    # Linux Health Check (bundled service/OS health script)
    if [[ -z "$HEALTH_SCRIPT" ]]; then
        for p in "${SCRIPT_DIR}/linux-health/linux_health_check.sh" "${SCRIPT_DIR}/linux_health_check.sh"; do
            [[ -f "$p" ]] && { HEALTH_SCRIPT="$p"; break; }
        done
    fi
    if [[ "$OS_TYPE" != "linux" ]]; then
        warn "Linux Health Check is Linux-only - will be SKIPPED on $OS_PRETTY."
        add_tool_status "Health Check" "skipped" "" "" "Linux-only (needs bash 4, systemd, ss)" "Run this audit on a Linux host to include it"
    elif [[ -n "$HEALTH_SCRIPT" && -f "$HEALTH_SCRIPT" ]]; then
        ok "Linux Health Check found: $HEALTH_SCRIPT"
        add_tool_status "Health Check" "found" "$HEALTH_SCRIPT" "" "" ""
    else
        warn "linux_health_check.sh not found - service/OS health section will be SKIPPED."
        add_tool_status "Health Check" "skipped" "" "" "Script not found" "Place linux_health_check.sh in ${SCRIPT_DIR}/linux-health/"
    fi

    write_tool_status_json
    ok "Tool detection complete."
}

# ─── INTERACTIVE WEB TARGET COLLECTION ──────────────────────────────────────
collect_web_targets() {
    echo ""
    echo -e "${BOLD}═══ WEB APPLICATION SCAN CONFIGURATION ═══${RESET}"
    echo ""

    if [[ ${#WEB_TARGETS[@]} -gt 0 ]]; then
        log "Web targets provided via CLI: ${WEB_TARGETS[*]}"
        return
    fi

    if [[ -z "$ZAP_BIN" ]]; then
        warn "OWASP ZAP not available - skipping web target collection."
        return
    fi

    echo "Enter the URLs/IPs you want to scan with OWASP ZAP."
    echo "Examples: https://example.com  |  http://192.168.1.10  |  https://app.example.com"
    echo "(Press ENTER on empty line when done)"
    echo ""

    local idx=1
    while true; do
        read -rp "  Target #${idx} (or press ENTER to finish): " url
        [[ -z "$url" ]] && break

        if [[ ! "$url" =~ ^https?:// ]]; then
            warn "URL must start with http:// or https:// - skipping: $url"
            continue
        fi

        WEB_TARGETS+=("$url")
        ok "Added: $url"
        ((idx++))
    done

    if [[ ${#WEB_TARGETS[@]} -eq 0 ]]; then
        warn "No web targets entered. Web application scan will be skipped."
    else
        log "Total web targets: ${#WEB_TARGETS[@]}"
    fi
    echo ""
}

# ─── COLLECT SYSTEM INFO (OS-aware) ──────────────────────────────────────────
collect_system_info() {
    log "Collecting system information..."
    mkdir -p "$TMP_DIR"

    uname -a > "$TMP_DIR/uname.txt" 2>/dev/null || true

    if [[ "$OS_TYPE" == "darwin" ]]; then
        { sw_vers; echo; system_profiler SPSoftwareDataType 2>/dev/null; } > "$TMP_DIR/os_release.txt" 2>/dev/null || true
        { scutil --get ComputerName 2>/dev/null || hostname; } > "$TMP_DIR/hostname.txt"
        uptime > "$TMP_DIR/uptime.txt" 2>/dev/null || true
        sysctl -n machdep.cpu.brand_string > "$TMP_DIR/lscpu.txt" 2>/dev/null || true
        { echo "Physical Memory:"; sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.2f GB\n", $1/1073741824}'; echo; vm_stat 2>/dev/null; } > "$TMP_DIR/memory.txt"
        df -h > "$TMP_DIR/disk.txt" 2>/dev/null || true
        ifconfig > "$TMP_DIR/network_config.txt" 2>/dev/null || true
        { lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null; lsof -nP -iUDP 2>/dev/null; } > "$TMP_DIR/listening_ports.txt" || true
        netstat -an -p tcp 2>/dev/null | head -30 > "$TMP_DIR/connections.txt" || true
        netstat -rn > "$TMP_DIR/routes.txt" 2>/dev/null || true
        {
            echo "--- Application Firewall (socketfilterfw) ---"
            /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unavailable"
            echo ""
            echo "--- pf packet filter rules (if active) ---"
            pfctl -sr 2>/dev/null || echo "pf not active, or requires root"
        } > "$TMP_DIR/iptables.txt"
        launchctl list > "$TMP_DIR/running_services.txt" 2>/dev/null || true
        last -20 > "$TMP_DIR/last_logins.txt" 2>/dev/null || true
        dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500{print}' > "$TMP_DIR/users.txt" || true
        { echo "macOS has no /etc/sudoers-equivalent central file by default; admin rights are via the 'admin' group."; grep -v "^#" /etc/sudoers 2>/dev/null; } > "$TMP_DIR/sudoers.txt"
        find /Users -maxdepth 3 -name ".ssh" -type d 2>/dev/null > "$TMP_DIR/ssh_dirs.txt" || true
        ps aux -r 2>/dev/null | head -20 > "$TMP_DIR/top_processes.txt" || true
        cat /etc/ssh/sshd_config > "$TMP_DIR/sshd_config.txt" 2>/dev/null || true
        run_with_timeout 60 find /usr /opt /Users /etc /Applications -perm -0002 -type f 2>/dev/null | head -50 > "$TMP_DIR/world_writable.txt" || true
        run_with_timeout 60 find /usr /opt /Users /etc /Applications \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > "$TMP_DIR/suid_sgid.txt" || true
        { crontab -l 2>/dev/null; echo "--- launchd (system daemons/agents) ---"; ls -la /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null; } > "$TMP_DIR/cron.txt" || true
    else
        cat /etc/os-release > "$TMP_DIR/os_release.txt" 2>/dev/null || true
        { hostnamectl 2>/dev/null || hostname; } > "$TMP_DIR/hostname.txt"
        uptime > "$TMP_DIR/uptime.txt" 2>/dev/null || true
        lscpu > "$TMP_DIR/lscpu.txt" 2>/dev/null || true
        free -h > "$TMP_DIR/memory.txt" 2>/dev/null || true
        df -h > "$TMP_DIR/disk.txt" 2>/dev/null || true
        { ip addr show 2>/dev/null || ifconfig 2>/dev/null; } > "$TMP_DIR/network_config.txt" || true
        { ss -tlnpu 2>/dev/null || netstat -tlnpu 2>/dev/null; } > "$TMP_DIR/listening_ports.txt" || true
        ss -tnp > "$TMP_DIR/connections.txt" 2>/dev/null || true
        { ip route 2>/dev/null || route -n 2>/dev/null; } > "$TMP_DIR/routes.txt" || true
        iptables -L -n -v > "$TMP_DIR/iptables.txt" 2>/dev/null || true
        command -v firewall-cmd &>/dev/null && firewall-cmd --list-all >> "$TMP_DIR/iptables.txt" 2>/dev/null
        command -v ufw &>/dev/null && ufw status verbose >> "$TMP_DIR/iptables.txt" 2>/dev/null
        systemctl list-units --type=service --state=running --no-pager > "$TMP_DIR/running_services.txt" 2>/dev/null || true
        last -n 20 > "$TMP_DIR/last_logins.txt" 2>/dev/null || true
        awk -F: '$3>=1000 && $3<65534{print}' /etc/passwd > "$TMP_DIR/users.txt" 2>/dev/null || true
        grep -v "^#" /etc/sudoers > "$TMP_DIR/sudoers.txt" 2>/dev/null || true
        find /home -name ".ssh" -type d > "$TMP_DIR/ssh_dirs.txt" 2>/dev/null || true
        ps aux --sort=-%cpu 2>/dev/null | head -20 > "$TMP_DIR/top_processes.txt" || true
        cat /etc/ssh/sshd_config > "$TMP_DIR/sshd_config.txt" 2>/dev/null || true
        run_with_timeout 60 find / -xdev -perm -0002 -type f -not -path "/proc/*" 2>/dev/null | head -50 > "$TMP_DIR/world_writable.txt" || true
        run_with_timeout 60 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > "$TMP_DIR/suid_sgid.txt" || true
        for dir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
            ls -la "$dir" 2>/dev/null >> "$TMP_DIR/cron.txt"
        done
        crontab -l >> "$TMP_DIR/cron.txt" 2>/dev/null || true
    fi

    ok "System information collected."
}

# ─── LYNIS SCAN ──────────────────────────────────────────────────────────────
run_lynis() {
    if [[ -z "$LYNIS_BIN" ]]; then
        warn "Skipping Lynis scan (not installed)."
        echo "Lynis not available - install with: $(install_cmd_for lynis lynis)" > "$TMP_DIR/lynis_report.txt"
        return
    fi

    log "Running Lynis infrastructure audit (timeout 10 min)..."
    run_with_timeout 600 "$LYNIS_BIN" audit system \
        --no-colors \
        --logfile "$TMP_DIR/lynis.log" \
        --report-file "$TMP_DIR/lynis_report.dat" \
        > "$TMP_DIR/lynis_report.txt" 2>&1 || true

    if [[ -f "$TMP_DIR/lynis_report.dat" ]]; then
        grep -E "^(warning|suggestion|hardening_index)" "$TMP_DIR/lynis_report.dat" > "$TMP_DIR/lynis_parsed.txt" 2>/dev/null || true
    fi

    ok "Lynis scan complete."
}

# ─── RKHUNTER SCAN ───────────────────────────────────────────────────────────
run_rkhunter() {
    if [[ -z "$RKHUNTER_BIN" ]]; then
        warn "Skipping rkhunter scan (not installed)."
        echo "rkhunter not available - install with: $(install_cmd_for rkhunter rkhunter)" > "$TMP_DIR/rkhunter_report.txt"
        return
    fi

    log "Running rkhunter rootkit scan (timeout 10 min)..."
    run_with_timeout 600 "$RKHUNTER_BIN" --check --sk --nocolors --no-mail-on-warning \
        > "$TMP_DIR/rkhunter_report.txt" 2>&1 || true
    ok "rkhunter scan complete."
}

# ─── NMAP SCAN (safe-by-default) ─────────────────────────────────────────────
run_nmap() {
    if [[ -z "$NMAP_BIN" ]]; then
        warn "Skipping nmap scan (not installed)."
        echo "nmap not available - install with: $(install_cmd_for nmap nmap)" > "$TMP_DIR/nmap_report.txt"
        return
    fi

    local nmap_args=(-sV --open -T3 --top-ports 1000)
    local scan_desc="safe default: top 1000 ports, normal (-T3) timing, no OS fingerprinting"
    if [[ "${FULL_SCAN:-false}" == "true" ]]; then
        nmap_args=(-sV -sC -O --osscan-guess --open -p- -T4)
        scan_desc="--full-scan requested: ALL 65535 ports, aggressive (-T4) timing, OS detection"
    fi

    log "Running nmap port scan on localhost ($scan_desc, timeout 30 min)..."
    if command -v nice &>/dev/null; then
        run_with_timeout 1800 nice -n 19 "$NMAP_BIN" "${nmap_args[@]}" -oN "$TMP_DIR/nmap_report.txt" 127.0.0.1 2>>"$LOG_FILE" || true
    else
        run_with_timeout 1800 "$NMAP_BIN" "${nmap_args[@]}" -oN "$TMP_DIR/nmap_report.txt" 127.0.0.1 2>>"$LOG_FILE" || true
    fi

    ok "nmap scan complete."
}

# ─── OWASP ZAP SCAN ──────────────────────────────────────────────────────────
run_zap() {
    if [[ ${#WEB_TARGETS[@]} -eq 0 ]]; then
        warn "No web targets - skipping ZAP scan."
        return
    fi

    if [[ -z "$ZAP_BIN" ]]; then
        warn "ZAP not installed - skipping web scan."
        return
    fi

    mkdir -p "$TMP_DIR/zap"

    for target in "${WEB_TARGETS[@]}"; do
        local safe_name
        safe_name="$(echo "$target" | sed 's|https\{0,1\}://||; s|[^a-zA-Z0-9._-]|_|g')"
        local zap_out="$TMP_DIR/zap/${safe_name}"
        mkdir -p "$zap_out"

        log "Running ZAP baseline (passive) scan on: $target (timeout 15 min)"

        if [[ "$ZAP_BIN" == "docker_zap" ]]; then
            run_with_timeout 900 docker run --rm \
                -v "$zap_out":/zap/wrk/:rw \
                ghcr.io/zaproxy/zaproxy:stable \
                zap-baseline.py \
                -t "$target" \
                -r "zap_report.html" \
                -J "zap_report.json" \
                -x "zap_report.xml" \
                --auto 2>>"$LOG_FILE" || true
        else
            run_with_timeout 900 "$ZAP_BIN" \
                -cmd \
                -quickurl "$target" \
                -quickprogress \
                -quickout "$zap_out/zap_report.xml" \
                2>>"$LOG_FILE" || true
        fi

        ok "ZAP scan complete for: $target"
    done
}

# ─── CUSTOM NETWORK SECURITY CHECKS (OS-aware) ───────────────────────────────
run_network_checks() {
    log "Running custom network security checks..."
    local out="$TMP_DIR/network_security.txt"

    {
        echo "=== NETWORK SECURITY ASSESSMENT ($OS_PRETTY) ==="
        echo "Generated: $(date)"
        echo ""

        echo "--- Open Ports (listening) ---"
        if [[ "$OS_TYPE" == "darwin" ]]; then
            lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || echo "lsof unavailable"
        else
            ss -tlnpu 2>/dev/null || netstat -tlnpu 2>/dev/null || echo "ss/netstat unavailable"
        fi
        echo ""

        echo "--- Active Network Connections ---"
        if [[ "$OS_TYPE" == "darwin" ]]; then
            netstat -an -p tcp 2>/dev/null | head -30 || echo "unavailable"
        else
            ss -tnp 2>/dev/null | head -30 || echo "unavailable"
        fi
        echo ""

        echo "--- Firewall Rules ---"
        if [[ "$OS_TYPE" == "darwin" ]]; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "Application Firewall status unavailable"
            pfctl -sr 2>/dev/null || echo "pf rules unavailable (requires root, or pf inactive)"
        else
            iptables -L -n -v 2>/dev/null || echo "iptables unavailable"
        fi
        echo ""

        if [[ "$OS_TYPE" != "darwin" ]]; then
            echo "--- IPv6 Firewall (ip6tables) ---"
            ip6tables -L -n 2>/dev/null || echo "ip6tables unavailable"
            echo ""
        fi

        echo "--- Routing Table ---"
        if [[ "$OS_TYPE" == "darwin" ]]; then
            netstat -rn 2>/dev/null || echo "unavailable"
        else
            ip route 2>/dev/null || route -n 2>/dev/null || echo "unavailable"
        fi
        echo ""

        echo "--- ARP Cache ---"
        arp -an 2>/dev/null || ip neigh 2>/dev/null || echo "unavailable"
        echo ""

        echo "--- DNS Configuration ---"
        cat /etc/resolv.conf 2>/dev/null || echo "unavailable"
        echo ""

        echo "--- /etc/hosts ---"
        cat /etc/hosts 2>/dev/null
        echo ""

        echo "--- Network Interfaces ---"
        if [[ "$OS_TYPE" == "darwin" ]]; then
            ifconfig 2>/dev/null || echo "unavailable"
        else
            ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "unavailable"
        fi
        echo ""

        if [[ "$OS_TYPE" != "darwin" ]]; then
            echo "--- TCP Kernel Parameters ---"
            sysctl net.ipv4 2>/dev/null | grep -E "syn_cookies|tcp_syncookies|forwarding|rp_filter|accept_redirects|send_redirects|icmp_echo|log_martians" || echo "sysctl unavailable"
            echo ""
        fi

        echo "--- Hosts.allow / Hosts.deny ---"
        echo "[hosts.allow]"; cat /etc/hosts.allow 2>/dev/null || echo "not configured"
        echo "[hosts.deny]";  cat /etc/hosts.deny  2>/dev/null || echo "not configured"

    } > "$out" 2>&1

    ok "Network security checks complete."
}

# ─── SSH SECURITY CHECK ───────────────────────────────────────────────────────
run_ssh_checks() {
    log "Running SSH security checks..."
    local out="$TMP_DIR/ssh_audit.txt"
    local cfg="/etc/ssh/sshd_config"

    {
        echo "=== SSH SECURITY ASSESSMENT ==="
        echo ""

        if [[ ! -f "$cfg" ]]; then
            echo "sshd_config not found"
        else
            echo "--- Key SSH Settings ---"
            grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|\
MaxAuthTries|AllowTcpForwarding|X11Forwarding|LogLevel|UseDNS|PermitEmptyPasswords|\
Protocol|ClientAliveInterval|ClientAliveCountMax|MaxSessions|AllowAgentForwarding|\
TCPKeepAlive|Banner)" "$cfg" 2>/dev/null | sort

            echo ""
            echo "--- Security Analysis ---"
            local issues=0
            local cfg_lower
            cfg_lower="$(lc "$(cat "$cfg" 2>/dev/null)")"

            check_ssh_param() {
                local param="$1" bad_val="$2" msg="$3"
                local val
                val=$(grep -i "^${param}" "$cfg" 2>/dev/null | awk '{print $2}' | head -1)
                if [[ -z "$val" || "$(lc "$val")" == "$(lc "$bad_val")" ]]; then
                    echo "[RISK] $msg (current: ${val:-default})"
                    issues=$((issues+1))
                else
                    echo "[OK]   $msg (current: $val)"
                fi
            }

            check_ssh_param "PermitRootLogin"         "yes"  "PermitRootLogin should be 'no' or 'prohibit-password'"
            check_ssh_param "PasswordAuthentication"  "yes"  "PasswordAuthentication should be 'no'"
            check_ssh_param "X11Forwarding"           "yes"  "X11Forwarding should be 'no'"
            check_ssh_param "AllowTcpForwarding"      "yes"  "AllowTcpForwarding should be 'no'"
            check_ssh_param "PermitEmptyPasswords"    "yes"  "PermitEmptyPasswords should be 'no'"

            local port
            port=$(grep -i "^Port " "$cfg" 2>/dev/null | awk '{print $2}' | head -1)
            [[ "${port:-22}" == "22" ]] && { echo "[WARN] SSH running on default port 22"; issues=$((issues+1)); }

            local max_auth
            max_auth=$(grep -i "^MaxAuthTries" "$cfg" 2>/dev/null | awk '{print $2}' | head -1)
            [[ -z "$max_auth" || "$max_auth" -gt 3 ]] && { echo "[WARN] MaxAuthTries should be <= 3 (current: ${max_auth:-default 6})"; issues=$((issues+1)); }

            echo ""
            echo "Total SSH issues found: $issues"
        fi

    } > "$out" 2>&1

    ok "SSH checks complete."
}

# ─── USER & AUTH CHECK (OS-aware) ────────────────────────────────────────────
run_user_checks() {
    log "Running user & authentication checks..."
    local out="$TMP_DIR/user_audit.txt"
    {
        echo "=== USER & AUTHENTICATION ASSESSMENT ($OS_PRETTY) ==="
        echo ""

        if [[ "$OS_TYPE" == "darwin" ]]; then
            echo "--- Users with UID >= 500 (non-system) ---"
            dscl . -list /Users UniqueID 2>/dev/null | awk '$2>=500{print $1, $2}'
            echo ""
            echo "--- Members of 'admin' group (sudo-equivalent) ---"
            dscl . -read /Groups/admin GroupMembership 2>/dev/null || echo "unavailable"
            echo ""
            echo "--- Password policy ---"
            echo "macOS has no /etc/shadow; password aging is managed via pwpolicy(1) or MDM."
            pwpolicy -getaccountpolicies 2>/dev/null | head -30 || echo "pwpolicy data unavailable (requires root / no policy set)"
            echo ""
            echo "--- Recent logins (last 20) ---"
            last -20 2>/dev/null || echo "unavailable"
            echo ""
            echo "--- Failed login attempts (unified log, last 24h) ---"
            run_with_timeout 15 log show --predicate 'eventMessage contains "authentication failure"' --last 1d 2>/dev/null | tail -20 || \
                echo "unavailable (grant Terminal 'Full Disk Access' in System Settings to enable this check)"
        else
            echo "--- Users with UID >= 1000 (non-system) ---"
            awk -F: '$3>=1000 && $3<65534{print $1, $3, $6, $7}' /etc/passwd 2>/dev/null | column -t
            echo ""
            echo "--- Users with empty/locked passwords ---"
            awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow 2>/dev/null || echo "(requires root or shadow access)"
            echo ""
            echo "--- Users with UID=0 (root privileges) ---"
            awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
            echo ""
            echo "--- Sudoers ---"
            grep -v "^#\|^$" /etc/sudoers 2>/dev/null | head -30 || echo "unavailable"
            echo ""
            echo "--- Recent logins (last 20) ---"
            last -n 20 2>/dev/null || echo "unavailable"
            echo ""
            echo "--- Failed login attempts ---"
            grep "Failed password" /var/log/secure 2>/dev/null | tail -20 || \
            grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || \
            echo "No failed login log found"
            echo ""
            echo "--- Password policy (/etc/login.defs) ---"
            grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)" /etc/login.defs 2>/dev/null || echo "unavailable"
        fi

    } > "$out" 2>&1

    ok "User checks complete."
}

# ─── LINUX SERVICE & OS HEALTH CHECK (linux_health_check.sh) ─────────────────
# Runs the bundled health-check script non-interactively and drops its CSV
# into the shared tmp dir so gen_report.py can merge it into the dashboard.
# The health script itself is READ-ONLY (it only inspects configs/services).
run_health_check() {
    if [[ "$OS_TYPE" != "linux" ]]; then
        warn "Skipping Linux Health Check (Linux-only)."
        return
    fi
    if [[ -z "$HEALTH_SCRIPT" || ! -f "$HEALTH_SCRIPT" ]]; then
        warn "Skipping Linux Health Check (linux_health_check.sh not found)."
        echo "linux_health_check.sh not found - place it in ${SCRIPT_DIR}/linux-health/" > "$TMP_DIR/health_check.csv"
        return
    fi

    log "Running Linux service & OS health check (timeout 15 min)..."

    # Optional user config: service selection, DB credentials, WEB_DOMAIN, etc.
    if [[ -n "$HEALTH_ENV_FILE" ]]; then
        if [[ -f "$HEALTH_ENV_FILE" ]]; then
            log "Loading health-check config from: $HEALTH_ENV_FILE"
            set -a
            # shellcheck disable=SC1090
            . "$HEALTH_ENV_FILE"
            set +a
        else
            warn "--health-env file not found: $HEALTH_ENV_FILE (using defaults)"
        fi
    fi

    # Derive WEB_DOMAIN (for its SSL check) from the first ZAP target if unset
    if [[ -z "${WEB_DOMAIN:-}" && ${#WEB_TARGETS[@]} -gt 0 ]]; then
        WEB_DOMAIN="$(printf '%s' "${WEB_TARGETS[0]}" | sed 's|https\{0,1\}://||; s|/.*||; s|:.*||')"
        log "Health check WEB_DOMAIN derived from web target: $WEB_DOMAIN"
    fi

    # Run inside TMP_DIR with a RELATIVE output filename: the health script's
    # redirections break on paths containing spaces, and running there also
    # guarantees no stray .env file can override our settings. stdin comes
    # from /dev/null so it can never sit waiting on a prompt (cron-safe).
    (
        cd "$TMP_DIR" && \
        SERVICE_INPUT="${HEALTH_SERVICES:-${SERVICE_INPUT:-all}}" \
        CATEGORY_INPUT="${HEALTH_CATEGORIES:-${CATEGORY_INPUT:-all}}" \
        OUTPUT="health_check.csv" \
        WEB_DOMAIN="${WEB_DOMAIN:-}" \
        MONGO_USER="${MONGO_USER:-}" MONGO_PASS="${MONGO_PASS:-}" MONGO_DB="${MONGO_DB:-admin}" \
        MYSQL_USER="${MYSQL_USER:-}" MYSQL_PASS="${MYSQL_PASS:-}" MYSQL_DB="${MYSQL_DB:-mysql}" \
        run_with_timeout 900 bash "$HEALTH_SCRIPT" </dev/null
    ) >> "$LOG_FILE" 2>&1 || true

    if [[ -s "$TMP_DIR/health_check.csv" ]]; then
        ok "Health check complete: $TMP_DIR/health_check.csv"
    else
        warn "Health check produced no output - check $LOG_FILE"
    fi
}

# ─── TRIVY KERNEL VULNERABILITY SCAN ────────────────────────────────────────────
run_trivy_kernel_scan() {
    if [[ -z "$TRIVY_BIN" ]]; then
        warn "Skipping Trivy kernel vulnerability scan (not installed)."
        echo "Trivy not available - install with: $(install_cmd_for trivy trivy)" > "$TMP_DIR/trivy-kernel-vulns.json"
        return
    fi

    if ! has_jq; then
        warn "jq not found - skipping Trivy kernel scan (jq is needed to filter kernel packages)."
        echo "jq not available - install with: $(install_cmd_for jq jq)" > "$TMP_DIR/trivy-kernel-vulns.json"
        return
    fi

    log "Running Trivy vulnerability scan for kernel packages (timeout 15 min)..."

    # Full rootfs scan, skipping noisy dirs, outputting JSON.
    # --timeout is important: trivy's DEFAULT internal timeout is 5 minutes,
    # which the very first run on a server will blow past while it downloads
    # its vulnerability DB (100MB+) — the scan then aborts before writing any
    # output. 900s matches the run_with_timeout wrapper below, so the kill
    # decision stays with our own timeout.
    local trivy_raw="$TMP_DIR/trivy-report.json"
    run_with_timeout 900 "$TRIVY_BIN" rootfs \
        --scanners vuln \
        --timeout 900s \
        --skip-java-db-update \
        --skip-dirs /home \
        --skip-dirs /var/lib/docker \
        --skip-dirs /opt \
        --severity HIGH,CRITICAL \
        --exit-code 0 \
        --format json \
        -o "$trivy_raw" \
        / 2>>"$LOG_FILE" || true

    if [[ ! -f "$trivy_raw" ]]; then
        warn "Trivy scan produced no output - check $LOG_FILE"
        return
    fi

    log "Filtering kernel-related vulnerabilities from Trivy results..."
    # Filter kernel-related packages: any package whose name starts with
    # "linux" or "kernel" (e.g. linux, linux-image-*, linux-firmware,
    # linux-base, kernel-core, kernel-devel, etc.).
    local filtered="$TMP_DIR/kernel-vulnerabilities.json"
    jq '
        [
            .Results[]
            | select(.Class=="os-pkgs")
            | .Vulnerabilities[]
            | select(
                (.PkgName | test("^(linux|kernel)"))
                and
                (.Severity == "HIGH" or .Severity == "CRITICAL")
            )
        ]
    ' "$trivy_raw" > "$filtered" 2>>"$LOG_FILE"

    if [[ -s "$filtered" ]]; then
        local vuln_count
        vuln_count=$(jq 'length' "$filtered" 2>/dev/null || echo 0)
        ok "Trivy kernel vulnerability scan complete: $vuln_count kernel vulnerabilities found (HIGH/CRITICAL)."
    else
        # Write a minimal empty array so gen_report.py can still parse it
        echo '[]' > "$filtered"
        ok "Trivy kernel vulnerability scan complete: no kernel-related vulnerabilities found."
    fi
}

# ─── GENERATE HTML REPORT ─────────────────────────────────────────────────────
generate_html_report() {
    log "Generating HTML security dashboard report..."

    local targets_env=""
    for t in "${WEB_TARGETS[@]:-}"; do
        [[ -z "${t:-}" ]] && continue
        targets_env+="${t}"$'\0'
    done

    TMP_DIR="$TMP_DIR" \
    HTML_REPORT="$HTML_REPORT" \
    TIMESTAMP="$TIMESTAMP" \
    WEB_TARGETS="${targets_env}" \
    python3 "$(dirname "${BASH_SOURCE[0]}")/gen_report.py" 2>>"$LOG_FILE" || {
        TMP_DIR="$TMP_DIR" \
        HTML_REPORT="$HTML_REPORT" \
        TIMESTAMP="$TIMESTAMP" \
        WEB_TARGETS="${targets_env}" \
        python3 "${SCRIPT_DIR}/gen_report.py" 2>>"$LOG_FILE"
    }

    if [[ -f "$HTML_REPORT" ]]; then
        ok "HTML report written to: $HTML_REPORT"
    else
        err "Report generation failed. Check: $LOG_FILE"
    fi
}

# ─── USAGE ───────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Server & Web Security Audit Framework v3.0 (Linux & macOS)

Usage: sudo $0 [OPTIONS]

Options:
  -u URL          Add web target URL for ZAP scan (repeatable)
  -s              Non-interactive mode (skip prompts)
  -o DIR          Custom output directory
  -n              Skip nmap scan
  -z              Skip ZAP scan
  -l              Skip Lynis scan
  -r              Skip rkhunter scan
  -t              Skip Trivy kernel vulnerability scan
  -H              Skip the Linux service & OS health check
  --health-env F  Load health-check config from file F (service selection,
                  DB credentials, WEB_DOMAIN - see linux-health/health.env.example)
  --full-scan     Full 1-65535 port nmap scan with OS detection & aggressive
                  timing (default is safe: top 1000 ports, normal timing)
  --check         Only detect/print tool availability, then exit (no scan)
  -h, --help      Show this help

Health check env vars (alternative to --health-env):
  HEALTH_SERVICES     e.g. "1 3 5" or "all"  (nginx/freeswitch/opensips/haproxy/
                      mongodb/rabbitmq/mysql - defaults to "all")
  HEALTH_CATEGORIES   e.g. "1 4" or "all"    (OS / app-global / sendmail /
                      security-enhancement - defaults to "all")

This script is READ-ONLY: it never installs packages or changes system
configuration. To stage missing tools, run ./install_tools.sh separately
(it defaults to a dry run and only acts with --yes).

Examples:
  sudo $0                                  # infra + network + user checks
  sudo $0 --check                          # just show what's installed
  sudo $0 -u https://example.com           # + web app scan
  sudo $0 -u https://example.com -s -o /var/reports
  sudo $0 --full-scan -u https://example.com
  sudo $0 -n -z                            # Lynis + system checks only
EOF
    exit 0
}

# ─── MAIN ────────────────────────────────────────────────────────────────────
main() {
    local skip_interactive=false skip_nmap=false skip_zap=false skip_lynis=false skip_rkhunter=false skip_trivy=false skip_health=false check_only=false
    FULL_SCAN=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u) WEB_TARGETS+=("${2:?missing URL for -u}"); shift 2 ;;
            -s) skip_interactive=true; shift ;;
            -o) REPORT_DIR="${2:?missing dir for -o}/${TIMESTAMP}"
                HTML_REPORT="${REPORT_DIR}/security_audit_report_${TIMESTAMP}.html"
                TMP_DIR="${REPORT_DIR}/tmp"
                LOG_FILE="${REPORT_DIR}/audit_run.log"
                shift 2 ;;
            -n) skip_nmap=true; shift ;;
            -z) skip_zap=true; shift ;;
            -l) skip_lynis=true; shift ;;
            -r) skip_rkhunter=true; shift ;;
            -t) skip_trivy=true; shift ;;
            -H) skip_health=true; shift ;;
            --health-env) HEALTH_ENV_FILE="${2:?missing file for --health-env}"; shift 2 ;;
            --full-scan) FULL_SCAN=true; shift ;;
            --check) check_only=true; shift ;;
            -h|--help) usage ;;
            *) err "Unknown option: $1"; usage ;;
        esac
    done

    print_banner
    check_root
    detect_os

    mkdir -p "$REPORT_DIR" "$TMP_DIR"
    touch "$LOG_FILE"

    log "Detected OS: $OS_PRETTY  (type=$OS_TYPE, family=$OS_FAMILY)"
    log "Audit started. Report dir: $REPORT_DIR"
    log "HTML Report will be: $HTML_REPORT"

    detect_tools

    if $check_only; then
        print_tool_status_table
        log "Tool check complete (--check mode). No scan was run."
        exit 0
    fi

    $skip_interactive || collect_web_targets

    log "═══ Phase 1: System Data Collection ═══"
    collect_system_info

    log "═══ Phase 2: Infrastructure Audit (Lynis) ═══"
    $skip_lynis || run_lynis

    log "═══ Phase 3: Network Security ═══"
    $skip_nmap || run_nmap
    run_network_checks

    log "═══ Phase 4: SSH Security ═══"
    run_ssh_checks

    log "═══ Phase 5: User & Auth Checks ═══"
    run_user_checks

    log "═══ Phase 6: Service & OS Health Check ═══"
    $skip_health || run_health_check

    log "═══ Phase 7: Rootkit Scan (rkhunter) ═══"
    $skip_rkhunter || run_rkhunter

    log "═══ Phase 8: Kernel Vulnerability Scan (Trivy) ═══"
    $skip_trivy || run_trivy_kernel_scan

    log "═══ Phase 9: Web Application Scan (ZAP) ═══"
    $skip_zap || run_zap

    # Change ownership back to the SSH user — all scan phases run under sudo,
    # so every file in REPORT_DIR is root-owned.  gen_report.py and the
    # subsequent SFTP download need to be able to read them as the regular
    # SSH user.  SUDO_USER is set by sudo to the original caller's name
    # (e.g. "ecosmob").  If SUDO_USER is unset (rare — direct root login)
    # fall back to world-readability.
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown -R "$SUDO_USER":"$SUDO_USER" "$REPORT_DIR" 2>>"$LOG_FILE" || true
        log "Report directory ownership set to $SUDO_USER: $REPORT_DIR"
    else
        chmod -R a+rX "$REPORT_DIR" 2>>"$LOG_FILE" || true
        log "Report directory permissions widened (fallback): $REPORT_DIR"
    fi

    log "═══ Phase 10: HTML Report Generation ═══"
    generate_html_report

    # Re-apply after report generation so the SFTP download later also works.
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown -R "$SUDO_USER":"$SUDO_USER" "$REPORT_DIR" 2>>"$LOG_FILE" || true
        log "Report directory ownership refreshed: $REPORT_DIR"
    else
        chmod -R a+rX "$REPORT_DIR" 2>>"$LOG_FILE" || true
        log "Report directory permissions refreshed (fallback): $REPORT_DIR"
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║        AUDIT COMPLETE                    ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  Report:  ${BOLD}${HTML_REPORT}${RESET}"
    echo -e "  Data:    ${REPORT_DIR}"
    echo -e "  Log:     ${LOG_FILE}"
    echo ""
    echo -e "  Open in browser: ${CYAN}xdg-open ${HTML_REPORT}${RESET}  (Linux)"
    echo -e "             or:   ${CYAN}open ${HTML_REPORT}${RESET}      (macOS)"
    echo -e "             or:   ${CYAN}python3 -m http.server 8888 --directory $(dirname "$HTML_REPORT")${RESET}"
    echo ""
}

main "$@"
