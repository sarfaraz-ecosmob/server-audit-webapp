#!/usr/bin/env bash
# =============================================================================
#  install_tools.sh - OPTIONAL, EXPLICIT installer for the audit toolchain
#
#  server_audit.sh NEVER installs anything by itself. If you want to stage
#  Lynis / Nmap / rkhunter / OWASP ZAP ahead of running the audit on a
#  production box, use this script - reviewed and run by a human, on purpose.
#
#  SAFE BY DEFAULT: this script only PRINTS what it would do. Nothing is
#  installed until you pass --yes.
#
#  Usage:
#    ./install_tools.sh                      # dry run - show plan, no changes
#    ./install_tools.sh --yes                # actually install everything
#    ./install_tools.sh --only lynis,nmap    # limit to specific tools
#    ./install_tools.sh --only nmap --yes    # install just nmap
#
#  Supported tools: lynis, nmap, rkhunter, zap-docker (pulls the ZAP image),
#  trivy (kernel vulnerability scanner), jq (JSON processor for filtering)
# =============================================================================

set -uo pipefail

CONFIRM=false
ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y) CONFIRM=true; shift ;;
        --only)   ONLY="${2:?missing value for --only}"; shift 2 ;;
        -h|--help)
            cat <<'EOF'
Usage: ./install_tools.sh [--yes] [--only lynis,nmap,rkhunter,zap-docker,trivy,jq]

Dry run by default: prints the exact commands it would run per tool, but
changes NOTHING. Pass --yes to actually execute them.
EOF
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

want() {
    [[ -z "$ONLY" ]] && return 0
    [[ ",${ONLY}," == *",$1,"* ]]
}

# ─── OS / package manager detection ─────────────────────────────────────────
OS_TYPE=""; OS_FAMILY=""; OS_PRETTY=""; PKG_MGR=""

case "$(uname -s)" in
    Linux)
        OS_TYPE="linux"
        if [[ -f /etc/os-release ]]; then
            # shellcheck disable=SC1091
            . /etc/os-release
            OS_PRETTY="${PRETTY_NAME:-Linux}"
            idlike="$(printf '%s' "${ID:-}${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"
            case "$idlike" in
                *debian*|*ubuntu*) OS_FAMILY="debian" ;;
                *rhel*|*centos*|*fedora*|*rocky*|*alma*) OS_FAMILY="rhel" ;;
                *suse*) OS_FAMILY="suse" ;;
                *arch*) OS_FAMILY="arch" ;;
                *) OS_FAMILY="unknown" ;;
            esac
        else
            OS_PRETTY="Linux (unrecognized distro)"; OS_FAMILY="unknown"
        fi
        ;;
    Darwin)
        OS_TYPE="darwin"; OS_FAMILY="mac"
        OS_PRETTY="macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
        ;;
    *)
        OS_TYPE="unknown"; OS_FAMILY="unknown"; OS_PRETTY="$(uname -s)"
        ;;
esac

case "$OS_FAMILY" in
    debian) command -v apt-get &>/dev/null && PKG_MGR="apt" ;;
    rhel)   command -v dnf &>/dev/null && PKG_MGR="dnf" || { command -v yum &>/dev/null && PKG_MGR="yum"; } ;;
    suse)   command -v zypper &>/dev/null && PKG_MGR="zypper" ;;
    arch)   command -v pacman &>/dev/null && PKG_MGR="pacman" ;;
    mac)    command -v brew &>/dev/null && PKG_MGR="brew" ;;
esac

echo -e "${BOLD}Detected OS:${RESET} $OS_PRETTY  (family=$OS_FAMILY, package manager=${PKG_MGR:-none detected})"
if [[ -z "$PKG_MGR" ]]; then
    if [[ "$OS_FAMILY" == "mac" ]]; then
        echo -e "${YELLOW}Homebrew not found.${RESET} Install it first: https://brew.sh, then re-run this script."
    else
        echo -e "${YELLOW}No supported package manager detected.${RESET} Install tools manually (see README.md)."
    fi
    exit 1
fi

pkg_cmd() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt)    echo "sudo apt-get update -qq 2>/dev/null || true && sudo apt-get install -y $pkg" ;;
        dnf)    echo "sudo dnf install -y $pkg" ;;
        yum)    echo "sudo yum install -y $pkg" ;;
        zypper) echo "sudo zypper install -y $pkg" ;;
        pacman) echo "sudo pacman -S --noconfirm $pkg" ;;
        brew)   echo "brew install $pkg" ;;
    esac
}

run_or_show() {
    local desc="$1" cmd="$2"
    echo ""
    echo -e "${CYAN}${desc}${RESET}"
    echo "  \$ $cmd"
    if $CONFIRM; then
        eval "$cmd"
        echo -e "${GREEN}Done.${RESET}"
    else
        echo -e "${YELLOW}(dry run - not executed. Re-run with --yes to apply)${RESET}"
    fi
}

echo ""
echo -e "${BOLD}═══ Install Plan ═══${RESET}"
$CONFIRM || echo -e "${YELLOW}DRY RUN - nothing will be changed. Pass --yes to actually install.${RESET}"

if want lynis; then
    if command -v lynis &>/dev/null; then
        echo -e "\n${GREEN}Lynis already installed:${RESET} $(command -v lynis)"
    else
        run_or_show "Install Lynis (infrastructure hardening scanner):" "$(pkg_cmd lynis)"
    fi
fi

if want nmap; then
    if command -v nmap &>/dev/null; then
        echo -e "\n${GREEN}Nmap already installed:${RESET} $(command -v nmap)"
    else
        run_or_show "Install Nmap (network/port scanner):" "$(pkg_cmd nmap)"
    fi
fi

if want rkhunter; then
    if command -v rkhunter &>/dev/null; then
        echo -e "\n${GREEN}rkhunter already installed:${RESET} $(command -v rkhunter)"
    else
        run_or_show "Install rkhunter (rootkit scanner):" "$(pkg_cmd rkhunter)"
    fi
fi

if want zap-docker; then
    if command -v docker &>/dev/null; then
        if docker image inspect ghcr.io/zaproxy/zaproxy:stable &>/dev/null; then
            echo -e "\n${GREEN}OWASP ZAP docker image already present.${RESET}"
        else
            run_or_show "Pull OWASP ZAP (web app scanner) docker image:" "docker pull ghcr.io/zaproxy/zaproxy:stable"
        fi
    else
        echo -e "\n${YELLOW}Docker not found.${RESET} Install Docker first (see docs.docker.com/engine/install), then re-run:"
        echo "  ./install_tools.sh --only zap-docker --yes"
    fi
fi

if want trivy; then
    if command -v trivy &>/dev/null; then
        echo -e "\n${GREEN}Trivy already installed:${RESET} $(command -v trivy)"
    else
        run_or_show "Install Trivy (kernel vulnerability scanner - official install script):" \
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin"
    fi
fi

if want jq; then
    if command -v jq &>/dev/null; then
        echo -e "\n${GREEN}jq already installed:${RESET} $(command -v jq)"
    else
        run_or_show "Install jq (JSON processor for filtering Trivy results):" "$(pkg_cmd jq)"
    fi
fi

echo ""
echo -e "${BOLD}═══ Next Steps ═══${RESET}"
echo "  Verify what the audit script sees:   sudo ./server_audit.sh --check"
echo "  Run a full audit:                    sudo ./server_audit.sh"
