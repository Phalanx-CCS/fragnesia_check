#!/usr/bin/env bash
# =============================================================================
# fragnesia_check.sh — Phalanx CCS Vulnerability Assessment
# Exploit  : Fragnesia (Dirty Frag family) — Linux LPE via XFRM ESP-in-TCP
# CVE Ref  : Patch: https://lists.openwall.net/netdev/2026/05/13/79
# Author   : Phalanx CCS / Grendel
# Version  : 1.0.0
# =============================================================================
set -euo pipefail

# ── Colour palette ────────────────────────────────────────────────────────────
RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
CYN='\033[1;36m'
BLD='\033[1m'
DIM='\033[2m'
RST='\033[0m'

# ── Verdict accumulators ──────────────────────────────────────────────────────
VULN_FLAGS=()   # conditions that confirm exploitability
MITIG_FLAGS=()  # conditions that block or reduce exploitability
INFO_FLAGS=()   # informational findings

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "${CYN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║        PHALANX CCS — FRAGNESIA VULNERABILITY CHECK       ║"
    echo "  ║    Linux XFRM ESP-in-TCP Page Cache Corruption (LPE)     ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RST}"
}

section() { echo -e "\n${BLD}${CYN}── $1 ──────────────────────────────────────────────────${RST}"; }
pass()    { echo -e "  ${GRN}[✔]${RST} $1"; }
fail()    { echo -e "  ${RED}[✘]${RST} $1"; }
warn()    { echo -e "  ${YLW}[!]${RST} $1"; }
info()    { echo -e "  ${DIM}[i]${RST} $1"; }

require_root_note() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root — some checks (module state, sysctl) may be incomplete."
        warn "Re-run with sudo for a complete assessment."
        echo
    fi
}

# =============================================================================
# CHECK 1 — Kernel version / build date
# =============================================================================
check_kernel_version() {
    section "KERNEL VERSION"

    local kver kbuild kdate_str patch_epoch kbuild_epoch
    kver=$(uname -r)
    kbuild=$(uname -v)   # e.g. #111-Ubuntu SMP ... Sat Apr 11 23:16:02 UTC 2026

    info "Kernel release : ${kver}"
    info "Kernel version : ${kbuild}"

    # Patch merged: 2026-05-13. Extract compile timestamp from uname -v.
    # Format varies by distro; attempt to parse the trailing date.
    patch_epoch=$(date -d "2026-05-13" +%s 2>/dev/null || \
                  python3 -c "import datetime; print(int(datetime.date(2026,5,13).strftime('%s')))" 2>/dev/null || \
                  echo 0)

    # Try to extract a date from the build string (last field cluster)
    # 'uname -v' typically ends with: "Mon Jan  6 12:34:56 UTC 2025"
    local parsed_date
    parsed_date=$(echo "$kbuild" | grep -oP '(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+[\d:]+\s+\w+\s+\d{4}' | tail -1)

    if [[ -n "$parsed_date" ]]; then
        kbuild_epoch=$(date -d "$parsed_date" +%s 2>/dev/null || echo 0)
        if [[ "$kbuild_epoch" -gt 0 && "$patch_epoch" -gt 0 ]]; then
            if [[ "$kbuild_epoch" -ge "$patch_epoch" ]]; then
                pass "Kernel compiled on/after patch date (2026-05-13) — ${parsed_date}"
                MITIG_FLAGS+=("kernel_build_date_ok")
            else
                fail "Kernel compiled BEFORE patch date — ${parsed_date}"
                VULN_FLAGS+=("kernel_build_date_before_patch")
            fi
        else
            warn "Could not parse build epoch; manual verification required."
            INFO_FLAGS+=("kernel_date_parse_failed")
        fi
    else
        warn "Could not extract build date from: '${kbuild}'"
        warn "Manually confirm kernel was built after 2026-05-13."
        INFO_FLAGS+=("kernel_date_not_parseable")
    fi

    # Secondary: check kernel release version against known vulnerable strings
    # Ubuntu 6.8.0-111-generic (confirmed vulnerable in advisory)
    if echo "$kver" | grep -qP '^6\.(1|2|3|4|5|6|7|8)\.\d+-\d+-'; then
        warn "Kernel series 6.1–6.8 detected — confirm patch status above."
    fi
}

# =============================================================================
# CHECK 2 — Vulnerable kernel modules loaded
# =============================================================================
check_modules_loaded() {
    section "VULNERABLE MODULES (esp4 / esp6 / rxrpc)"

    for mod in esp4 esp6 rxrpc; do
        if lsmod 2>/dev/null | grep -q "^${mod}\s"; then
            fail "Module '${mod}' is LOADED — attack surface present"
            VULN_FLAGS+=("module_loaded_${mod}")
        else
            pass "Module '${mod}' is NOT loaded"
            MITIG_FLAGS+=("module_not_loaded_${mod}")
        fi
    done
}

# =============================================================================
# CHECK 3 — Module blacklist (modprobe.d)
# =============================================================================
check_module_blacklist() {
    section "MODULE BLACKLIST (modprobe.d)"

    local conf_files=(/etc/modprobe.d/*.conf /etc/modprobe.conf)
    local all_conf=""
    for f in "${conf_files[@]}"; do
        [[ -f "$f" ]] && all_conf+=$(cat "$f" 2>/dev/null)$'\n'
    done

    for mod in esp4 esp6 rxrpc; do
        # Accept both "blacklist" and "install /bin/false" patterns
        if echo "$all_conf" | grep -qP "^\s*(blacklist\s+${mod}|install\s+${mod}\s+/bin/false)"; then
            pass "Module '${mod}' is blacklisted in modprobe.d"
            MITIG_FLAGS+=("module_blacklisted_${mod}")
        else
            fail "Module '${mod}' has NO modprobe.d blacklist entry"
            VULN_FLAGS+=("module_not_blacklisted_${mod}")
        fi
    done

    # Show relevant lines for reference
    local relevant
    relevant=$(echo "$all_conf" | grep -P '(esp4|esp6|rxrpc)' || true)
    if [[ -n "$relevant" ]]; then
        info "Relevant modprobe.d entries:"
        echo "$relevant" | while IFS= read -r line; do
            echo -e "    ${DIM}${line}${RST}"
        done
    fi
}

# =============================================================================
# CHECK 4 — Unprivileged user namespaces (prerequisite for exploit)
# =============================================================================
check_userns() {
    section "UNPRIVILEGED USER NAMESPACES"

    # Debian/Ubuntu: kernel.unprivileged_userns_clone
    local clone_val
    clone_val=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "N/A")
    if [[ "$clone_val" == "N/A" ]]; then
        info "kernel.unprivileged_userns_clone not present (upstream kernel — userns always available)"
        INFO_FLAGS+=("userns_clone_sysctl_absent")
    elif [[ "$clone_val" -eq 1 ]]; then
        fail "kernel.unprivileged_userns_clone = 1 (enabled — exploit can obtain CAP_NET_ADMIN)"
        VULN_FLAGS+=("userns_clone_enabled")
    else
        pass "kernel.unprivileged_userns_clone = 0 (disabled)"
        MITIG_FLAGS+=("userns_clone_disabled")
    fi

    # Check user.max_user_namespaces
    local max_ns
    max_ns=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "N/A")
    if [[ "$max_ns" == "N/A" ]]; then
        info "user.max_user_namespaces not readable"
    elif [[ "$max_ns" -eq 0 ]]; then
        pass "user.max_user_namespaces = 0 (user namespaces disabled system-wide)"
        MITIG_FLAGS+=("max_user_namespaces_zero")
    else
        info "user.max_user_namespaces = ${max_ns}"
    fi
}

# =============================================================================
# CHECK 5 — AppArmor unprivileged userns restriction (Ubuntu-specific)
# =============================================================================
check_apparmor_userns() {
    section "APPARMOR UNPRIVILEGED USERNS RESTRICTION"

    local aa_val
    aa_val=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo "N/A")

    if [[ "$aa_val" == "N/A" ]]; then
        info "kernel.apparmor_restrict_unprivileged_userns not present (non-Ubuntu or AppArmor absent)"
        INFO_FLAGS+=("apparmor_userns_sysctl_absent")
    elif [[ "$aa_val" -eq 1 ]]; then
        pass "AppArmor unprivileged userns restriction = 1 (ENABLED — exploit blocked without bypass)"
        MITIG_FLAGS+=("apparmor_userns_restricted")
        warn "NOTE: A secondary bug can bypass this restriction. Not a primary control."
    else
        fail "AppArmor unprivileged userns restriction = 0 (DISABLED — full exploit path available)"
        VULN_FLAGS+=("apparmor_userns_unrestricted")
    fi
}

# =============================================================================
# CHECK 6 — XFRM/ESP subsystem in kernel config
# =============================================================================
check_kernel_config() {
    section "KERNEL CONFIG — XFRM / ESP COMPILATION"

    local cfg="/boot/config-$(uname -r)"
    if [[ ! -f "$cfg" ]]; then
        # Some systems put it under /proc
        if [[ -f /proc/config.gz ]]; then
            cfg=$(mktemp /tmp/kconfig.XXXXXX)
            zcat /proc/config.gz > "$cfg"
            trap "rm -f $cfg" EXIT
        else
            warn "Kernel config not found — skipping compile-time checks."
            INFO_FLAGS+=("kernel_config_not_found")
            return
        fi
    fi

    info "Reading config: ${cfg}"

    for opt in CONFIG_NET_KEY CONFIG_XFRM_USER CONFIG_INET_ESP CONFIG_INET6_ESP CONFIG_INET_ESPINTCP; do
        local val
        val=$(grep -m1 "^${opt}=" "$cfg" 2>/dev/null | cut -d= -f2 || echo "not set")
        case "$val" in
            y)   warn "${opt} = y (compiled in — cannot be blacklisted)" ;;
            m)   info "${opt} = m (module — blacklist effective)" ;;
            *)   pass "${opt} = not set / disabled" ;;
        esac
    done
}

# =============================================================================
# CHECK 7 — Patch verification via /proc/sys or kernel symbol presence
# =============================================================================
check_patch_indicators() {
    section "PATCH INDICATORS"

    # Check for the patched symbol via /proc/kallsyms if available
    if [[ -r /proc/kallsyms ]]; then
        # The patch modifies xfrm_input / esp_input path; we can check for
        # absence/presence of specific internal symbols as a heuristic.
        # This is opportunistic — not definitive.
        info "Checking /proc/kallsyms for XFRM symbol indicators..."
        local xfrm_count
        xfrm_count=$(grep -c 'xfrm_' /proc/kallsyms 2>/dev/null || echo 0)
        info "XFRM-related kernel symbols present: ${xfrm_count}"
        if [[ "$xfrm_count" -eq 0 ]]; then
            pass "No XFRM symbols found in kallsyms — subsystem likely not compiled in"
            MITIG_FLAGS+=("xfrm_symbols_absent")
        fi
    else
        info "/proc/kallsyms not readable (normal for unprivileged)"
    fi

    # Check if espintcp ULP is available in the system
    if [[ -d /proc/net ]]; then
        if grep -qi 'espintcp\|esp-in-tcp' /proc/net/protocols 2>/dev/null; then
            fail "espintcp protocol found in /proc/net/protocols — ULP available"
            VULN_FLAGS+=("espintcp_ulp_available")
        else
            pass "espintcp not visible in /proc/net/protocols"
            MITIG_FLAGS+=("espintcp_ulp_absent")
        fi
    fi
}

# =============================================================================
# CHECK 8 — su binary integrity (post-exploitation indicator)
# =============================================================================
check_su_integrity() {
    section "SU BINARY INTEGRITY (Post-Exploitation Indicator)"

    local su_path="/usr/bin/su"
    if [[ ! -f "$su_path" ]]; then
        warn "${su_path} not found — skipping"
        return
    fi

    # The exploit writes a 192-byte ELF stub over the first 192 bytes of /usr/bin/su
    # Read first 4 bytes and check ELF magic — this would be present anyway.
    # More usefully: check if the first 192 bytes match a setresuid/execve stub pattern.
    # We check size consistency and hash against known-good if available.

    local su_size
    su_size=$(stat -c%s "$su_path" 2>/dev/null || echo 0)
    info "${su_path} on-disk size: ${su_size} bytes"

    # ELF magic present is expected; check for anomalously small binary (stub is 192 bytes but
    # page cache is not written to disk — disk file should be untouched)
    if [[ "$su_size" -lt 1000 ]]; then
        fail "${su_path} is suspiciously small (${su_size} bytes) — possible exploitation or corruption"
        VULN_FLAGS+=("su_binary_anomalous_size")
    else
        pass "${su_path} on-disk size appears normal (${su_size} bytes)"
        info "NOTE: Page cache exploit does NOT modify on-disk binary. For live check, compare"
        info "      memory-mapped pages vs disk: 'cmp /proc/\$(pgrep -x su)/exe ${su_path}'"
    fi

    # Check setuid bit
    if [[ -u "$su_path" ]]; then
        info "${su_path} has setuid bit set (expected for su)"
    else
        warn "${su_path} does NOT have setuid bit — unusual"
    fi
}

# =============================================================================
# FINAL VERDICT
# =============================================================================
print_verdict() {
    local vuln_count=${#VULN_FLAGS[@]}
    local mitig_count=${#MITIG_FLAGS[@]}

    echo -e "\n${BLD}${CYN}══════════════════════════════════════════════════════════════${RST}"
    echo -e "${BLD}${CYN}  FRAGNESIA ASSESSMENT VERDICT${RST}"
    echo -e "${BLD}${CYN}══════════════════════════════════════════════════════════════${RST}"

    echo -e "\n  ${BLD}Vulnerability indicators : ${RED}${vuln_count}${RST}"
    echo -e "  ${BLD}Mitigation  indicators   : ${GRN}${mitig_count}${RST}\n"

    if [[ ${#VULN_FLAGS[@]} -gt 0 ]]; then
        echo -e "  ${RED}Vulnerability flags:${RST}"
        for f in "${VULN_FLAGS[@]}"; do
            echo -e "    ${RED}▸ ${f}${RST}"
        done
        echo
    fi

    if [[ ${#MITIG_FLAGS[@]} -gt 0 ]]; then
        echo -e "  ${GRN}Mitigation flags:${RST}"
        for f in "${MITIG_FLAGS[@]}"; do
            echo -e "    ${GRN}▸ ${f}${RST}"
        done
        echo
    fi

    # Determine overall verdict
    local critical_vulns=(
        "module_loaded_esp4"
        "module_loaded_esp6"
        "kernel_build_date_before_patch"
        "espintcp_ulp_available"
    )
    local crit_hit=0
    for cv in "${critical_vulns[@]}"; do
        for vf in "${VULN_FLAGS[@]}"; do
            [[ "$vf" == "$cv" ]] && crit_hit=1 && break 2
        done
    done

    echo -e "${BLD}${CYN}──────────────────────────────────────────────────────────────${RST}"

    if [[ $vuln_count -eq 0 ]]; then
        echo -e "\n  ${GRN}${BLD}  ✔  VERDICT: NOT VULNERABLE${RST}"
        echo -e "  ${DIM}All checked conditions indicate this host is patched or mitigated.${RST}"
    elif [[ $crit_hit -eq 1 ]]; then
        echo -e "\n  ${RED}${BLD}  ✘  VERDICT: LIKELY VULNERABLE (CRITICAL CONDITIONS MET)${RST}"
        echo -e "  ${DIM}One or more critical conditions confirm active attack surface.${RST}"
        echo -e "\n  ${YLW}${BLD}Recommended immediate actions:${RST}"
        echo -e "  ${YLW}1. Apply kernel patch (rebuild/upgrade to kernel built after 2026-05-13)${RST}"
        echo -e "  ${YLW}2. Blacklist modules: rmmod esp4 esp6 rxrpc${RST}"
        echo -e "     ${DIM}printf 'install esp4 /bin/false\\ninstall esp6 /bin/false\\ninstall rxrpc /bin/false\\n' \\${RST}"
        echo -e "     ${DIM}  > /etc/modprobe.d/dirtyfrag.conf${RST}"
        echo -e "  ${YLW}3. Drop page cache if su execution is suspected: echo 1 | tee /proc/sys/vm/drop_caches${RST}"
    else
        echo -e "\n  ${YLW}${BLD}  !  VERDICT: PARTIAL RISK — REVIEW FLAGGED ITEMS${RST}"
        echo -e "  ${DIM}Some vulnerability indicators present but critical conditions not confirmed.${RST}"
        echo -e "  ${DIM}Address all flagged items before marking this host clean.${RST}"
    fi

    echo -e "\n${BLD}${CYN}══════════════════════════════════════════════════════════════${RST}"
    echo -e "  ${DIM}Phalanx CCS — fragnesia_check.sh v1.0.0${RST}"
    echo -e "  ${DIM}Patch ref: https://lists.openwall.net/netdev/2026/05/13/79${RST}"
    echo -e "${BLD}${CYN}══════════════════════════════════════════════════════════════${RST}\n"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    banner
    require_root_note

    info "Host     : $(hostname)"
    info "Date     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    info "Kernel   : $(uname -r)"
    info "Arch     : $(uname -m)"
    echo

    check_kernel_version
    check_modules_loaded
    check_module_blacklist
    check_userns
    check_apparmor_userns
    check_kernel_config
    check_patch_indicators
    check_su_integrity

    print_verdict
}

main "$@"
