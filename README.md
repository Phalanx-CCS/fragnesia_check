# fragnesia_check.sh — Phalanx CCS Vulnerability Assessment

**Linux LPE Vulnerability Checker for Fragnesia (Dirty Frag family)**

---

## 📋 Description

`fragnesia_check.sh` is a comprehensive bash script designed to assess whether a Linux system is vulnerable to **Fragnesia** — a Page Cache corruption Local Privilege Escalation (LPE) exploit targeting the XFRM ESP-in-TCP subsystem.

The script performs multiple layered checks including kernel build date, loaded modules, module blacklisting, user namespace restrictions, AppArmor policies, kernel configuration, and more.

**CVE/Patch Reference**:  
Patch merged on **2026-05-13** — [netdev mailing list](https://lists.openwall.net/netdev/2026/05/13/79)

---

## ✨ Features

- **Kernel Build Date Analysis** —> Detects if the running kernel was compiled before or after the patch
- **Module State Checks** —> Verifies if `esp4`, `esp6`, or `rxrpc` are loaded
- **Module Blacklist Verification** —> Checks `/etc/modprobe.d/` for hardening
- **User Namespace Controls** —> Evaluates `unprivileged_userns_clone` and `max_user_namespaces`
- **AppArmor Integration** —> Checks Ubuntu-specific unprivileged userns restrictions
- **Kernel Config Inspection** —> Reviews relevant XFRM/ESP compile-time options
- **Patch Indicator Detection** —> Looks for runtime indicators of the fix
- **Post-Exploitation Indicators** —> Checks for signs of prior compromise (e.g., `/usr/bin/su` anomalies)
- **Clear color-coded output** with verdict summary

---

## 🛠 Requirements

- Bash
- Standard tools: `uname`, `lsmod`, `sysctl`, `grep`, `date`, `stat`
- **Recommended**: Run as root (`sudo`) for complete module and sysctl visibility

---

## 📥 Installation

# Clone the repository
git clone https://github.com/Phalanx-CCS/fragnesia_check.git
cd fragnesia_check

# Make executable
chmod +x fragnesia_check.sh

# Run the checker
sudo ./fragnesia_check.sh

🚀 Usage

# Basic usage
sudo ./fragnesia_check.sh

# Or without sudo (limited checks)
./fragnesia_check.sh

Example Output

The script produces a detailed report ending with a clear verdict:

    NOT VULNERABLE — All checks passed
    LIKELY VULNERABLE — Critical conditions met
    PARTIAL RISK — Some mitigations missing

🔒 Mitigation Recommendations

If the script reports vulnerability, apply these immediately:

    Upgrade to a kernel built after 2026-05-13
    Blacklist vulnerable modules:

    sudo bash -c 'cat > /etc/modprobe.d/dirtyfrag.conf << EOF
    install esp4 /bin/false
    install esp6 /bin/false
    install rxrpc /bin/false
    EOF'

    Disable unprivileged user namespaces (if appropriate)
    Drop page cache if compromise is suspected:

    echo 1 | sudo tee /proc/sys/vm/drop_caches

⚠️ Disclaimer

This tool is provided for defensive security assessment only. It does not contain exploit code.

Phalanx CCS and the author are not responsible for any misuse or damage resulting from the use of this script.
📝 Author

    Author: d_0_4 (@ Phalanx CCS)
    Version: 1.0.0

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

Made with ❤️ for the Linux security community
