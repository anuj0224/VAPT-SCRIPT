# Authorized VAPT Script

A **read-only, host-based Vulnerability Assessment & Penetration Testing (VAPT) automation script** for **Linux and Windows systems**, designed strictly for **authorized security auditing**.

This tool performs a **safe, non-intrusive security assessment** and generates a **detailed audit report** in plain text format.

> ⚠️ **IMPORTANT**  
> This script must only be executed on systems you own or have explicit authorization to test.  
> No exploitation, privilege escalation, or destructive actions are performed.

---

## 📌 Supported Platforms

- Rocky Linux
- RHEL
- AlmaLinux
- CentOS
- Ubuntu
- Debian
- Windows (limited scope)

---

## 📄 Output

The script generates a comprehensive report:

```

vapt_report.txt

````

A **demo output file** is included in this repository for reference.

---

## 🧠 What This Script Does (Section by Section)

---

## 1️⃣ Executive Summary

Provides a high-level overview of the scan:
- Confirms the scan is **automated and read-only**
- States that **no exploitation** or system modification occurred

Purpose:
- Useful for management, auditors, and compliance documentation

---

## 2️⃣ Scan Scope & Authorization

Defines:
- Scan type (Authenticated, Read-only)
- Scope (Host, Services, Configurations)
- Authorization assumption (System Owner)

Purpose:
- Ensures legal clarity and audit traceability

---

## 3️⃣ Server Overview

Collects system metadata:
- Platform / OS type
- Hostname
- IP address
- Kernel version

Purpose:
- Establishes environment context for the assessment

---

## 4️⃣ Network Exposure Analysis

Analyzes listening services and open ports:
- Uses `ss -tuln` on Linux
- Flags risky exposures (e.g., database ports like `3306`, `5432`)

Risk Impact:
- Adds risk score if sensitive services are publicly exposed

---

## 5️⃣ Service & Version Analysis

Identifies critical running services:
- Web servers (nginx, apache)
- Databases (mysql, postgres)
- Caching & containers (redis, docker)

Purpose:
- Helps correlate running services with known vulnerabilities

---

## 6️⃣ CVE, CVSS, Exploit & MITRE ATT&CK Mapping

### CVE Detection
- Rocky / RHEL-based systems: `dnf updateinfo`
- Debian / Ubuntu: `ubuntu-security-status`
- Windows: Advisory note (Defender / WSUS recommended)

### CVSS Scoring
Each CVE is mapped to an estimated **CVSS score**:
- Critical
- High
- Medium
- Low

### Exploit Availability
- Checks Exploit-DB using `searchsploit`
- Indicates whether public exploits exist

### MITRE ATT&CK Mapping
Maps affected packages to **MITRE ATT&CK techniques** to understand:
- Attack vectors
- Potential adversary behavior

Risk Impact:
- Higher CVSS = higher risk score contribution

---

## 7️⃣ SBOM (Software Bill of Materials)

Lists installed packages:
- Debian: `dpkg-query`
- RHEL/Rocky: `rpm -qa`
- Windows: `wmic`

Purpose:
- Enables SBOM-based vulnerability monitoring
- Supports compliance (ISO 27001, SOC 2, PCI-DSS)

---

## 8️⃣ File & Configuration Footprint Analysis

### File Type Discovery
Detects common application and configuration files:
- `.js`, `.java`, `.php`, `.conf`, `.env`

### Sensitive File Name Detection
Identifies potentially dangerous files:
- `.env`
- `.pem`
- `.key`
- credential-related filenames

Risk Impact:
- Adds risk score if sensitive files are found

---

## 9️⃣ Configuration Weakness Checks

### Web Root Exposure
Detects risky files in web directories:
- `.sql`
- `.bak`
- `.old`

### Git Repository Exposure
Checks for `.git` directories in production paths

### Container Environment Detection
Detects running Docker containers

Risk Impact:
- Misconfigurations increase overall risk score

---

## 🔟 Risk Score Summary

All findings contribute to a cumulative **risk score**:

| Score Range | Severity |
|------------|----------|
| 0–19       | LOW      |
| 20–39      | MEDIUM   |
| 40–69      | HIGH     |
| 70+        | CRITICAL |

Purpose:
- Gives a quick, executive-level security posture

---

## 1️⃣1️⃣ Actionable Recommendations

Provides remediation guidance such as:
- Patch critical CVEs immediately
- Restrict exposed services
- Remove secrets from filesystem
- Harden configurations
- Implement centralized logging & SIEM

---

## 1️⃣2️⃣ Disclaimer

Clearly states:
- Informational use only
- Manual validation recommended
- Unauthorized use is prohibited

---

## 🚀 Usage

```bash
node vapt_script.js
````

After execution, review:

```
vapt_report.txt
```

---

## 🛡️ Security & Legal Notice

This tool is intended for:

* Blue teams
* System administrators
* Security engineers
* Internal audits
* Compliance preparation

❌ **Do NOT use this tool on systems you do not own or lack authorization for.**

---

## 📌 License

Use at your own risk.
The author is not responsible for misuse or damage caused by unauthorized execution.

---

## ⭐ Contributions

Pull requests and improvements are welcome:

* Additional OS support
* Better CVE severity mapping
* SIEM / JSON export
* HTML or PDF reports

---

**Demo output available in `vapt_report.txt`**


