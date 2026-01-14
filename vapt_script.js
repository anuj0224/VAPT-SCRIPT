/**
 * AUTHORIZED VAPT SCRIPT
 * Read-only security audit for owned systems only
 */

const { execSync } = require("child_process");
const fs = require("fs");

const REPORT = [];
let RISK_SCORE = 0;
const PLATFORM = process.platform;

/* =====================
   Utility Functions
===================== */
function run(cmd) {
  try {
    return execSync(cmd, { stdio: "pipe" }).toString().trim();
  } catch {
    return "N/A";
  }
}

function section(title) {
  REPORT.push(`\n${title}\n${"=".repeat(title.length)}`);
}

function risk(points, reason) {
  RISK_SCORE += points;
  REPORT.push(`❌ RISK (+${points}): ${reason}`);
}

/* =====================
   OS Detection
===================== */
function detectOS() {
  if (PLATFORM === "win32") return "windows";
  const osRelease = run("cat /etc/os-release");
  if (/ubuntu|debian/i.test(osRelease)) return "debian";
  if (/rocky|rhel|almalinux|centos/i.test(osRelease)) return "rhel";
  return "linux";
}
const OS_TYPE = detectOS();

/* =====================
   CVSS Mapping
===================== */
function cvssScore(severity) {
  switch ((severity || "").toLowerCase()) {
    case "critical": return 9.5;
    case "important":
    case "high": return 7.5;
    case "medium": return 5.0;
    case "low": return 2.5;
    default: return 0.0;
  }
}

/* =====================
   Exploit Availability
===================== */
function exploitAvailable(cve) {
  const out = run(`searchsploit ${cve} 2>/dev/null`);
  return out && out !== "N/A" && out.includes(cve);
}

/* =====================
   MITRE ATT&CK Mapping
===================== */
function mitreMapping(pkg) {
  const map = {
    nginx: ["T1190", "T1071"],
    apache: ["T1190"],
    openssl: ["T1557"],
    glibc: ["T1055"],
    ssh: ["T1021"],
    docker: ["T1610"],
    kernel: ["T1068"]
  };
  return map[pkg] || ["T1046"];
}

/* =====================
   1. Executive Summary
===================== */
section("1. Executive Summary");
REPORT.push("Automated read-only VAPT audit performed.");
REPORT.push("No exploitation or destructive actions executed.");

/* =====================
   2. Scan Scope
===================== */
section("2. Scan Scope & Authorization");
REPORT.push("Scan Type : Authenticated (Read-only)");
REPORT.push("Scope     : Host, Services, Configurations");
REPORT.push("Auth      : System Owner Assumed");

/* =====================
   3. Server Overview
===================== */
section("3. Server Overview");
REPORT.push(`Platform : ${OS_TYPE}`);
REPORT.push(`Hostname : ${run("hostname")}`);
REPORT.push(`IP       : ${PLATFORM !== "win32" ? run("hostname -I") : "N/A"}`);
REPORT.push(`Kernel   : ${PLATFORM !== "win32" ? run("uname -r") : "N/A"}`);

/* =====================
   4. Network Exposure
===================== */
section("4. Network Exposure");
if (PLATFORM !== "win32") {
  const ports = run("ss -tuln");
  REPORT.push(ports);
  if (ports.includes(":3306") || ports.includes(":5432")) {
    risk(30, "Database port exposed");
  }
} else {
  REPORT.push("Windows network scan skipped");
}

/* =====================
   5. Services
===================== */
section("5. Service & Version Analysis");
if (PLATFORM !== "win32") {
  REPORT.push(run("systemctl list-units --type=service | grep -E 'nginx|apache|mysql|postgres|redis|docker'"));
}

/* =====================
   6. CVE, CVSS, Exploit & MITRE Mapping
===================== */
section("6. CVE, CVSS, Exploit & MITRE Mapping");

let CVES = [];

if (OS_TYPE === "rhel") {
  run("dnf updateinfo list cves 2>/dev/null | tail -n +2")
    .split("\n")
    .forEach(line => {
      const cve = line.match(/CVE-\d+-\d+/);
      if (cve) CVES.push({ id: cve[0], severity: "important", pkg: line });
    });
}

if (OS_TYPE === "debian") {
  try {
    const data = JSON.parse(run("ubuntu-security-status --format json"));
    Object.entries(data.packages || {}).forEach(([pkg, d]) => {
      (d.cves || []).forEach(cve =>
        CVES.push({ id: cve, severity: d.status, pkg })
      );
    });
  } catch {}
}

if (CVES.length === 0) REPORT.push("No known CVEs detected.");

CVES.slice(0, 20).forEach(cve => {
  const score = cvssScore(cve.severity);
  const exploit = exploitAvailable(cve.id);
  REPORT.push(`
CVE ID      : ${cve.id}
Package     : ${cve.pkg}
Severity    : ${cve.severity}
CVSS Score  : ${score}
Exploit DB  : ${exploit ? "YES" : "NO"}
MITRE       : ${mitreMapping(cve.pkg).join(", ")}
`);
  if (score >= 9) risk(40, `Critical CVE ${cve.id}`);
  else if (score >= 7) risk(30, `High CVE ${cve.id}`);
  else if (score >= 5) risk(20, `Medium CVE ${cve.id}`);
});

/* =====================
   7. File & Configuration Footprint
===================== */
section("7. File & Configuration Footprint");

if (PLATFORM !== "win32") {
  REPORT.push("\nDetected File Types:");
  REPORT.push(run(
    "find /var/www /opt /etc -type f \\( -name '*.js' -o -name '*.java' -o -name '*.php' -o -name '*.cs' -o -name '*.conf' -o -name '*.env' \\) 2>/dev/null | awk -F. '{print $NF}' | sort | uniq -c"
  ));

  REPORT.push("\nSensitive File Names:");
  const sensitiveFiles = run(
    "find /var/www /etc /opt -type f \\( -name '*.env' -o -name '*.pem' -o -name '*.key' -o -name '*credentials*' \\) 2>/dev/null"
  );
  REPORT.push(sensitiveFiles || "None");
  if (sensitiveFiles && sensitiveFiles !== "N/A") {
    risk(25, "Sensitive files present on filesystem");
  }
} else {
  REPORT.push("File footprint scanning skipped on Windows");
}

/* =====================
   8. Configuration Weaknesses
===================== */
section("8. Configuration Weaknesses");

if (PLATFORM !== "win32") {
  REPORT.push("\nWeb Root Exposure:");
  const webRisk = run(
    "find /var/www -type f \\( -name '*.sql' -o -name '*.bak' -o -name '*.old' \\) 2>/dev/null"
  );
  REPORT.push(webRisk || "None");
  if (webRisk && webRisk !== "N/A") risk(30, "Backup files exposed in web root");

  REPORT.push("\nGit Repository Presence:");
  const gitRepo = run("find /var/www -type d -name '.git' 2>/dev/null");
  REPORT.push(gitRepo || "None");
  if (gitRepo && gitRepo !== "N/A") risk(20, "Source repository exposed");

  REPORT.push("\nContainer Environment:");
  const docker = run("docker ps --format '{{.Image}}'");
  REPORT.push(docker || "No containers");
  if (docker && docker !== "N/A") risk(10, "Containers running on host");
} else {
  REPORT.push("Configuration checks skipped on Windows");
}

/* =====================
   9. SBOM
===================== */
section("9. SBOM (Installed Packages)");

if (OS_TYPE === "debian") REPORT.push(run("dpkg-query -W -f='${Package} ${Version}\n' | head -n 20"));
if (OS_TYPE === "rhel") REPORT.push(run("rpm -qa --qf '%{NAME} %{VERSION}\n' | head -n 20"));
if (OS_TYPE === "windows") REPORT.push(run("wmic product get name,version"));

/* =====================
   10. Risk Summary
===================== */
section("10. Risk Score Summary");

let LEVEL = "LOW";
if (RISK_SCORE >= 70) LEVEL = "CRITICAL";
else if (RISK_SCORE >= 40) LEVEL = "HIGH";
else if (RISK_SCORE >= 20) LEVEL = "MEDIUM";

REPORT.push(`Total Risk Score : ${RISK_SCORE}`);
REPORT.push(`Overall Severity : ${LEVEL}`);

/* =====================
   11. Recommendations
===================== */
section("11. Actionable Recommendations");
REPORT.push("- Remove sensitive files from production systems");
REPORT.push("- Patch critical CVEs immediately");
REPORT.push("- Restrict exposed services and ports");
REPORT.push("- Secure CI/CD artifacts");
REPORT.push("- Enable monitoring & SIEM");

/* =====================
   12. Disclaimer
===================== */
section("12. Disclaimer");
REPORT.push("This assessment is informational only.");
REPORT.push("Manual validation is recommended.");
REPORT.push("Unauthorized usage is prohibited.");

fs.writeFileSync("vapt_report.txt", REPORT.join("\n"));
console.log("✅ VAPT report generated: vapt_report.txt");
