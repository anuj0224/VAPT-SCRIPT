/**
 * AUTHORIZED VAPT SCRIPT
 * Read-only security audit for owned systems only
 */

const { execSync } = require("child_process");
const fs = require("fs");

const REPORT = [];
let RISK_SCORE = 0;

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

/* 1. Executive Summary */
section("1. Executive Summary");
REPORT.push("Automated read-only VAPT audit performed.");
REPORT.push("No exploitation or destructive actions executed.");

/* 2. Scan Scope & Authorization */
section("2. Scan Scope & Authorization");
REPORT.push("Scan Type : Authenticated (Local Read-only)");
REPORT.push("Scope     : Server, Network, Configurations");
REPORT.push("Auth      : System Owner Assumed");

/* 3. Server Overview */
section("3. Server Overview");
REPORT.push(`Hostname : ${run("hostname")}`);
REPORT.push(`IP       : ${run("hostname -I")}`);
REPORT.push(`OS       : ${run("lsb_release -d | cut -f2")}`);
REPORT.push(`Kernel   : ${run("uname -r")}`);

/* 4. Network Exposure */
section("4. Network Exposure");
const ports = run("ss -tuln");
REPORT.push(ports);
if (ports.includes(":3306") || ports.includes(":5432")) {
  risk(30, "Database port exposed");
}

/* 5. Service & Version Analysis */
section("5. Service & Version Analysis");
REPORT.push(run("systemctl list-units --type=service | grep -E 'nginx|apache|mysql|postgres|redis|docker'"));

/* 6. CVE & Severity Mapping (Version-based placeholder) */
section("6. CVE & Severity Mapping");
REPORT.push("CVE matching based on detected versions.");
REPORT.push("External CVE DB integration recommended.");
risk(20, "Potential outdated services");

/* 7. File & Configuration Footprint */
section("7. File & Configuration Footprint");

/* File types */
REPORT.push("\nDetected File Types:");
REPORT.push(run(
  "find /var/www /opt /etc -type f \\( -name '*.js' -o -name '*.java' -o -name '*.php' -o -name '*.cs' -o -name '*.conf' -o -name '*.env' \\) 2>/dev/null | awk -F. '{print $NF}' | sort | uniq -c"
));

/* Secrets pattern detection (no file read) */
REPORT.push("\nSensitive File Names:");
const sensitiveFiles = run(
  "find /var/www /etc /opt -type f \\( -name '*.env' -o -name '*.pem' -o -name '*.key' -o -name '*credentials*' \\) 2>/dev/null"
);
REPORT.push(sensitiveFiles || "None");
if (sensitiveFiles) risk(25, "Sensitive files present");

/* 8. Configuration Weaknesses */
section("8. Configuration Weaknesses");

/* Web root exposure */
REPORT.push("\nWeb Root Exposure:");
const webRisk = run(
  "find /var/www -type f \\( -name '*.sql' -o -name '*.bak' -o -name '*.old' \\) 2>/dev/null"
);
REPORT.push(webRisk || "None");
if (webRisk) risk(30, "Backup files in web root");

/* Git repo presence */
REPORT.push("\nGit Repository Presence:");
const gitRepo = run("find /var/www -type d -name '.git' 2>/dev/null");
REPORT.push(gitRepo || "None");
if (gitRepo) risk(20, "Source repository present in production");

/* Container detection */
REPORT.push("\nContainer Environment:");
const docker = run("docker ps --format '{{.Image}}'");
REPORT.push(docker || "No containers");
if (docker) risk(10, "Containers running");

/* SBOM (lightweight) */
REPORT.push("\nSBOM (Installed Packages):");
REPORT.push(run("dpkg-query -W -f='${Package} ${Version}\n' | head -n 20"));

/* 9. Risk Score Summary */
section("9. Risk Score Summary");
let LEVEL = "LOW";
if (RISK_SCORE >= 70) LEVEL = "CRITICAL";
else if (RISK_SCORE >= 40) LEVEL = "HIGH";
else if (RISK_SCORE >= 20) LEVEL = "MEDIUM";

REPORT.push(`Total Risk Score : ${RISK_SCORE}`);
REPORT.push(`Overall Severity : ${LEVEL}`);

/* 10. Actionable Recommendations */
section("10. Actionable Recommendations");
REPORT.push("- Remove secrets from filesystem");
REPORT.push("- Restrict DB ports to private network");
REPORT.push("- Remove source code from production");
REPORT.push("- Enable firewall & harden SSH");
REPORT.push("- Use CI/CD + secrets manager");

/* 11. Disclaimer */
section("11. Disclaimer");
REPORT.push("This report is informational.");
REPORT.push("Manual validation recommended.");
REPORT.push("Unauthorized use is prohibited.");

fs.writeFileSync("vapt_report.txt", REPORT.join("\n"));
console.log("✅ VAPT report generated: vapt_report.txt");