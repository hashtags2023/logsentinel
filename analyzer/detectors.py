"""
LogSentinel — Threat Detectors
Detects: brute-force, port scans, web attacks, privilege escalation,
suspicious commands, anomalous hours, and more.
"""

from collections import defaultdict
from datetime import datetime
import re


# ── Suspicious patterns ────────────────────────────────────────────────────────

WEB_ATTACK_PATTERNS = [
    (re.compile(r"(union.*select|select.*from|drop\s+table|insert\s+into|or\s+1=1)", re.I), "SQL Injection attempt"),
    (re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I),                  "XSS attempt"),
    (re.compile(r"(\.\./|%2e%2e%2f|%252e%252e)", re.I),                                    "Path traversal attempt"),
    (re.compile(r"(/etc/passwd|/etc/shadow|/proc/self)", re.I),                            "LFI/sensitive path access"),
    (re.compile(r"(phpMyAdmin|wp-admin|\.env|\.git/config)", re.I),                        "Sensitive file/admin probe"),
    (re.compile(r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster)", re.I),                  "Known scanner user-agent/path"),
]

SUSPICIOUS_COMMANDS = [
    r"chmod\s+[0-7]*7[0-7]*",          # world-writable chmod
    r"wget\s+http",                     # download from internet
    r"curl\s+http",
    r"/tmp/\S+\.(sh|py|pl|elf)",       # executing from /tmp
    r"base64\s+-d",                     # base64 decode (common in payloads)
    r"nc\s+-[el]",                      # netcat listener
    r"python.*-c\s+['\"]import",       # python one-liners
    r"echo.*>>.*/(etc|passwd|cron)",   # writing to sensitive files
]

HIGH_VALUE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/root/", "/.ssh/",
    "/var/log/auth", "/proc/", "/sys/", "id_rsa",
]

WINDOWS_CRITICAL_EVENTS = {
    "4625": ("MEDIUM", "Failed logon attempt"),
    "4648": ("MEDIUM", "Logon with explicit credentials"),
    "4672": ("INFO",   "Special privileges assigned"),
    "4720": ("HIGH",   "New user account created"),
    "4728": ("HIGH",   "User added to privileged group"),
    "4732": ("HIGH",   "User added to local admins group"),
    "4756": ("HIGH",   "User added to universal group"),
    "4776": ("MEDIUM", "Credential validation attempt"),
    "1102": ("HIGH",   "Security audit log cleared"),
    "7045": ("HIGH",   "New service installed"),
}

AFTER_HOURS_START = 22  # 10 PM
AFTER_HOURS_END   = 6   # 6 AM


class ThreatDetector:
    def __init__(self, threshold: int = 5):
        self.threshold = threshold  # failed login threshold for brute-force

    def analyze(self, events: list[dict]) -> list[dict]:
        findings = []
        findings += self._detect_brute_force(events)
        findings += self._detect_web_attacks(events)
        findings += self._detect_suspicious_commands(events)
        findings += self._detect_privilege_escalation(events)
        findings += self._detect_new_accounts(events)
        findings += self._detect_after_hours(events)
        findings += self._detect_windows_events(events)
        findings += self._detect_high_value_access(events)
        findings += self._detect_scanner_activity(events)
        return findings

    # ── SSH / Auth Brute Force ─────────────────────────────────────────────────
    def _detect_brute_force(self, events: list[dict]) -> list[dict]:
        findings = []
        fail_counts = defaultdict(list)  # ip → [raw lines]

        for e in events:
            if e.get("pattern") == "ssh_fail" and e.get("ip"):
                fail_counts[e["ip"]].append(e["raw"])

        for ip, attempts in fail_counts.items():
            if len(attempts) >= self.threshold:
                severity = "CRITICAL" if len(attempts) >= self.threshold * 4 else "HIGH"
                findings.append({
                    "title": f"SSH Brute-Force Attack — {ip}",
                    "description": f"{len(attempts)} failed SSH login attempts from {ip} "
                                   f"(threshold: {self.threshold})",
                    "severity": severity,
                    "category": "Brute Force",
                    "ip": ip,
                    "count": len(attempts),
                    "evidence": attempts[:5],
                    "mitigation": f"Block IP {ip} via firewall. Consider fail2ban. "
                                  f"Disable password auth and use SSH keys only.",
                })

        return findings

    # ── Web Attack Signatures ──────────────────────────────────────────────────
    def _detect_web_attacks(self, events: list[dict]) -> list[dict]:
        findings = []
        attack_hits = defaultdict(list)  # (attack_type, ip) → [raw]

        for e in events:
            if e.get("log_type") not in ("apache", "nginx"):
                # Also check raw lines from any log
                pass
            raw = e.get("raw", "")
            ip = e.get("ip", "unknown")

            for pattern, attack_name in WEB_ATTACK_PATTERNS:
                if pattern.search(raw):
                    key = (attack_name, ip)
                    attack_hits[key].append(raw)

        for (attack_name, ip), lines in attack_hits.items():
            count = len(lines)
            severity = "CRITICAL" if count >= 10 else "HIGH" if count >= 3 else "MEDIUM"
            findings.append({
                "title": f"{attack_name} — {ip}",
                "description": f"{count} request(s) matching {attack_name} pattern from {ip}",
                "severity": severity,
                "category": "Web Attack",
                "ip": ip,
                "count": count,
                "evidence": lines[:3],
                "mitigation": "Review WAF rules. Validate/sanitize all user input. "
                              "Check if any requests were successful (status 200).",
            })

        return findings

    # ── Suspicious Commands ────────────────────────────────────────────────────
    def _detect_suspicious_commands(self, events: list[dict]) -> list[dict]:
        findings = []

        for e in events:
            if e.get("pattern") != "sudo":
                continue
            cmd = e.get("cmd", "")
            for pattern in SUSPICIOUS_COMMANDS:
                if re.search(pattern, cmd, re.I):
                    findings.append({
                        "title": f"Suspicious sudo command — {e.get('user', '?')}",
                        "description": f"User '{e.get('user')}' ran a suspicious command: {cmd[:120]}",
                        "severity": "HIGH",
                        "category": "Suspicious Command",
                        "user": e.get("user"),
                        "evidence": [e["raw"]],
                        "mitigation": "Review if this command was authorized. Check for persistence mechanisms.",
                    })

        return findings

    # ── Privilege Escalation ───────────────────────────────────────────────────
    def _detect_privilege_escalation(self, events: list[dict]) -> list[dict]:
        findings = []
        root_logins = []

        for e in events:
            raw = e.get("raw", "")
            if "session opened for user root" in raw or \
               (e.get("pattern") == "ssh_success" and e.get("user") == "root"):
                root_logins.append(raw)

        if root_logins:
            findings.append({
                "title": "Direct Root Login Detected",
                "description": f"{len(root_logins)} direct root login(s) observed.",
                "severity": "HIGH",
                "category": "Privilege Escalation",
                "count": len(root_logins),
                "evidence": root_logins[:3],
                "mitigation": "Disable direct root SSH login (PermitRootLogin no in sshd_config). "
                              "Require sudo for privilege escalation.",
            })

        return findings

    # ── New Account Creation ───────────────────────────────────────────────────
    def _detect_new_accounts(self, events: list[dict]) -> list[dict]:
        findings = []

        for e in events:
            if e.get("pattern") == "new_user":
                findings.append({
                    "title": f"New User Account Created — {e.get('user', '?')}",
                    "description": f"A new user account was created: {e.get('user')}",
                    "severity": "HIGH",
                    "category": "Account Activity",
                    "user": e.get("user"),
                    "evidence": [e["raw"]],
                    "mitigation": "Verify this account creation was authorized. "
                                  "Check if the account has been added to any privileged groups.",
                })

        return findings

    # ── After-Hours Login ──────────────────────────────────────────────────────
    def _detect_after_hours(self, events: list[dict]) -> list[dict]:
        findings = []
        after_hours = []

        month_map = {m: i+1 for i, m in enumerate(
            ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])}

        for e in events:
            if e.get("pattern") != "ssh_success":
                continue
            ts_str = e.get("timestamp", "")
            try:
                parts = ts_str.split()
                # Format: "Jan 15 14:32:08"
                if len(parts) >= 3:
                    hour = int(parts[2].split(":")[0])
                    if hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END:
                        after_hours.append((e.get("user"), e.get("ip"), ts_str, e["raw"]))
            except (ValueError, IndexError):
                continue

        if after_hours:
            findings.append({
                "title": f"After-Hours Login Activity ({len(after_hours)} event(s))",
                "description": f"{len(after_hours)} successful login(s) occurred between "
                               f"{AFTER_HOURS_START}:00 and {AFTER_HOURS_END:02d}:00",
                "severity": "MEDIUM",
                "category": "Anomalous Behavior",
                "count": len(after_hours),
                "evidence": [r for _, _, _, r in after_hours[:3]],
                "mitigation": "Review if after-hours access is expected for these users/IPs. "
                              "Consider time-based access controls.",
            })

        return findings

    # ── Windows Event IDs ──────────────────────────────────────────────────────
    def _detect_windows_events(self, events: list[dict]) -> list[dict]:
        findings = []
        event_id_counts = defaultdict(list)

        for e in events:
            eid = e.get("event_id")
            if eid and eid in WINDOWS_CRITICAL_EVENTS:
                event_id_counts[eid].append(e["raw"])

        # Brute-force via event 4625
        fails_4625 = event_id_counts.get("4625", [])
        if len(fails_4625) >= self.threshold:
            findings.append({
                "title": f"Windows Brute-Force (Event 4625) — {len(fails_4625)} failures",
                "description": f"{len(fails_4625)} failed Windows logon attempts detected.",
                "severity": "HIGH",
                "category": "Brute Force",
                "count": len(fails_4625),
                "evidence": fails_4625[:3],
                "mitigation": "Enable account lockout policy. Review source IPs.",
            })

        # All other critical events
        for eid, lines in event_id_counts.items():
            if eid == "4625":
                continue  # handled above
            severity, description = WINDOWS_CRITICAL_EVENTS[eid]
            findings.append({
                "title": f"Windows Event {eid}: {description}",
                "description": f"{len(lines)} occurrence(s) of Event ID {eid}: {description}",
                "severity": severity,
                "category": "Windows Security",
                "count": len(lines),
                "evidence": lines[:3],
                "mitigation": f"Investigate Event ID {eid}. Check Microsoft documentation for context.",
            })

        return findings

    # ── High-Value Path Access ─────────────────────────────────────────────────
    def _detect_high_value_access(self, events: list[dict]) -> list[dict]:
        findings = []

        for e in events:
            path = e.get("path", "") or ""
            raw = e.get("raw", "")
            for hp in HIGH_VALUE_PATHS:
                if hp in path or hp in raw:
                    findings.append({
                        "title": f"High-Value Path Accessed — {hp}",
                        "description": f"Access to sensitive path '{hp}' detected from {e.get('ip', 'unknown')}",
                        "severity": "HIGH",
                        "category": "Sensitive Data Access",
                        "evidence": [raw],
                        "mitigation": "Verify this access is authorized. Check HTTP response code. "
                                      "Block via web server config if unintended.",
                    })
                    break  # one finding per event

        return findings

    # ── Scanner Detection ──────────────────────────────────────────────────────
    def _detect_scanner_activity(self, events: list[dict]) -> list[dict]:
        findings = []
        scanner_hits = defaultdict(list)

        scan_agents = re.compile(
            r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|nessus|openvas|acunetix|w3af)", re.I)

        for e in events:
            raw = e.get("raw", "")
            match = scan_agents.search(raw)
            if match:
                scanner_hits[match.group(1).lower()].append(raw)

        for tool, lines in scanner_hits.items():
            findings.append({
                "title": f"Security Scanner Detected — {tool}",
                "description": f"{len(lines)} request(s) identified as coming from '{tool}'",
                "severity": "HIGH",
                "category": "Reconnaissance",
                "count": len(lines),
                "evidence": lines[:3],
                "mitigation": f"Block the source IP. Investigate what '{tool}' found. "
                              f"Review scan scope and remediate any discovered issues.",
            })

        return findings
