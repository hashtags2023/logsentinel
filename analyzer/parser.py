"""
LogSentinel — Log Parser
Parses auth, Apache, Nginx, syslog, and Windows event log formats
"""

import re
from pathlib import Path
from datetime import datetime


# ── Regex patterns for each log type ──────────────────────────────────────────

PATTERNS = {
    "auth": {
        # sshd failed password
        "ssh_fail": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*?\]:\s+"
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
        ),
        # sshd accepted password / publickey
        "ssh_success": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*?\]:\s+"
            r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
        ),
        # su / sudo
        "sudo": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo.*?:\s+(?P<user>\S+).*?COMMAND=(?P<cmd>.+)"
        ),
        # new user / group
        "new_user": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*?new user:\s+name=(?P<user>\S+)"
        ),
    },
    "apache": {
        # Combined log format
        "access": re.compile(
            r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
        ),
    },
    "nginx": {
        # Same combined format as Apache
        "access": re.compile(
            r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
        ),
    },
    "syslog": {
        "generic": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<process>\S+?):\s+(?P<message>.+)"
        ),
        "kernel": re.compile(
            r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+kernel:.*?(?P<message>.+)"
        ),
    },
    "windows": {
        # Simplified Windows Security event export (CSV-like or plain text)
        "event": re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+[\d:]+).*?EventID[:\s]+(?P<event_id>\d+).*?"
            r"(?:Account Name[:\s]+(?P<user>\S+))?"
        ),
    },
}

# Auto-detect signatures
AUTODETECT_SIGNATURES = {
    "auth":    ["sshd[", "Failed password", "Accepted password", "sudo:", "PAM"],
    "apache":  ["HTTP/1.1", "HTTP/2.0", "GET /", "POST /", "Mozilla/"],
    "nginx":   ["HTTP/1.1", "nginx", "GET /", "POST /"],
    "syslog":  ["kernel:", "systemd[", "CRON[", "dbus["],
    "windows": ["EventID", "Security", "Logon", "Account Name"],
}


class LogParser:
    def __init__(self, log_type="auto", verbose=False):
        self.log_type = log_type
        self.verbose = verbose

    def detect_type(self, sample_lines: list[str]) -> str:
        sample = "\n".join(sample_lines[:50])
        scores = {lt: 0 for lt in AUTODETECT_SIGNATURES}
        for log_type, sigs in AUTODETECT_SIGNATURES.items():
            for sig in sigs:
                if sig in sample:
                    scores[log_type] += 1
        best = max(scores, key=scores.get)
        if scores[best] == 0:
            return "syslog"  # fallback
        return best

    def parse(self, file_path: Path) -> list[dict]:
        events = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"    [!] Could not read {file_path}: {e}")
            return events

        log_type = self.log_type
        if log_type == "auto":
            log_type = self.detect_type(lines)
            if self.verbose:
                print(f"    [auto-detected] {log_type}")

        patterns = PATTERNS.get(log_type, PATTERNS["syslog"])

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            event = self._try_parse_line(line, line_num, log_type, patterns, file_path.name)
            if event:
                events.append(event)

        return events

    def _try_parse_line(self, line, line_num, log_type, patterns, source) -> dict | None:
        for pattern_name, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                data = match.groupdict()
                return {
                    "source": source,
                    "line_num": line_num,
                    "log_type": log_type,
                    "pattern": pattern_name,
                    "raw": line,
                    **data
                }
        # Still return unparsed lines so detectors can do raw keyword scans
        return {
            "source": source,
            "line_num": line_num,
            "log_type": log_type,
            "pattern": "raw",
            "raw": line,
        }
