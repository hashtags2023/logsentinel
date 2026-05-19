"""
LogSentinel — IP Reputation Lookup
Checks IPs against AbuseIPDB to see if they've been reported for malicious activity.
"""

import urllib.request
import urllib.parse
import json
import os


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """
    Query AbuseIPDB for a single IP address.
    Returns a dict with reputation data, or an error dict if the request fails.
    """
    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": False,
    })

    url = f"{ABUSEIPDB_URL}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json",
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get("data", {})
    except Exception as e:
        return {"error": str(e)}


def check_ips(ip_list: list[str], api_key: str) -> dict:
    """
    Check multiple IPs. Returns a dict of {ip: reputation_data}.
    Deduplicates the list automatically.
    """
    results = {}
    seen = set()
    for ip in ip_list:
        if ip in seen or not ip:
            continue
        seen.add(ip)
        results[ip] = check_ip(ip, api_key)
    return results


def format_reputation(ip: str, data: dict) -> str:
    """
    Format reputation data as a readable string for terminal output.
    """
    if "error" in data:
        return f"  ⚠️  {ip} — lookup failed: {data['error']}"

    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)
    country = data.get("countryCode", "??")
    isp = data.get("isp", "Unknown ISP")
    usage = data.get("usageType", "Unknown")
    last_reported = data.get("lastReportedAt", "Never")

    if score >= 80:
        icon = "🔴"
        label = "MALICIOUS"
    elif score >= 40:
        icon = "🟠"
        label = "SUSPICIOUS"
    elif score >= 1:
        icon = "🟡"
        label = "LOW RISK"
    else:
        icon = "🟢"
        label = "CLEAN"

    return (
        f"  {icon} {ip} [{label}] — Abuse Score: {score}/100 | "
        f"Reports: {reports} | Country: {country} | "
        f"ISP: {isp} | Type: {usage} | Last reported: {last_reported}"
    )


def get_api_key():
    """
    Load API key from environment variable ABUSEIPDB_KEY.
    Returns None if not set.
    """
    return os.environ.get("ABUSEIPDB_KEY")
