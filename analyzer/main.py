#!/usr/bin/env python3
"""
LogSentinel — Security Log Analyzer
Entry point and CLI interface
"""

import argparse
import sys
from pathlib import Path
from analyzer.parser import LogParser
from analyzer.detectors import ThreatDetector
from utils.report import ReportGenerator
from utils.banner import print_banner


def parse_args():
    parser = argparse.ArgumentParser(
        description="LogSentinel — Security Log Analyzer for SOC & Blue Team Practice",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m analyzer.main logs/auth.log -t auth
  python -m analyzer.main logs/access.log -t apache -o report.html
  python -m analyzer.main logs/syslog -t syslog -v
  python -m analyzer.main logs/ --all -o report.json
        """
    )
    parser.add_argument("log_path", help="Path to log file or directory")
    parser.add_argument(
        "-t", "--type",
        choices=["auth", "apache", "nginx", "syslog", "windows", "auto"],
        default="auto",
        help="Log format type (default: auto-detect)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to file (.html or .json)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all log files in directory"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold for brute-force detection (default: 5)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"[ERROR] Path not found: {log_path}")
        sys.exit(1)

    # Collect files to process
    if log_path.is_dir() and args.all:
        log_files = list(log_path.glob("*"))
        log_files = [f for f in log_files if f.is_file()]
    elif log_path.is_file():
        log_files = [log_path]
    else:
        print("[ERROR] Use --all flag to process a directory, or specify a single file.")
        sys.exit(1)

    all_events = []

    for log_file in log_files:
        print(f"\n[*] Parsing: {log_file.name}")
        parser = LogParser(log_type=args.type, verbose=args.verbose)
        events = parser.parse(log_file)
        print(f"    → {len(events)} events parsed")
        all_events.extend(events)

    if not all_events:
        print("\n[!] No events parsed. Check log format or use -t to specify type.")
        sys.exit(0)

    print(f"\n[*] Running threat detection on {len(all_events)} events...")
    detector = ThreatDetector(threshold=args.threshold)
    findings = detector.analyze(all_events)

    # Print summary to terminal
    _print_summary(findings, args.verbose)

    # Generate report if requested
    if args.output:
        reporter = ReportGenerator()
        output_path = Path(args.output)
        if output_path.suffix == ".html":
            reporter.to_html(findings, all_events, output_path)
        elif output_path.suffix == ".json":
            reporter.to_json(findings, all_events, output_path)
        else:
            print(f"[!] Unknown output format '{output_path.suffix}'. Use .html or .json")
        print(f"\n[+] Report saved → {output_path}")


def _print_summary(findings, verbose):
    severity_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH":     "\033[93m",  # Yellow
        "MEDIUM":   "\033[94m",  # Blue
        "INFO":     "\033[96m",  # Cyan
    }
    reset = "\033[0m"

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}

    print("\n" + "=" * 60)
    print("  THREAT DETECTION RESULTS")
    print("=" * 60)

    if not findings:
        print("\n  ✅  No threats detected.\n")
        return

    for finding in findings:
        sev = finding.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        color = severity_colors.get(sev, "")
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}.get(sev, "⚪")

        print(f"\n  {icon} {color}[{sev}]{reset} {finding['title']}")
        print(f"     {finding['description']}")
        if verbose and finding.get("evidence"):
            for line in finding["evidence"][:3]:
                print(f"     → {line}")

    print("\n" + "-" * 60)
    print(f"  🔴 Critical : {counts['CRITICAL']}   🟠 High : {counts['HIGH']}   "
          f"🟡 Medium : {counts['MEDIUM']}   🔵 Info : {counts['INFO']}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
