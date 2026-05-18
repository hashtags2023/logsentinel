"""
LogSentinel — Report Generator
Generates HTML and JSON reports from threat findings
"""

import json
from pathlib import Path
from datetime import datetime


class ReportGenerator:

    def to_json(self, findings: list[dict], events: list[dict], output_path: Path):
        report = {
            "generated": datetime.now().isoformat(),
            "tool": "LogSentinel v1.0",
            "summary": {
                "total_events": len(events),
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "info":     sum(1 for f in findings if f["severity"] == "INFO"),
            },
            "findings": findings,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

    def to_html(self, findings: list[dict], events: list[dict], output_path: Path):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH":     sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "INFO":     sum(1 for f in findings if f["severity"] == "INFO"),
        }

        severity_colors = {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff8800",
            "MEDIUM":   "#ffcc00",
            "INFO":     "#4499ff",
        }

        # Build finding cards
        finding_cards = ""
        if not findings:
            finding_cards = '<div class="no-findings">✅ No threats detected.</div>'
        else:
            for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","INFO"].index(x["severity"])):
                sev = f["severity"]
                color = severity_colors.get(sev, "#888")
                evidence_html = ""
                if f.get("evidence"):
                    evidence_items = "".join(
                        f"<li><code>{_esc(line)}</code></li>" for line in f["evidence"][:3]
                    )
                    evidence_html = f'<div class="evidence"><strong>Evidence:</strong><ul>{evidence_items}</ul></div>'

                mitigation_html = ""
                if f.get("mitigation"):
                    mitigation_html = f'<div class="mitigation"><strong>💡 Mitigation:</strong> {_esc(f["mitigation"])}</div>'

                finding_cards += f"""
                <div class="finding" style="border-left: 4px solid {color}">
                    <div class="finding-header">
                        <span class="badge" style="background:{color}">{sev}</span>
                        <span class="finding-title">{_esc(f['title'])}</span>
                        <span class="category">{_esc(f.get('category',''))}</span>
                    </div>
                    <p class="description">{_esc(f['description'])}</p>
                    {evidence_html}
                    {mitigation_html}
                </div>
                """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogSentinel Report — {now}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }}
        .header {{
            border-bottom: 1px solid #30363d;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .header h1 {{
            font-size: 1.8rem;
            color: #58a6ff;
            margin-bottom: 0.3rem;
        }}
        .header .meta {{ color: #8b949e; font-size: 0.9rem; }}
        .summary {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem 1.5rem;
            text-align: center;
            min-width: 120px;
        }}
        .stat-card .number {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .stat-card .label {{
            font-size: 0.8rem;
            color: #8b949e;
            text-transform: uppercase;
        }}
        .finding {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.2rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }}
        .badge {{
            font-size: 0.7rem;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
            color: #000;
        }}
        .finding-title {{
            font-weight: 600;
            font-size: 1rem;
            flex: 1;
        }}
        .category {{
            font-size: 0.75rem;
            background: #21262d;
            padding: 2px 8px;
            border-radius: 12px;
            color: #8b949e;
        }}
        .description {{ color: #8b949e; margin-bottom: 0.75rem; }}
        .evidence {{
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 4px;
            padding: 0.75rem;
            margin-bottom: 0.75rem;
            font-size: 0.85rem;
        }}
        .evidence ul {{ margin-left: 1rem; }}
        .evidence li {{ margin: 0.3rem 0; }}
        code {{
            font-family: 'Consolas', 'Courier New', monospace;
            color: #a5d6ff;
            word-break: break-all;
        }}
        .mitigation {{
            background: #1c2a1c;
            border: 1px solid #2d4a2d;
            border-radius: 4px;
            padding: 0.6rem 0.75rem;
            font-size: 0.85rem;
            color: #7ee787;
        }}
        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: #7ee787;
            font-size: 1.2rem;
        }}
        .section-title {{
            font-size: 1.1rem;
            color: #58a6ff;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #21262d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 LogSentinel — Security Analysis Report</h1>
        <p class="meta">Generated: {now} &nbsp;|&nbsp; Total events analyzed: {len(events):,}</p>
    </div>

    <div class="summary">
        <div class="stat-card">
            <div class="number" style="color:#ff4444">{counts['CRITICAL']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#ff8800">{counts['HIGH']}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#ffcc00">{counts['MEDIUM']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#4499ff">{counts['INFO']}</div>
            <div class="label">Info</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#8b949e">{len(findings)}</div>
            <div class="label">Total Findings</div>
        </div>
    </div>

    <div class="section-title">Findings</div>
    {finding_cards}

</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)


def _esc(s: str) -> str:
    if not s:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
