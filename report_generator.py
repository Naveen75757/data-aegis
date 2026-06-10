import json
import os
from datetime import datetime

# ============================================================
# DATA-AEGIS RISK INTELLIGENCE DASHBOARD
# Generates visual HTML risk report after each agent session.
# SOC-ready output for security leadership and compliance teams.
# ============================================================

def generate_html_report(incidents, agent_memory_summary):
    """
    Generates a visual HTML dashboard from agent session data.
    Shows threat breakdown by category, risk by region,
    and open incident summary — the kind of output that
    goes to a CISO or compliance team after a SOC session.
    """

    # Count threats by data class
    class_counts = {}
    for inc in incidents:
        data_class = inc["data_class"]
        if data_class not in class_counts:
            class_counts[data_class] = 0
        class_counts[data_class] += 1

    # Count threats by region
    region_counts = {}
    for inc in incidents:
        region = inc["region"]
        if region not in region_counts:
            region_counts[region] = 0
        region_counts[region] += 1

    # Count escalations
    escalations = [i for i in incidents if i.get("escalate_to_human")]
    auto_remediated = [i for i in incidents if not i.get("escalate_to_human")]
    memory_escalated = [i for i in incidents if i.get("memory_escalated")]

    # Build class breakdown rows
    class_rows = ""
    class_colors = {
        "PII": "#e74c3c",
        "Credentials": "#e67e22",
        "Healthcare": "#9b59b6",
        "IAM_Violation": "#3498db",
        "Financial": "#1abc9c",
        "Unknown": "#95a5a6"
    }

    for data_class, count in class_counts.items():
        color = class_colors.get(data_class, "#95a5a6")
        percentage = round((count / len(incidents)) * 100) if incidents else 0
        class_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{data_class}</span></td>
            <td>{count}</td>
            <td>
                <div class="bar-container">
                    <div class="bar" style="width:{percentage}%; background:{color}"></div>
                </div>
            </td>
            <td>{percentage}%</td>
        </tr>"""

    # Build region breakdown rows
    region_rows = ""
    for region, count in sorted(region_counts.items(), key=lambda x: x[1], reverse=True):
        is_repeat = region in agent_memory_summary.get("repeat_threat_regions", [])
        repeat_flag = ' <span class="repeat-flag">⚠️ REPEAT</span>' if is_repeat else ""
        region_rows += f"""
        <tr>
            <td>{region}{repeat_flag}</td>
            <td>{count}</td>
        </tr>"""

    # Build incident rows
    incident_rows = ""
    for inc in incidents:
        severity_color = "#e74c3c" if inc["severity"] == "CRITICAL" else "#e67e22"
        escalation = "👤 Human Review" if inc["escalate_to_human"] else "✅ Auto-remediated"
        memory_flag = " 🧠" if inc.get("memory_escalated") else ""
        incident_rows += f"""
        <tr>
            <td><code>{inc['incident_id']}</code></td>
            <td><span class="badge" style="background:{severity_color}">{inc['severity']}</span></td>
            <td>{inc['data_class']}</td>
            <td>{inc['region']}</td>
            <td>{inc['risk_score']}/10{memory_flag}</td>
            <td>{escalation}</td>
        </tr>"""

    # Build full HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data-Aegis Risk Intelligence Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; padding: 2rem; }}
        .header {{ border-bottom: 1px solid #2d2d3a; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 1.8rem; color: #ffffff; font-weight: 600; }}
        .header h1 span {{ color: #4a9eff; }}
        .header p {{ color: #888; margin-top: 0.5rem; font-size: 0.9rem; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .metric-card {{ background: #1a1d2e; border: 1px solid #2d2d3a; border-radius: 8px; padding: 1.25rem; }}
        .metric-card .label {{ font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }}
        .metric-card .value {{ font-size: 2rem; font-weight: 700; margin-top: 0.5rem; }}
        .metric-card .value.red {{ color: #e74c3c; }}
        .metric-card .value.green {{ color: #2ecc71; }}
        .metric-card .value.blue {{ color: #4a9eff; }}
        .metric-card .value.orange {{ color: #e67e22; }}
        .section {{ background: #1a1d2e; border: 1px solid #2d2d3a; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .section h2 {{ font-size: 1rem; color: #ffffff; font-weight: 600; margin-bottom: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; font-size: 0.75rem; color: #888; text-transform: uppercase; padding: 0.5rem; border-bottom: 1px solid #2d2d3a; }}
        td {{ padding: 0.75rem 0.5rem; border-bottom: 1px solid #1e2030; font-size: 0.875rem; }}
        tr:last-child td {{ border-bottom: none; }}
        .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; color: white; }}
        .bar-container {{ background: #2d2d3a; border-radius: 4px; height: 8px; width: 200px; }}
        .bar {{ height: 8px; border-radius: 4px; }}
        .repeat-flag {{ color: #e67e22; font-size: 0.75rem; font-weight: 600; }}
        code {{ background: #2d2d3a; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.8rem; color: #4a9eff; }}
        .footer {{ text-align: center; color: #444; font-size: 0.8rem; margin-top: 2rem; }}
        .status-bar {{ background: #1a1d2e; border: 1px solid #2ecc71; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 0.75rem; }}
        .status-dot {{ width: 10px; height: 10px; background: #2ecc71; border-radius: 50%; }}
        .status-text {{ color: #2ecc71; font-size: 0.875rem; font-weight: 500; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Data-<span>Aegis</span> Risk Intelligence Dashboard</h1>
        <p>AI Security Posture Management — Session Report | {datetime.now().strftime("%B %d, %Y %H:%M:%S")}</p>
    </div>

    <div class="status-bar">
        <div class="status-dot"></div>
        <div class="status-text">Agent session complete — Audit trail persisted — Safe payload delivered to downstream AI</div>
    </div>

    <div class="metrics">
        <div class="metric-card">
            <div class="label">Total Scanned</div>
            <div class="value blue">{agent_memory_summary.get('total_records_scanned', 0)}</div>
        </div>
        <div class="metric-card">
            <div class="label">Incidents Generated</div>
            <div class="value red">{len(incidents)}</div>
        </div>
        <div class="metric-card">
            <div class="label">Human Escalations</div>
            <div class="value orange">{len(escalations)}</div>
        </div>
        <div class="metric-card">
            <div class="label">Auto Remediated</div>
            <div class="value green">{len(auto_remediated)}</div>
        </div>
    </div>

    <div class="section">
        <h2>Threat Breakdown by Data Class</h2>
        <table>
            <thead>
                <tr>
                    <th>Data Class</th>
                    <th>Count</th>
                    <th>Distribution</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                {class_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Risk by AWS Region</h2>
        <table>
            <thead>
                <tr>
                    <th>Region</th>
                    <th>Incidents</th>
                </tr>
            </thead>
            <tbody>
                {region_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Open Incidents</h2>
        <table>
            <thead>
                <tr>
                    <th>Incident ID</th>
                    <th>Severity</th>
                    <th>Data Class</th>
                    <th>Region</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {incident_rows}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>Data-Aegis AI-SPM Gateway — Powered by LLaMA 3.3 70B — github.com/Naveen75757/data-aegis</p>
    </div>
</body>
</html>"""

    return html


def save_report(incidents, agent_memory_summary):
    """Saves the HTML report to disk and returns the filename"""
    html = generate_html_report(incidents, agent_memory_summary)
    filename = f"risk_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename


if __name__ == "__main__":
    # Test with sample data
    sample_incidents = [
        {
            "incident_id": "INC-44995",
            "severity": "CRITICAL",
            "data_class": "PII",
            "region": "us-east-1",
            "risk_score": 8,
            "escalate_to_human": False,
            "memory_escalated": False
        },
        {
            "incident_id": "INC-21800",
            "severity": "CRITICAL",
            "data_class": "Credentials",
            "region": "us-west-2",
            "risk_score": 8,
            "escalate_to_human": False,
            "memory_escalated": False
        },
        {
            "incident_id": "INC-21533",
            "severity": "CRITICAL",
            "data_class": "Healthcare",
            "region": "us-east-2",
            "risk_score": 9,
            "escalate_to_human": True,
            "memory_escalated": False
        },
        {
            "incident_id": "INC-18382",
            "severity": "CRITICAL",
            "data_class": "PII",
            "region": "us-east-1",
            "risk_score": 10,
            "escalate_to_human": True,
            "memory_escalated": True
        }
    ]

    sample_memory = {
        "total_records_scanned": 9,
        "regions_flagged": ["us-east-1", "us-west-2", "us-east-2"],
        "repeat_threat_regions": ["us-east-1"]
    }

    filename = save_report(sample_incidents, sample_memory)
    print(f"✅ Dashboard generated: {filename}")
    print(f"   Open {filename} in your browser to view!")