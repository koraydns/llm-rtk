import os
import json
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

def generate_report(findings, total_tests, final_url):
    """
    Generate structured HTML red-team report including
    severity distribution, risk summary, and detailed findings.
    """

    # Sorting Vulnerabilities by Severity
    severity_order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    findings_sorted = sorted(
        findings,
        key=lambda f: severity_order.get(
            f["analysis"]["severity"], 0
        ),
        reverse=True
    )

    # Severity Distribution
    severities = [f["analysis"]["severity"] for f in findings]
    severity_counts = Counter(severities)

    labels = []
    sizes = []

    for level in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(level, 0)
        if count > 0:
            labels.append(level)
            sizes.append(count)

    chart_filename = "severity_pie.png"

    severity_colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#eab308",
        "Low": "#16a34a"
    }

    colors = [severity_colors[label] for label in labels]

    if sizes:
        plt.figure()
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors)
        plt.title("Severity Distribution")
        plt.savefig(chart_filename)
        plt.close()
    else:
        chart_filename = None

    # Overall Risk Calculation
    if "Critical" in severities:
        overall_risk = "Critical"
    elif "High" in severities:
        overall_risk = "High"
    elif "Medium" in severities:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Report Generation
    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>LLM-RTK Red Team Report</title>
<link href='https://fonts.googleapis.com/css?family=Nunito' rel='stylesheet'>
<style>
body {{
    font-family: 'Nunito';
    background-color: #0f172a;
    color: #e2e8f0;
    margin: 0;
}}
.container {{
    width: 85%;
    margin: auto;
    padding: 40px 0;
}}
h1 {{
    text-align: center;
    color: #38bdf8;
}}
.section {{
    background: #1e293b;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 30px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}
th, td {{
    padding: 10px;
    border: 1px solid #334155;
}}
th {{
    background-color: #334155;
}}
.finding {{
    background: #111827;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 20px;
}}
pre {{
    background: #0f172a;
    padding: 10px;
    overflow-x: auto;
}}
.footer {{
    text-align: center;
    margin-top: 40px;
    color: #94a3b8;
    font-size: 12px;
}}
img {{
    display: block;
    margin: 20px auto;
    max-width: 400px;
}}
.badge {{
    padding: 4px 10px;
    border-radius: 5px;
    font-size: 12px;
}}
.Critical {{ background-color: #dc2626; }}
.High {{ background-color: #ea580c; }}
.Medium {{ background-color: #eab308; color: black; }}
.Low {{ background-color: #16a34a; }}
</style>
</head>
<body>
<div class="container">

<h1>LLM-RTK Red Team Assessment Report</h1>
<p style="text-align: center;"><i>Objective-Driven Adversarial Validation for OWASP GenAI Top 10 LLM Security Risks</i></p>

<div class="section">
<strong>Target Endpoint:</strong> {final_url}<br>
<strong>Total Tests:</strong> {total_tests}<br>
<strong>Successful Attacks:</strong> {len(findings)}<br>
<strong>Overall Risk:</strong> <span class="badge {overall_risk}">{overall_risk}</span><br>
<strong>Generated:</strong> {timestamp}
</div>

<div class="section">
<h2>Severity Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
"""

    for level in ["Critical", "High", "Medium", "Low"]:
        html += f"<tr><td>{level}</td><td>{severity_counts.get(level,0)}</td></tr>"

    html += "</table></div>"

    if chart_filename:
        html += f"""
<div class="section">
<h2>Severity Distribution</h2>
<img src="{chart_filename}">
</div>
"""

    html += '<div class="section"><h2>Detailed Findings</h2>'
    
    for finding in findings_sorted:
        analysis = finding["analysis"]
        mapping = analysis.get("owasp_mapping", {})

        html += f"""
<div class="finding">
<strong>Objective:</strong> {finding.get("objective")}<br>
<strong>Payload ID:</strong> {finding.get("payload_id")}<br>
<strong>Technique:</strong> {finding.get("technique")}<br>
<strong>Severity:</strong> <span class="badge {analysis.get("severity")}">{analysis.get("severity")}</span><br>
<strong>Impact:</strong> {analysis.get("impact")}<br><br>

<strong>OWASP Mapping</strong><br>
Risk ID: {mapping.get("risk_id")}<br>
Risk Name: {mapping.get("risk_name")}<br><br>

<strong>Request</strong>
<pre>{json.dumps(finding.get("request_body"), indent=2)}</pre>

<strong>Response</strong>
<pre>{finding.get("response_body")}</pre>
</div>
"""

    html += """
</div>

<div class="footer">
Generated by LLM-RTK — Objective-Driven Adversarial Validation Framework
</div>

</div>
</body>
</html>
"""

    output_file = "LLM-RTK_Red_Team_Report.html"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML Report generated: {output_file}")