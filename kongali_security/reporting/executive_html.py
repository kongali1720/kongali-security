"""Executive HTML report renderer."""

from __future__ import annotations

from typing import Any


def render_executive_html(
    report: dict[str, Any],
) -> str:
    """Generate HTML executive report."""

    findings = ""

    for item in report.get(
        "security_findings",
        [],
    ):

        findings += (
            "<li>"
            f"<b>{item.get('severity')}</b> "
            f"{item.get('title')}"
            "</li>"
        )


    return f"""
<!DOCTYPE html>
<html>
<head>
<title>Kongali Security Executive Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
}}

h1 {{
    color: #111;
}}

.card {{
    border:1px solid #ddd;
    padding:20px;
    border-radius:10px;
}}

</style>

</head>

<body>

<h1>
KONGALI SECURITY EXECUTIVE REPORT
</h1>


<div class="card">

<h2>
Target
</h2>

<p>
{report.get('target')}
</p>


<h2>
Security Score
</h2>

<p>
{report.get('security_score')}/100
</p>


<h2>
Risk Level
</h2>

<p>
{report.get('risk_level')}
</p>


<h2>
Findings
</h2>

<ul>
{findings}
</ul>

</div>

</body>
</html>
"""
