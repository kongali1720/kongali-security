"""Security report generation module for Kongali Security."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from kongali_security.analysis.cvss import (
    default_cvss_for_finding,
)

from kongali_security.analysis.owasp import get_owasp_mapping


MODULE_NAME = "security_report"
MODULE_VERSION = "0.2.0"


SECURITY_HEADER_SEVERITY = {
    "Content-Security-Policy": "HIGH",
    "Strict-Transport-Security": "HIGH",
    "X-Content-Type-Options": "HIGH",
    "X-Frame-Options": "HIGH",
    "Referrer-Policy": "MEDIUM",
    "Permissions-Policy": "MEDIUM",
}


def _result_to_dict(result: Any) -> Dict[str, Any]:
    """Convert an analysis result into a dictionary."""

    if hasattr(result, "to_dict"):
        data = result.to_dict()

        if isinstance(data, dict):
            return data

    if isinstance(result, dict):
        return result

    if hasattr(result, "__dict__"):
        return dict(result.__dict__)

    return {"result": str(result)}


def _build_findings(
    scan: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build security findings from scan results."""

    findings: List[Dict[str, Any]] = []

    headers = scan.get(
        "headers",
        {},
    )

    if isinstance(headers, dict):
        missing_headers = headers.get(
            "missing",
            [],
        )

        if isinstance(missing_headers, list):
            for header in missing_headers:
                severity = SECURITY_HEADER_SEVERITY.get(
                    header,
                    "MEDIUM",
                )

                mapping = get_owasp_mapping(
                    header,
                )

                finding = {
                    "severity": severity,
                    "category": "HTTP Security Headers",
                    "title": (
                        f"Missing security header: {header}"
                    ),
                    "description": (
                        "The HTTP response does not include "
                        f"the {header} security header."
                    ),
                    "owasp": mapping["owasp"],
                    "cwe": mapping["cwe"],
                    "impact": mapping["impact"],
                    "remediation": mapping["remediation"],
                    "evidence": {
                        "header": header,
                        "status": "missing",
                    },
                }

                finding["cvss"] = (
                    default_cvss_for_finding(
                        finding
                    )
                )

                findings.append(
                    finding
                )

    return findings


def _calculate_score(
    scan: Dict[str, Any],
) -> int:
    """Calculate an overall security score from 0 to 100."""

    headers = scan.get(
        "headers",
        {},
    )

    if isinstance(headers, dict):
        score = headers.get(
            "security_score",
        )

        if isinstance(score, (int, float)):
            return max(
                0,
                min(
                    100,
                    int(score),
                ),
            )

    return 100


def _calculate_risk(
    findings: List[Dict[str, Any]],
    score: int,
) -> str:
    """Calculate overall risk level."""

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "LOW",
            )
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    if severity_counts["CRITICAL"] > 0:
        return "CRITICAL"

    if severity_counts["HIGH"] >= 4:
        return "CRITICAL"

    if severity_counts["HIGH"] > 0:
        return "HIGH"

    if severity_counts["MEDIUM"] > 0:
        return "MEDIUM"

    if severity_counts["LOW"] > 0:
        return "LOW"

    if score < 25:
        return "CRITICAL"

    if score < 50:
        return "HIGH"

    if score < 75:
        return "MEDIUM"

    return "LOW"


def generate_report(
    scan_result: Any,
) -> Dict[str, Any]:
    """Generate a complete security assessment report."""

    scan = _result_to_dict(
        scan_result,
    )

    target = str(
        scan.get(
            "target",
            "",
        )
    )

    findings = _build_findings(
        scan,
    )

    score = _calculate_score(
        scan,
    )

    risk = _calculate_risk(
        findings,
        score,
    )

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "LOW",
            )
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "target": target,
        "overall_risk": risk,
        "overall_score": score,
        "findings": findings,
        "summary": {
            "total_findings": len(
                findings,
            ),
            "severity_counts": severity_counts,
        },
        "scan": scan,
        "metadata": {
            "module": MODULE_NAME,
            "version": MODULE_VERSION,
            "generated_at": datetime.now(
                timezone.utc,
            ).isoformat(),
        },
    }


def render_markdown(
    report: Dict[str, Any],
) -> str:
    """Render a security report as Markdown."""

    target = report.get(
        "target",
        "",
    )

    risk = report.get(
        "overall_risk",
        "UNKNOWN",
    )

    score = report.get(
        "overall_score",
        0,
    )

    summary = report.get(
        "summary",
        {},
    )

    severity_counts = summary.get(
        "severity_counts",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    lines = [
        "# Kongali Security Report",
        "",
        f"**Target:** `{target}`",
        "",
        f"**Overall Risk:** `{risk}`",
        "",
        f"**Overall Score:** `{score}/100`",
        "",
        "## Summary",
        "",
        f"- Total Findings: {summary.get('total_findings', 0)}",
        (
            "- Critical: "
            f"{severity_counts.get('CRITICAL', 0)}"
        ),
        (
            "- High: "
            f"{severity_counts.get('HIGH', 0)}"
        ),
        (
            "- Medium: "
            f"{severity_counts.get('MEDIUM', 0)}"
        ),
        (
            "- Low: "
            f"{severity_counts.get('LOW', 0)}"
        ),
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append(
            "No security findings were identified.",
        )
    else:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            owasp = finding.get(
                "owasp",
                {},
            )

            cwe = finding.get(
                "cwe",
                {},
            )

            evidence = finding.get(
                "evidence",
                {},
            )

            lines.extend(
                [
                    (
                        f"### {index}. "
                        f"{finding.get('title', 'Unknown Finding')}"
                    ),
                    "",
                    (
                        "**Severity:** "
                        f"`{finding.get('severity', 'UNKNOWN')}`"
                    ),
                    "",
                    (
                        "**Category:** "
                        f"{finding.get('category', 'Unknown')}"
                    ),
                    "",
                    (
                        "**OWASP:** "
                        f"{owasp.get('id', 'N/A')} - "
                        f"{owasp.get('name', 'Unknown')}"
                    ),
                    "",
                    (
                        "**CWE:** "
                        f"{cwe.get('id', 'N/A')} - "
                        f"{cwe.get('name', 'Unknown')}"
                    ),
                    "",
                    f"{finding.get('description', '')}",
                    "",
                    "**Impact**",
                    "",
                    f"{finding.get('impact', 'Not specified.')}",
                    "",
                    "**Evidence**",
                    "",
                    "```json",
                    json.dumps(
                        evidence,
                        indent=2,
                        default=str,
                    ),
                    "```",
                    "",
                    "**Remediation**",
                    "",
                    f"{finding.get('remediation', 'Not specified.')}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Technical Scan Data",
            "",
            "```json",
            json.dumps(
                report.get(
                    "scan",
                    {},
                ),
                indent=2,
                default=str,
            ),
            "```",
            "",
            "---",
            "",
            "Generated by Kongali Security.",
        ]
    )

    return "\n".join(
        lines,
    )


def render_html(
    report: Dict[str, Any],
) -> str:
    """Render a security report as standalone HTML."""

    target = html.escape(
        str(
            report.get(
                "target",
                "",
            )
        )
    )

    risk = html.escape(
        str(
            report.get(
                "overall_risk",
                "UNKNOWN",
            )
        )
    )

    score = report.get(
        "overall_score",
        0,
    )

    summary = report.get(
        "summary",
        {},
    )

    severity_counts = summary.get(
        "severity_counts",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    finding_html = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        severity = html.escape(
            str(
                finding.get(
                    "severity",
                    "UNKNOWN",
                )
            )
        )

        category = html.escape(
            str(
                finding.get(
                    "category",
                    "Unknown",
                )
            )
        )

        title = html.escape(
            str(
                finding.get(
                    "title",
                    "Unknown Finding",
                )
            )
        )

        description = html.escape(
            str(
                finding.get(
                    "description",
                    "",
                )
            )
        )

        impact = html.escape(
            str(
                finding.get(
                    "impact",
                    "Not specified.",
                )
            )
        )

        remediation = html.escape(
            str(
                finding.get(
                    "remediation",
                    "Not specified.",
                )
            )
        )

        owasp = finding.get(
            "owasp",
            {},
        )

        cwe = finding.get(
            "cwe",
            {},
        )

        evidence = finding.get(
            "evidence",
            {},
        )

        owasp_id = html.escape(
            str(
                owasp.get(
                    "id",
                    "N/A",
                )
            )
        )

        owasp_name = html.escape(
            str(
                owasp.get(
                    "name",
                    "Unknown",
                )
            )
        )

        cwe_id = html.escape(
            str(
                cwe.get(
                    "id",
                    "N/A",
                )
            )
        )

        cwe_name = html.escape(
            str(
                cwe.get(
                    "name",
                    "Unknown",
                )
            )
        )

        evidence_json = html.escape(
            json.dumps(
                evidence,
                indent=2,
                default=str,
            )
        )

        finding_html.append(
            f"""
            <div class="finding">
                <h3>{index}. {title}</h3>

                <p>
                    <strong>Severity:</strong>
                    {severity}
                </p>

                <p>
                    <strong>Category:</strong>
                    {category}
                </p>

                <p>
                    <strong>OWASP:</strong>
                    {owasp_id} - {owasp_name}
                </p>

                <p>
                    <strong>CWE:</strong>
                    {cwe_id} - {cwe_name}
                </p>

                <p>
                    <strong>Description:</strong>
                    {description}
                </p>

                <h4>Impact</h4>
                <p>{impact}</p>

                <h4>Evidence</h4>
                <pre>{evidence_json}</pre>

                <h4>Remediation</h4>
                <p>{remediation}</p>
            </div>
            """
        )

    if not finding_html:
        finding_html.append(
            "<p>No security findings were identified.</p>",
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">
<title>Kongali Security Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    max-width: 1100px;
    margin: 40px auto;
    padding: 0 20px;
    line-height: 1.6;
    color: #222;
}}

h1 {{
    border-bottom: 2px solid #333;
    padding-bottom: 10px;
}}

h2 {{
    margin-top: 0;
}}

h4 {{
    margin-bottom: 5px;
}}

.card {{
    border: 1px solid #ddd;
    padding: 20px;
    margin: 20px 0;
    border-radius: 8px;
}}

.finding {{
    border-left: 4px solid #333;
    padding: 15px;
    margin: 15px 0;
    background: #f7f7f7;
}}

pre {{
    background: #eee;
    padding: 12px;
    overflow-x: auto;
    border-radius: 4px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 10px;
    text-align: left;
}}

footer {{
    margin-top: 40px;
    border-top: 1px solid #ddd;
    padding-top: 20px;
}}
</style>
</head>
<body>

<h1>Kongali Security Report</h1>

<div class="card">
    <h2>Assessment Overview</h2>
    <p>
        <strong>Target:</strong>
        {target}
    </p>
    <p>
        <strong>Overall Risk:</strong>
        {risk}
    </p>
    <p>
        <strong>Overall Score:</strong>
        {score}/100
    </p>
</div>

<div class="card">
    <h2>Severity Summary</h2>

    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>

        <tr>
            <td>Critical</td>
            <td>{severity_counts.get("CRITICAL", 0)}</td>
        </tr>

        <tr>
            <td>High</td>
            <td>{severity_counts.get("HIGH", 0)}</td>
        </tr>

        <tr>
            <td>Medium</td>
            <td>{severity_counts.get("MEDIUM", 0)}</td>
        </tr>

        <tr>
            <td>Low</td>
            <td>{severity_counts.get("LOW", 0)}</td>
        </tr>
    </table>
</div>

<div class="card">
    <h2>Security Findings</h2>
    {"".join(finding_html)}
</div>

<footer>
    <p>
        Generated by Kongali Security.
    </p>
</footer>

</body>
</html>
"""


def render_sarif(
    report: Dict[str, Any],
) -> str:
    """Render a security report as SARIF 2.1.0."""

    findings = report.get(
        "findings",
        [],
    )

    results = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        severity = str(
            finding.get(
                "severity",
                "LOW",
            )
        ).upper()

        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }

        owasp = finding.get(
            "owasp",
            {},
        )

        cwe = finding.get(
            "cwe",
            {},
        )

        results.append(
            {
                "ruleId": (
                    f"KONGALI-{severity}-{index:04d}"
                ),
                "level": level_map.get(
                    severity,
                    "warning",
                ),
                "message": {
                    "text": str(
                        finding.get(
                            "description",
                            "Security finding detected.",
                        )
                    ),
                },
                "properties": {
                    "severity": severity,
                    "category": str(
                        finding.get(
                            "category",
                            "Unknown",
                        )
                    ),
                    "owasp": str(
                        owasp.get(
                            "id",
                            "N/A",
                        )
                    ),
                    "cwe": str(
                        cwe.get(
                            "id",
                            "N/A",
                        )
                    ),
                    "impact": str(
                        finding.get(
                            "impact",
                            "",
                        )
                    ),
                    "remediation": str(
                        finding.get(
                            "remediation",
                            "",
                        )
                    ),
                    "evidence": finding.get(
                        "evidence",
                        {},
                    ),
                },
            }
        )

    sarif = {
        "$schema": (
            "https://json.schemastore.org/"
            "sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kongali Security",
                        "informationUri": (
                            "https://github.com/"
                            "kongali1720/"
                            "kongali-security"
                        ),
                        "version": MODULE_VERSION,
                    },
                },
                "results": results,
            },
        ],
    }

    return json.dumps(
        sarif,
        indent=2,
    )


def save_report(
    report: Dict[str, Any],
    output_format: str,
    output_path: str,
) -> None:
    """Save a rendered report to a file."""

    if output_format == "html":
        content = render_html(
            report,
        )
    elif output_format == "markdown":
        content = render_markdown(
            report,
        )
    elif output_format == "sarif":
        content = render_sarif(
            report,
        )
    else:
        raise ValueError(
            "File output supports only "
            "html, markdown, and sarif formats."
        )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            content,
        )
