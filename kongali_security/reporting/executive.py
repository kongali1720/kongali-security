"""Executive security report engine."""

from __future__ import annotations

from typing import Any


def collect_findings(
    data: Any,
) -> list[dict[str, Any]]:
    """Collect findings recursively."""

    findings = []

    if isinstance(data, dict):

        for key, value in data.items():

            if key == "findings":

                if isinstance(value, list):
                    findings.extend(value)

            else:
                findings.extend(
                    collect_findings(value)
                )

    elif isinstance(data, list):

        for item in data:
            findings.extend(
                collect_findings(item)
            )

    return findings



def generate_executive_report(
    scan_result: dict[str, Any],
) -> dict[str, Any]:
    """Generate executive security report."""

    risk = scan_result.get(
        "risk",
        {},
    )

    findings = collect_findings(
        scan_result
    )


    security_findings = [
        f for f in findings
        if f.get(
            "severity",
            "INFO",
        ).upper()
        != "INFO"
    ]


    informational = [
        f for f in findings
        if f.get(
            "severity",
            "INFO",
        ).upper()
        == "INFO"
    ]


    return {
        "title":
            "Kongali Security Executive Report",

        "target":
            scan_result.get(
                "target"
            ),

        "security_score":
            risk.get(
                "score",
                100,
            ),

        "risk_level":
            risk.get(
                "risk_level",
                "UNKNOWN",
            ),

        "summary":
            risk.get(
                "summary",
                {},
            ),

        "total_security_findings":
            len(
                security_findings
            ),

        "security_findings":
            security_findings[:20],

        "informational":
            informational[:20],
    }



def render_terminal_report(
    report: dict[str, Any],
) -> str:
    """Render terminal output."""

    lines = []

    lines.append(
        "=" * 50
    )

    lines.append(
        " KONGALI SECURITY EXECUTIVE REPORT"
    )

    lines.append(
        "=" * 50
    )

    lines.append("")

    lines.append(
        f"Target: {report.get('target')}"
    )

    lines.append(
        f"Score: {report.get('security_score')}/100"
    )

    lines.append(
        f"Risk: {report.get('risk_level')}"
    )

    lines.append("")

    lines.append(
        "Security Findings:"
    )


    for finding in report.get(
        "security_findings",
        [],
    ):

        lines.append(
            f"[{finding.get('severity')}] "
            f"{finding.get('title')}"
        )


    lines.append("")

    lines.append(
        "Informational:"
    )


    for finding in report.get(
        "informational",
        [],
    ):

        lines.append(
            f"[INFO] "
            f"{finding.get('title')}"
        )


    return "\n".join(lines)
