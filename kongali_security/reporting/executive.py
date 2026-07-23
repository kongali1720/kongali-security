"""Executive security report generator."""

from __future__ import annotations

from typing import Any


def _collect_findings(
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
                    _collect_findings(value)
                )

    elif isinstance(data, list):

        for item in data:
            findings.extend(
                _collect_findings(item)
            )

    return findings



def generate_executive_report(
    scan_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate human-readable security summary.
    """

    risk = scan_result.get(
        "risk",
        {},
    )

    findings = _collect_findings(
        scan_result
    )

    top_findings = []

    for finding in findings[:10]:

        top_findings.append(
            {
                "title": finding.get(
                    "title",
                    "Unknown",
                ),
                "severity": finding.get(
                    "severity",
                    "INFO",
                ),
                "category": finding.get(
                    "category",
                    "Unknown",
                ),
            }
        )


    recommendations = []

    for finding in findings:

        remediation = finding.get(
            "remediation"
        )

        if remediation:

            recommendations.append(
                remediation
            )


    return {
        "title": "Kongali Security Executive Report",
        "target": scan_result.get(
            "target"
        ),
        "security_score": risk.get(
            "score",
            100,
        ),
        "risk_level": risk.get(
            "risk_level",
            "UNKNOWN",
        ),
        "summary": risk.get(
            "summary",
            {},
        ),
        "total_findings": len(
            findings
        ),
        "top_findings": top_findings,
        "recommendations": recommendations[:10],
    }
