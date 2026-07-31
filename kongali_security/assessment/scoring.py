"""Assessment risk scoring engine."""

from __future__ import annotations

from typing import Any


SEVERITY_SCORE = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}


def calculate_assessment_score(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate security posture score.
    """

    score = 100
    deductions = []

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


    for finding in findings:

        severity = (
            finding.get(
                "severity",
                "INFO",
            )
            .upper()
        )

        deduction = SEVERITY_SCORE.get(
            severity,
            0,
        )

        score -= deduction


        key = severity.lower()

        if key in summary:
            summary[key] += 1


        if deduction:

            deductions.append(
                {
                    "title": finding.get(
                        "title"
                    ),
                    "severity": severity,
                    "deduction": deduction,
                }
            )


    score = max(
        score,
        0,
    )


    if score >= 90:
        risk = "LOW"

    elif score >= 70:
        risk = "MEDIUM"

    elif score >= 40:
        risk = "HIGH"

    else:
        risk = "CRITICAL"


    return {
        "security_score": score,
        "risk_level": risk,
        "summary": summary,
        "deductions": deductions,
        "total_findings": len(findings),
    }
