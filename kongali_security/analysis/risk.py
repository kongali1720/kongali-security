"""Risk scoring engine for Kongali Security."""

from __future__ import annotations

from typing import Any


SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}


def calculate_risk_level(
    score: int,
) -> str:
    """Convert security score into risk level."""

    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"



def collect_findings(
    data: Any,
) -> list[dict[str, Any]]:
    """
    Recursively collect findings
    from security scan results.
    """

    findings: list[dict[str, Any]] = []


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



def calculate_risk(
    report: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate overall security risk score.

    Base score:
        100

    Deduction:
        CRITICAL : -40
        HIGH     : -20
        MEDIUM   : -10
        LOW      : -5
        INFO     : 0
    """

    score = 100

    findings = collect_findings(
        report
    )

    deductions = []


    for finding in findings:

        severity = (
            finding.get(
                "severity",
                "INFO",
            )
            .upper()
        )


        deduction = SEVERITY_WEIGHT.get(
            severity,
            0,
        )


        if deduction:

            score -= deduction

            deductions.append(
                {
                    "title": finding.get(
                        "title",
                        "Unknown finding",
                    ),
                    "severity": severity,
                    "deduction": deduction,
                }
            )


    score = max(
        score,
        0,
    )


    return {
        "score": score,
        "risk_level": calculate_risk_level(
            score
        ),
        "total_findings": len(
            findings
        ),
        "deductions": deductions,
        "summary": {
            "critical": sum(
                1
                for f in findings
                if f.get(
                    "severity",
                    "",
                ).upper()
                == "CRITICAL"
            ),
            "high": sum(
                1
                for f in findings
                if f.get(
                    "severity",
                    "",
                ).upper()
                == "HIGH"
            ),
            "medium": sum(
                1
                for f in findings
                if f.get(
                    "severity",
                    "",
                ).upper()
                == "MEDIUM"
            ),
            "low": sum(
                1
                for f in findings
                if f.get(
                    "severity",
                    "",
                ).upper()
                == "LOW"
            ),
        },
    }
