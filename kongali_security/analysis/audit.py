"""Security audit orchestration for Kongali Security."""

from __future__ import annotations

from typing import Any

from kongali_security.analysis.report import generate_report
from kongali_security.analysis.scan import analyze_scan


def analyze_audit(target: str) -> dict[str, Any]:
    """Run a complete security audit for a target."""

    scan_result = analyze_scan(target)

    report = generate_report(scan_result)

    return {
        "target": target,
        "audit_type": "security_assessment",
        "executive_summary": _build_executive_summary(report),
        "risk": {
            "overall_risk": report.get(
                "overall_risk",
                "UNKNOWN",
            ),
            "overall_score": report.get(
                "overall_score",
                0,
            ),
        },
        "findings": report.get(
            "findings",
            [],
        ),
        "summary": report.get(
            "summary",
            {},
        ),
        "scan": report.get(
            "scan",
            {},
        ),
        "recommendations": _build_recommendations(
            report
        ),
    }


def _build_executive_summary(
    report: dict[str, Any],
) -> str:
    """Build an executive security summary."""

    target = report.get(
        "target",
        "unknown target",
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

    total_findings = summary.get(
        "total_findings",
        0,
    )

    return (
        f"Security assessment for {target} identified "
        f"{total_findings} security finding(s). "
        f"The overall risk level is {risk} with "
        f"a security score of {score}/100. "
        "Organizations should prioritize remediation "
        "of high and critical severity findings."
    )


def _build_recommendations(
    report: dict[str, Any],
) -> list[dict[str, str]]:
    """Build remediation recommendations from findings."""

    recommendations: list[dict[str, str]] = []

    findings = report.get(
        "findings",
        [],
    )

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "LOW",
            )
        )

        category = str(
            finding.get(
                "category",
                "Security",
            )
        )

        title = str(
            finding.get(
                "title",
                "Security finding",
            )
        )

        if category == "HTTP Security Headers":
            recommendation = (
                "Configure the missing HTTP security header "
                "at the web server, reverse proxy, or application "
                "layer and verify the response after deployment."
            )
        else:
            recommendation = (
                "Review the finding and apply appropriate "
                "security remediation based on the affected "
                "component."
            )

        recommendations.append(
            {
                "severity": severity,
                "title": title,
                "recommendation": recommendation,
            }
        )

    return recommendations
