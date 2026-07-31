"""Executive assessment summary generator."""

from __future__ import annotations

from typing import Any


def build_executive_summary(
    assessment: dict[str, Any],
) -> dict[str, Any]:

    return {

        "title":
            "Kongali Security Assessment Summary",

        "security_score":
            assessment.get(
                "security_score"
            ),

        "risk_level":
            assessment.get(
                "risk_level"
            ),

        "summary":
            assessment.get(
                "summary"
            ),

        "priority":
            (
                "Immediate remediation required"
                if assessment.get(
                    "risk_level"
                )
                in [
                    "HIGH",
                    "CRITICAL",
                ]
                else
                "Security posture acceptable"
            ),
    }
