"""Executive PDF report renderer."""

from __future__ import annotations

from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)


def render_executive_pdf(
    report: dict[str, Any],
    output: str,
) -> str:
    """Generate executive PDF report."""

    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
    )

    styles = getSampleStyleSheet()

    story = []


    story.append(
        Paragraph(
            "KONGALI SECURITY EXECUTIVE REPORT",
            styles["Title"],
        )
    )

    story.append(
        Spacer(1, 20)
    )


    lines = [
        f"Target: {report.get('target')}",
        (
            f"Security Score: "
            f"{report.get('security_score')}/100"
        ),
        (
            f"Risk Level: "
            f"{report.get('risk_level')}"
        ),
        "",
        "Security Findings:",
    ]


    for finding in report.get(
        "security_findings",
        [],
    ):

        lines.append(
            (
                f"[{finding.get('severity')}] "
                f"{finding.get('title')}"
            )
        )


    lines.append("")
    lines.append("Informational:")


    for finding in report.get(
        "informational",
        [],
    ):

        lines.append(
            (
                f"[INFO] "
                f"{finding.get('title')}"
            )
        )


    for line in lines:

        story.append(
            Paragraph(
                line,
                styles["BodyText"],
            )
        )

        story.append(
            Spacer(
                1,
                8,
            )
        )


    doc.build(
        story
    )

    return output
