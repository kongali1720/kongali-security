"""Executive Markdown report renderer."""

from __future__ import annotations

from typing import Any


def render_executive_markdown(
    report: dict[str, Any],
) -> str:
    """Render executive report to Markdown."""

    lines = []

    lines.append(
        "# KONGALI SECURITY EXECUTIVE REPORT"
    )

    lines.append("")

    lines.append(
        f"**Target:** {report.get('target')}"
    )

    lines.append("")

    lines.append(
        f"**Security Score:** "
        f"{report.get('security_score')}/100"
    )

    lines.append(
        f"**Risk Level:** "
        f"{report.get('risk_level')}"
    )

    lines.append("")

    lines.append(
        "## Security Summary"
    )

    lines.append("")

    for key, value in report.get(
        "summary",
        {},
    ).items():

        lines.append(
            f"- {key.title()}: {value}"
        )


    lines.append("")

    lines.append(
        "## Security Findings"
    )

    lines.append("")

    for finding in report.get(
        "security_findings",
        [],
    ):

        lines.append(
            f"- **{finding.get('severity')}** "
            f"{finding.get('title')}"
        )


    lines.append("")

    lines.append(
        "## Informational"
    )

    lines.append("")

    for finding in report.get(
        "informational",
        [],
    ):

        lines.append(
            f"- {finding.get('title')}"
        )


    return "\n".join(lines)
