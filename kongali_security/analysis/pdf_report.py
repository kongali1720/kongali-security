"""Professional PDF security assessment report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _safe(value: Any, default: str = "") -> str:
    """Convert values safely to strings."""
    if value is None:
        return default

    return str(value)


def _severity_color(severity: str):
    """Return a color for a severity level."""
    colors_map = {
        "CRITICAL": colors.HexColor("#7F1D1D"),
        "HIGH": colors.HexColor("#B91C1C"),
        "MEDIUM": colors.HexColor("#D97706"),
        "LOW": colors.HexColor("#2563EB"),
        "INFO": colors.HexColor("#6B7280"),
    }

    return colors_map.get(
        severity.upper(),
        colors.HexColor("#374151"),
    )


def generate_pdf_report(
    report: dict[str, Any],
    output_path: str,
) -> None:
    """Generate a professional PDF security assessment report."""

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Kongali Security Assessment Report",
        author="Kongali Security",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "KongaliTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        leading=28,
        spaceAfter=12,
    )

    subtitle_style = ParagraphStyle(
        "KongaliSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.HexColor("#4B5563"),
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "KongaliHeading",
        parent=styles["Heading2"],
        fontSize=15,
        leading=20,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "KongaliBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "KongaliSmall",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
    )

    target = _safe(
        report.get(
            "target",
            "Unknown",
        )
    )

    risk = _safe(
        report.get(
            "overall_risk",
            "UNKNOWN",
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

    metadata = report.get(
        "metadata",
        {},
    )

    generated_at = metadata.get(
        "generated_at",
        datetime.now(
            timezone.utc
        ).isoformat(),
    )

    story = []

    # Cover
    story.append(
        Spacer(
            1,
            30 * mm,
        )
    )

    story.append(
        Paragraph(
            "KONGALI SECURITY",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Professional Security Assessment Report",
            subtitle_style,
        )
    )

    cover_data = [
        [
            Paragraph(
                "<b>Target</b>",
                body_style,
            ),
            Paragraph(
                target,
                body_style,
            ),
        ],
        [
            Paragraph(
                "<b>Overall Risk</b>",
                body_style,
            ),
            Paragraph(
                risk,
                body_style,
            ),
        ],
        [
            Paragraph(
                "<b>Security Score</b>",
                body_style,
            ),
            Paragraph(
                f"{score}/100",
                body_style,
            ),
        ],
        [
            Paragraph(
                "<b>Generated</b>",
                body_style,
            ),
            Paragraph(
                _safe(generated_at),
                body_style,
            ),
        ],
        [
            Paragraph(
                "<b>Scanner</b>",
                body_style,
            ),
            Paragraph(
                "Kongali Security",
                body_style,
            ),
        ],
        [
            Paragraph(
                "<b>Scanner Version</b>",
                body_style,
            ),
            Paragraph(
                _safe(
                    metadata.get(
                        "version",
                        "unknown",
                    )
                ),
                body_style,
            ),
        ],
    ]

    cover_table = Table(
        cover_data,
        colWidths=[
            45 * mm,
            120 * mm,
        ],
    )

    cover_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#D1D5DB"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F3F4F6"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        cover_table
    )

    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            "Confidential Security Assessment",
            subtitle_style,
        )
    )

    story.append(
        PageBreak()
    )

    # Executive Summary
    story.append(
        Paragraph(
            "1. Executive Summary",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            (
                "This security assessment was generated by Kongali Security "
                "to identify security weaknesses and provide actionable "
                "remediation guidance. Findings are categorized by severity "
                "and enriched with OWASP Top 10, CWE, CVSS, impact, evidence, "
                "and remediation information where available."
            ),
            body_style,
        )
    )

    summary_data = [
        [
            "Metric",
            "Value",
        ],
        [
            "Target",
            target,
        ],
        [
            "Overall Risk",
            risk,
        ],
        [
            "Security Score",
            f"{score}/100",
        ],
        [
            "Total Findings",
            str(
                summary.get(
                    "total_findings",
                    len(findings),
                )
            ),
        ],
        [
            "Critical",
            str(
                severity_counts.get(
                    "CRITICAL",
                    0,
                )
            ),
        ],
        [
            "High",
            str(
                severity_counts.get(
                    "HIGH",
                    0,
                )
            ),
        ],
        [
            "Medium",
            str(
                severity_counts.get(
                    "MEDIUM",
                    0,
                )
            ),
        ],
        [
            "Low",
            str(
                severity_counts.get(
                    "LOW",
                    0,
                )
            ),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            60 * mm,
            105 * mm,
        ],
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#D1D5DB"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#111827"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    story.append(
        summary_table
    )

    # Findings
    story.append(
        Paragraph(
            "2. Security Findings",
            heading_style,
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No security findings were identified.",
                body_style,
            )
        )

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        severity = _safe(
            finding.get(
                "severity",
                "UNKNOWN",
            )
        ).upper()

        title = _safe(
            finding.get(
                "title",
                "Unknown Finding",
            )
        )

        category = _safe(
            finding.get(
                "category",
                "Unknown",
            )
        )

        description = _safe(
            finding.get(
                "description",
                "",
            )
        )

        owasp = finding.get(
            "owasp",
            "N/A",
        )

        cwe = finding.get(
            "cwe",
            "N/A",
        )

        impact = _safe(
            finding.get(
                "impact",
                "Not provided.",
            )
        )

        remediation = _safe(
            finding.get(
                "remediation",
                "No remediation guidance provided.",
            )
        )

        evidence = finding.get(
            "evidence",
            {},
        )

        cvss = finding.get(
            "cvss",
            {},
        )

        story.append(
            Paragraph(
                f"{index}. {title}",
                heading_style,
            )
        )

        finding_data = [
            [
                Paragraph(
                    "<b>Severity</b>",
                    small_style,
                ),
                Paragraph(
                    severity,
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Category</b>",
                    small_style,
                ),
                Paragraph(
                    category,
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>OWASP</b>",
                    small_style,
                ),
                Paragraph(
                    _safe(owasp),
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>CWE</b>",
                    small_style,
                ),
                Paragraph(
                    _safe(cwe),
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>CVSS</b>",
                    small_style,
                ),
                Paragraph(
                    _safe(
                        cvss.get(
                            "score",
                            "N/A",
                        )
                    ),
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>CVSS Vector</b>",
                    small_style,
                ),
                Paragraph(
                    _safe(
                        cvss.get(
                            "vector",
                            "N/A",
                        )
                    ),
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Description</b>",
                    small_style,
                ),
                Paragraph(
                    description,
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Impact</b>",
                    small_style,
                ),
                Paragraph(
                    impact,
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Remediation</b>",
                    small_style,
                ),
                Paragraph(
                    remediation,
                    small_style,
                ),
            ],
            [
                Paragraph(
                    "<b>Evidence</b>",
                    small_style,
                ),
                Paragraph(
                    _safe(evidence),
                    small_style,
                ),
            ],
        ]

        finding_table = Table(
            finding_data,
            colWidths=[
                38 * mm,
                127 * mm,
            ],
        )

        finding_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#D1D5DB"),
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.HexColor("#F3F4F6"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TEXTCOLOR",
                        (1, 0),
                        (1, 0),
                        _severity_color(
                            severity
                        ),
                    ),
                ]
            )
        )

        story.append(
            finding_table
        )

        story.append(
            Spacer(
                1,
                8,
            )
        )

    # Methodology
    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "3. Assessment Methodology",
            heading_style,
        )
    )

    methodology = [
        "HTTP security header analysis",
        "Security finding classification",
        "OWASP Top 10 mapping",
        "CWE classification",
        "CVSS v3.1 risk scoring",
        "Evidence collection",
        "Remediation guidance",
        "SARIF-compatible security reporting",
        "Baseline security regression comparison",
    ]

    for item in methodology:
        story.append(
            Paragraph(
                f"• {item}",
                body_style,
            )
        )

    story.append(
        Paragraph(
            "4. Risk Interpretation",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            (
                "Risk ratings should be interpreted in the context of the "
                "application, deployment architecture, exposed attack "
                "surface, business impact, and existing compensating controls. "
                "CVSS scores provide a standardized technical severity "
                "indicator and should not replace organizational risk analysis."
            ),
            body_style,
        )
    )

    story.append(
        Paragraph(
            "5. Recommendations",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            (
                "Prioritize remediation of Critical and High severity findings. "
                "After remediation, rerun Kongali Security and compare the "
                "new assessment against the established security baseline. "
                "Integrate SARIF output into CI/CD pipelines to detect "
                "security regressions before changes are merged."
            ),
            body_style,
        )
    )

    story.append(
        Spacer(
            1,
            15,
        )
    )

    story.append(
        Paragraph(
            "Generated by Kongali Security",
            subtitle_style,
        )
    )

    doc.build(
        story
    )
