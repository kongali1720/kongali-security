"""Security baseline comparison utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON object from a file."""

    file_path = Path(path)

    with file_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "JSON root must be an object."
        )

    return data


def _finding_key(
    finding: dict[str, Any],
) -> tuple[str, str, str]:
    """Create a stable identifier for a finding."""

    return (
        str(finding.get("category", "")),
        str(finding.get("title", "")),
        str(finding.get("severity", "")),
    )


def compare_reports(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """Compare two security reports or baselines."""

    baseline_findings = {
        _finding_key(item)
        for item in baseline.get(
            "findings",
            [],
        )
        if isinstance(item, dict)
    }

    current_findings = {
        _finding_key(item)
        for item in current.get(
            "findings",
            [],
        )
        if isinstance(item, dict)
    }

    new_findings = sorted(
        current_findings - baseline_findings
    )

    resolved_findings = sorted(
        baseline_findings - current_findings
    )

    baseline_score = baseline.get(
        "overall_score",
        0,
    )

    current_score = current.get(
        "overall_score",
        0,
    )

    baseline_risk = baseline.get(
        "overall_risk",
        "UNKNOWN",
    )

    current_risk = current.get(
        "overall_risk",
        "UNKNOWN",
    )

    if current_score > baseline_score:
        trend = "IMPROVED"
    elif current_score < baseline_score:
        trend = "REGRESSED"
    else:
        trend = "UNCHANGED"

    return {
        "target": current.get(
            "target",
            baseline.get(
                "target",
                "",
            ),
        ),
        "baseline_risk": baseline_risk,
        "current_risk": current_risk,
        "baseline_score": baseline_score,
        "current_score": current_score,
        "score_change": (
            current_score - baseline_score
        ),
        "new_findings": [
            {
                "category": item[0],
                "title": item[1],
                "severity": item[2],
            }
            for item in new_findings
        ],
        "resolved_findings": [
            {
                "category": item[0],
                "title": item[1],
                "severity": item[2],
            }
            for item in resolved_findings
        ],
        "new_findings_count": len(
            new_findings
        ),
        "resolved_findings_count": len(
            resolved_findings
        ),
        "security_trend": trend,
        "regression": (
            current_score < baseline_score
        ),
    }
