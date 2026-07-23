"""Security baseline management for Kongali Security."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from kongali_security.analysis.audit import analyze_audit


def create_baseline(
    target: str,
) -> dict[str, Any]:
    """Create a security baseline for a target."""

    audit = analyze_audit(target)

    return {
        "baseline_version": "1.0",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": target,
        "overall_risk": audit["risk"]["overall_risk"],
        "overall_score": audit["risk"]["overall_score"],
        "findings": audit.get(
            "findings",
            [],
        ),
        "summary": audit.get(
            "summary",
            {},
        ),
        "recommendations": audit.get(
            "recommendations",
            [],
        ),
        "audit": audit,
    }


def save_baseline(
    baseline: dict[str, Any],
    output: str,
) -> None:
    """Save a baseline to a JSON file."""

    path = Path(output)

    path.write_text(
        json.dumps(
            baseline,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )


def load_baseline(
    source: str,
) -> dict[str, Any]:
    """Load a baseline from a JSON file."""

    path = Path(source)

    return cast(
        dict[str, Any],
        json.loads(
            path.read_text(
                encoding="utf-8",
            )
        ),
    )
