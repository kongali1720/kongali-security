"""Batch security scanner for Kongali Security."""

from __future__ import annotations

from typing import Any

from kongali_security.analysis.scan import analyze_scan


def analyze_batch(
    targets_file: str,
) -> dict[str, Any]:
    """Run security scan for multiple targets."""

    result: dict[str, Any] = {
        "targets_file": targets_file,
        "total": 0,
        "completed": 0,
        "failed": 0,
        "results": [],
    }

    with open(
        targets_file,
        "r",
        encoding="utf-8",
    ) as file:

        targets = [
            line.strip()
            for line in file.readlines()
            if line.strip()
        ]

    result["total"] = len(targets)

    for target in targets:

        try:

            scan_result = analyze_scan(
                target
            )

            result["results"].append(
                {
                    "target": target,
                    "status": "DONE",
                    "result": scan_result,
                }
            )

            result["completed"] += 1

        except Exception as exc:

            result["results"].append(
                {
                    "target": target,
                    "status": "FAILED",
                    "error": str(exc),
                }
            )

            result["failed"] += 1

    return result
