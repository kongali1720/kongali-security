"""Content Security Policy analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


def analyze_csp(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze Content-Security-Policy header."""

    result: dict[str, Any] = {
        "target": target,
        "csp": None,
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
        )

        csp = response.headers.get(
            "Content-Security-Policy"
        )

        result["csp"] = csp

        if not csp:
            result["findings"].append(
                {
                    "id": "KONGALI-CSP-0001",
                    "title": (
                        "Content-Security-Policy missing"
                    ),
                    "severity": "MEDIUM",
                    "category": "CSP Security",
                }
            )

            return result

        if "'unsafe-inline'" in csp:
            result["findings"].append(
                {
                    "id": "KONGALI-CSP-0002",
                    "title": (
                        "CSP allows unsafe-inline"
                    ),
                    "severity": "MEDIUM",
                    "category": "CSP Security",
                }
            )

        if "'unsafe-eval'" in csp:
            result["findings"].append(
                {
                    "id": "KONGALI-CSP-0003",
                    "title": (
                        "CSP allows unsafe-eval"
                    ),
                    "severity": "HIGH",
                    "category": "CSP Security",
                }
            )

        if "*" in csp:
            result["findings"].append(
                {
                    "id": "KONGALI-CSP-0004",
                    "title": (
                        "CSP contains wildcard source"
                    ),
                    "severity": "MEDIUM",
                    "category": "CSP Security",
                }
            )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-CSP-0005",
                "title": "CSP analysis failed",
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
