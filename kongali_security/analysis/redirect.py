"""HTTP redirect security analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


def analyze_redirect(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze HTTP redirect behavior."""

    result: dict[str, Any] = {
        "target": target,
        "status_code": None,
        "final_url": None,
        "redirect_chain": [],
        "redirect_count": 0,
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
            allow_redirects=True,
        )

        result["status_code"] = response.status_code
        result["final_url"] = response.url

        for item in response.history:
            result["redirect_chain"].append(
                {
                    "status_code": item.status_code,
                    "url": item.url,
                    "location": item.headers.get(
                        "Location"
                    ),
                }
            )

        result["redirect_count"] = len(
            response.history
        )

        if result["redirect_count"] > 5:
            result["findings"].append(
                {
                    "id": "KONGALI-REDIRECT-0001",
                    "title": "Excessive redirect chain",
                    "severity": "MEDIUM",
                    "category": "HTTP Redirect",
                    "description": (
                        "The target contains too many redirects."
                    ),
                    "remediation": (
                        "Reduce redirect chain length."
                    ),
                }
            )

        if (
            target.startswith("http://")
            and str(response.url).startswith("https://")
        ):
            result["findings"].append(
                {
                    "id": "KONGALI-REDIRECT-0002",
                    "title": "HTTP to HTTPS redirect detected",
                    "severity": "LOW",
                    "category": "Transport Security",
                    "description": (
                        "HTTP traffic redirects to HTTPS."
                    ),
                    "remediation": (
                        "Prefer direct HTTPS links."
                    ),
                }
            )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-REDIRECT-0003",
                "title": "Redirect analysis failed",
                "severity": "LOW",
                "category": "HTTP Redirect",
                "description": str(exc),
                "remediation": (
                    "Verify target availability."
                ),
            }
        )

    return result
