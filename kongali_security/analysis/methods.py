"""HTTP methods security analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


COMMON_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
    "TRACE",
]


def analyze_methods(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze allowed HTTP methods."""

    result: dict[str, Any] = {
        "target": target,
        "reachable": False,
        "allowed_methods": [],
        "findings": [],
    }

    for method in COMMON_METHODS:
        try:
            response = requests.request(
                method,
                target,
                timeout=timeout,
                allow_redirects=False,
            )

            result["reachable"] = True

            result["allowed_methods"].append(
                {
                    "method": method,
                    "status_code": response.status_code,
                }
            )

            if method == "TRACE" and response.status_code < 400:
                result["findings"].append(
                    {
                        "id": "KONGALI-METHODS-0001",
                        "title": "TRACE HTTP method enabled",
                        "severity": "MEDIUM",
                        "category": "HTTP Methods",
                        "description": (
                            "TRACE method is enabled."
                        ),
                        "remediation": (
                            "Disable TRACE method."
                        ),
                    }
                )

        except requests.RequestException:
            continue

    return result
