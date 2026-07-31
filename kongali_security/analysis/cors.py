"""CORS security analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


def analyze_cors(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze Cross-Origin Resource Sharing policy."""

    result: dict[str, Any] = {
        "target": target,
        "headers": {},
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
        )

        headers = response.headers

        cors_headers = {
            key: value
            for key, value in headers.items()
            if key.lower().startswith(
                "access-control"
            )
        }

        result["headers"] = cors_headers

        origin = headers.get(
            "Access-Control-Allow-Origin"
        )

        credentials = headers.get(
            "Access-Control-Allow-Credentials"
        )

        if origin == "*":
            result["findings"].append(
                {
                    "id": "KONGALI-CORS-0001",
                    "title": (
                        "Wildcard CORS origin enabled"
                    ),
                    "severity": "MEDIUM",
                    "category": "CORS Security",
                    "description": (
                        "Access-Control-Allow-Origin "
                        "allows all origins."
                    ),
                    "remediation": (
                        "Restrict allowed origins."
                    ),
                }
            )

        if (
            origin == "*"
            and credentials == "true"
        ):
            result["findings"].append(
                {
                    "id": "KONGALI-CORS-0002",
                    "title": (
                        "Unsafe CORS credentials"
                    ),
                    "severity": "HIGH",
                    "category": "CORS Security",
                    "description": (
                        "Wildcard origin with "
                        "credentials enabled."
                    ),
                    "remediation": (
                        "Disable wildcard origin "
                        "when using credentials."
                    ),
                }
            )

        if not origin:
            result["findings"].append(
                {
                    "id": "KONGALI-CORS-0003",
                    "title": (
                        "CORS header not detected"
                    ),
                    "severity": "INFO",
                    "category": "CORS Security",
                    "description": (
                        "No Access-Control-Allow-Origin "
                        "header found."
                    ),
                }
            )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-CORS-0004",
                "title": "CORS analysis failed",
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
