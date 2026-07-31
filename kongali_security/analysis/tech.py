"""Technology detection analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


TECH_SIGNATURES = {
    "nginx": [
        "nginx",
    ],
    "Apache": [
        "apache",
    ],
    "Cloudflare": [
        "cloudflare",
        "cf-ray",
    ],
    "PHP": [
        "x-powered-by: php",
        ".php",
    ],
    "WordPress": [
        "wp-content",
        "wordpress",
    ],
    "Laravel": [
        "laravel",
    ],
    "Django": [
        "csrfmiddlewaretoken",
        "django",
    ],
}


def analyze_tech(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Detect technologies from HTTP response."""

    result: dict[str, Any] = {
        "target": target,
        "technologies": [],
        "headers": {},
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
        )

        headers = response.headers

        result["headers"] = dict(
            headers
        )

        content = (
            response.text.lower()
        )

        header_text = (
            str(headers).lower()
        )

        combined = (
            content
            + header_text
        )

        for tech, signatures in TECH_SIGNATURES.items():

            for signature in signatures:

                if signature.lower() in combined:

                    if tech not in result["technologies"]:
                        result["technologies"].append(
                            tech
                        )

                    break

        server = headers.get(
            "Server"
        )

        if server:
            result["findings"].append(
                {
                    "id": "KONGALI-TECH-0001",
                    "title": (
                        "Server technology exposed"
                    ),
                    "severity": "LOW",
                    "category": (
                        "Information Disclosure"
                    ),
                    "server": server,
                }
            )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-TECH-0002",
                "title": (
                    "Technology detection failed"
                ),
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
