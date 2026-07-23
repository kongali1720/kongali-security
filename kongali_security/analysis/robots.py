"""robots.txt security analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


SENSITIVE_WORDS = [
    "admin",
    "login",
    "backup",
    "private",
    "config",
    "database",
]


def analyze_robots(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze robots.txt file."""

    if target.endswith("/"):
        robots_url = target + "robots.txt"
    else:
        robots_url = target + "/robots.txt"

    result: dict[str, Any] = {
        "target": target,
        "robots_url": robots_url,
        "reachable": False,
        "status_code": None,
        "disallow": [],
        "allow": [],
        "findings": [],
    }

    try:
        response = requests.get(
            robots_url,
            timeout=timeout,
        )

        result["status_code"] = response.status_code

        if response.status_code != 200:
            result["findings"].append(
                {
                    "id": "KONGALI-ROBOTS-0003",
                    "title": "robots.txt not found",
                    "severity": "INFO",
                    "category": "Information Disclosure",
                    "description": (
                        "The target does not expose a robots.txt file."
                    ),
                    "remediation": (
                        "Consider publishing robots.txt "
                        "according to website requirements."
                    ),
                }
            )

        if response.status_code == 200:
            result["reachable"] = True

            for line in response.text.splitlines():

                line = line.strip()

                if line.lower().startswith(
                    "disallow:"
                ):
                    path = line.split(
                        ":",
                        1,
                    )[1].strip()

                    result["disallow"].append(
                        path
                    )

                    lower_path = path.lower()

                    for word in SENSITIVE_WORDS:
                        if word in lower_path:
                            result["findings"].append(
                                {
                                    "id": "KONGALI-ROBOTS-0001",
                                    "title": (
                                        "Sensitive path exposed "
                                        "in robots.txt"
                                    ),
                                    "severity": "MEDIUM",
                                    "category": (
                                        "Information Disclosure"
                                    ),
                                    "path": path,
                                }
                            )

                elif line.lower().startswith(
                    "allow:"
                ):
                    result["allow"].append(
                        line.split(
                            ":",
                            1,
                        )[1].strip()
                    )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-ROBOTS-0002",
                "title": "robots.txt unavailable",
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
