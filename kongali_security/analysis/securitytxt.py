"""security.txt analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


def analyze_securitytxt(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze /.well-known/security.txt."""

    if target.endswith("/"):
        url = (
            target
            + ".well-known/security.txt"
        )
    else:
        url = (
            target
            + "/.well-known/security.txt"
        )

    result: dict[str, Any] = {
        "target": target,
        "securitytxt_url": url,
        "reachable": False,
        "status_code": None,
        "fields": {},
        "findings": [],
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
        )

        result["status_code"] = response.status_code

        if response.status_code == 200:
            result["reachable"] = True

            for line in response.text.splitlines():
                if ":" in line:
                    key, value = line.split(
                        ":",
                        1,
                    )

                    result["fields"][
                        key.strip()
                    ] = value.strip()

            if "Contact" not in result["fields"]:
                result["findings"].append(
                    {
                        "id": "KONGALI-SECURITYTXT-0001",
                        "title": (
                            "Security contact missing"
                        ),
                        "severity": "LOW",
                        "category": (
                            "Security Disclosure"
                        ),
                    }
                )

        else:
            result["findings"].append(
                {
                    "id": "KONGALI-SECURITYTXT-0002",
                    "title": (
                        "security.txt not found"
                    ),
                    "severity": "INFO",
                    "category": (
                        "Security Disclosure"
                    ),
                    "description": (
                        "No security.txt file published."
                    ),
                }
            )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-SECURITYTXT-0003",
                "title": (
                    "security.txt check failed"
                ),
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
