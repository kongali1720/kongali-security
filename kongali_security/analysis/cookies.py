"""Cookie security analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


def analyze_cookies(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze HTTP cookie security attributes."""

    result: dict[str, Any] = {
        "target": target,
        "cookies": [],
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
        )

        cookies = response.cookies

        for cookie in cookies:
            item = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": (
                    "httponly"
                    in cookie._rest
                ),
                "samesite": (
                    cookie._rest.get(
                        "SameSite"
                    )
                ),
            }

            result["cookies"].append(
                item
            )

            if not cookie.secure:
                result["findings"].append(
                    {
                        "id": "KONGALI-COOKIE-0001",
                        "title": (
                            "Cookie missing Secure flag"
                        ),
                        "severity": "MEDIUM",
                        "category": "Cookie Security",
                    }
                )

            if (
                "httponly"
                not in cookie._rest
            ):
                result["findings"].append(
                    {
                        "id": "KONGALI-COOKIE-0002",
                        "title": (
                            "Cookie missing HttpOnly flag"
                        ),
                        "severity": "MEDIUM",
                        "category": "Cookie Security",
                    }
                )

            if not cookie._rest.get(
                "SameSite"
            ):
                result["findings"].append(
                    {
                        "id": "KONGALI-COOKIE-0003",
                        "title": (
                            "Cookie missing SameSite"
                        ),
                        "severity": "LOW",
                        "category": "Cookie Security",
                    }
                )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-COOKIE-0004",
                "title": "Cookie analysis failed",
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
