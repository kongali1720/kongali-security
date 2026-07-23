"""Password security analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any
import re

import requests
from bs4 import BeautifulSoup


PASSWORD_PATTERNS = [
    r"password\s*=",
    r"passwd\s*=",
    r"secret\s*=",
    r"pwd\s*=",
]


def analyze_password(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Perform defensive password security checks."""

    result: dict[str, Any] = {
        "target": target,
        "https": target.startswith("https://"),
        "password_fields": [],
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
        )

        html = response.text

        soup = BeautifulSoup(
            html,
            "html.parser",
        )

        password_inputs = soup.find_all(
            "input",
            {
                "type": "password"
            },
        )

        for item in password_inputs:

            field = {
                "name": item.get("name"),
                "autocomplete": item.get(
                    "autocomplete"
                ),
            }

            result["password_fields"].append(
                field
            )

            if item.get(
                "autocomplete"
            ) == "off":

                result["findings"].append(
                    {
                        "id": "KONGALI-PASSWORD-0001",
                        "title": (
                            "Password autocomplete disabled"
                        ),
                        "severity": "INFO",
                        "category": (
                            "Password Security"
                        ),
                    }
                )

        for pattern in PASSWORD_PATTERNS:

            if re.search(
                pattern,
                html,
                re.IGNORECASE,
            ):

                result["findings"].append(
                    {
                        "id": "KONGALI-PASSWORD-0002",
                        "title": (
                            "Possible credential pattern exposed"
                        ),
                        "severity": "HIGH",
                        "category": (
                            "Credential Exposure"
                        ),
                    }
                )

                break


        if not result["https"]:

            result["findings"].append(
                {
                    "id": "KONGALI-PASSWORD-0003",
                    "title": (
                        "Password page not using HTTPS"
                    ),
                    "severity": "HIGH",
                    "category": (
                        "Transport Security"
                    ),
                }
            )

    except requests.RequestException as exc:

        result["findings"].append(
            {
                "id": "KONGALI-PASSWORD-0004",
                "title": (
                    "Password analysis failed"
                ),
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
