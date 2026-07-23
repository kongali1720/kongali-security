"""IP intelligence analyzer for Kongali Security."""

from __future__ import annotations

import socket
import ipaddress
from typing import Any


def analyze_ip(
    target: str,
) -> dict[str, Any]:
    """Perform defensive IP analysis."""

    result: dict[str, Any] = {
        "target": target,
        "valid": False,
        "version": None,
        "private": False,
        "reverse_dns": None,
        "findings": [],
    }

    try:

        ip = ipaddress.ip_address(
            target
        )

        result["valid"] = True
        result["version"] = (
            f"IPv{ip.version}"
        )
        result["private"] = (
            ip.is_private
        )

        try:
            result["reverse_dns"] = (
                socket.gethostbyaddr(target)[0]
            )

        except Exception:
            result["reverse_dns"] = None


        if ip.is_private:

            result["findings"].append(
                {
                    "id": "KONGALI-IP-0001",
                    "title": (
                        "Private IP address detected"
                    ),
                    "severity": "INFO",
                    "category": "IP Intelligence",
                }
            )


        else:

            result["findings"].append(
                {
                    "id": "KONGALI-IP-0002",
                    "title": (
                        "Public IP address detected"
                    ),
                    "severity": "INFO",
                    "category": "IP Intelligence",
                }
            )


    except ValueError:

        result["findings"].append(
            {
                "id": "KONGALI-IP-0003",
                "title": (
                    "Invalid IP address"
                ),
                "severity": "LOW",
                "category": "IP Validation",
            }
        )


    return result
