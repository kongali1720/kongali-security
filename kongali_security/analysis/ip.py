"""IP Intelligence analyzer for Kongali Security."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any


CLOUD_SIGNATURES = {
    "googleusercontent.com": "Google Cloud",
    "amazonaws.com": "AWS",
    "compute.amazonaws.com": "AWS",
    "azure.com": "Microsoft Azure",
    "cloudflare.com": "Cloudflare",
}


def detect_cloud_provider(
    hostname: str | None,
) -> str | None:
    """Detect common cloud providers from reverse DNS."""

    if not hostname:
        return None

    hostname = hostname.lower()

    for signature, provider in CLOUD_SIGNATURES.items():

        if signature in hostname:
            return provider

    return None


def analyze_ip(
    target: str,
) -> dict[str, Any]:
    """
    Perform defensive IP intelligence analysis.
    """

    result: dict[str, Any] = {
        "target": target,
        "valid": False,
        "version": None,
        "type": None,
        "private": False,
        "reverse_dns": None,
        "cloud_provider": None,
        "risk": "UNKNOWN",
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


        if ip.is_private:

            result["type"] = "PRIVATE"

            result["risk"] = "LOW"

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

            result["type"] = "PUBLIC"

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


        try:

            hostname = socket.gethostbyaddr(
                target
            )[0]

            result["reverse_dns"] = hostname


            provider = detect_cloud_provider(
                hostname
            )

            if provider:

                result["cloud_provider"] = (
                    provider
                )

                result["findings"].append(
                    {
                        "id": "KONGALI-IP-0003",
                        "title": (
                            f"Cloud provider detected: {provider}"
                        ),
                        "severity": "INFO",
                        "category": (
                            "Infrastructure Intelligence"
                        ),
                    }
                )


        except Exception:

            result["reverse_dns"] = None



        if result["type"] == "PUBLIC":

            if result["cloud_provider"]:

                result["risk"] = "LOW"

            else:

                result["risk"] = "MEDIUM"



    except ValueError:


        result["findings"].append(
            {
                "id": "KONGALI-IP-0004",
                "title": (
                    "Invalid IP address"
                ),
                "severity": "LOW",
                "category": "IP Validation",
            }
        )


    return result
