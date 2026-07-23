"""WAF detection analyzer for Kongali Security."""

from __future__ import annotations

from typing import Any

import requests


WAF_SIGNATURES = {
    "Cloudflare": [
        "cf-ray",
        "cloudflare",
        "__cf_bm",
        "cf_clearance",
    ],
    "AWS WAF": [
        "x-amzn-waf",
        "awselb",
    ],
    "Akamai": [
        "akamai",
        "x-akamai",
    ],
    "Imperva": [
        "imperva",
        "incap_ses",
    ],
    "Sucuri": [
        "sucuri",
    ],
    "F5 BIG-IP": [
        "bigip",
        "f5",
    ],
    "ModSecurity": [
        "mod_security",
        "modsecurity",
    ],
}


def analyze_waf(
    target: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Detect possible web application firewall."""

    result: dict[str, Any] = {
        "target": target,
        "detected": [],
        "headers": {},
        "findings": [],
    }

    try:
        response = requests.get(
            target,
            timeout=timeout,
        )

        headers = response.headers

        result["headers"] = dict(headers)

        combined = (
            str(headers).lower()
            + response.text.lower()
        )

        for waf, signatures in WAF_SIGNATURES.items():

            for signature in signatures:

                if signature.lower() in combined:

                    if waf not in result["detected"]:
                        result["detected"].append(
                            waf
                        )

                    break

        if result["detected"]:
            result["findings"].append(
                {
                    "id": "KONGALI-WAF-0001",
                    "title": (
                        "Web Application Firewall detected"
                    ),
                    "severity": "INFO",
                    "category": "WAF Detection",
                }
            )

        else:
            result["findings"].append(
                {
                    "id": "KONGALI-WAF-0002",
                    "title": (
                        "No WAF fingerprint detected"
                    ),
                    "severity": "INFO",
                    "category": "WAF Detection",
                }
            )

    except requests.RequestException as exc:
        result["findings"].append(
            {
                "id": "KONGALI-WAF-0003",
                "title": "WAF analysis failed",
                "severity": "LOW",
                "description": str(exc),
            }
        )

    return result
