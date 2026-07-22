"""Security knowledge mappings for Kongali Security."""

from __future__ import annotations

from typing import Any

SECURITY_KNOWLEDGE: dict[str, dict[str, Any]] = {
    "Content-Security-Policy": {
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "impact": (
            "Missing Content-Security-Policy may reduce protection "
            "against content injection and cross-site scripting "
            "attack scenarios."
        ),
        "remediation": (
            "Implement a restrictive Content-Security-Policy "
            "appropriate to the application's resource requirements."
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/693.html",
        ],
    },
    "Strict-Transport-Security": {
        "cwe": {
            "id": "CWE-319",
            "name": "Cleartext Transmission of Sensitive Information",
        },
        "owasp": {
            "id": "A02:2021",
            "name": "Cryptographic Failures",
        },
        "impact": (
            "Without Strict-Transport-Security, clients may be more "
            "susceptible to protocol downgrade and insecure HTTP "
            "connection scenarios."
        ),
        "remediation": (
            "Enable Strict-Transport-Security over HTTPS with an "
            "appropriate max-age and consider includeSubDomains "
            "and preload where suitable."
        ),
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    },
    "X-Content-Type-Options": {
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "impact": (
            "Missing X-Content-Type-Options may allow browsers to "
            "perform MIME type sniffing, increasing exposure to "
            "content interpretation attacks."
        ),
        "remediation": (
            "Set the X-Content-Type-Options response header to "
            "nosniff."
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/693.html",
        ],
    },
    "X-Frame-Options": {
        "cwe": {
            "id": "CWE-1021",
            "name": "Improper Restriction of Rendered UI Layers "
            "or Frames",
        },
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "impact": (
            "Missing X-Frame-Options may increase exposure to "
            "clickjacking attacks where an application is embedded "
            "inside a malicious frame."
        ),
        "remediation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN according "
            "to the application's embedding requirements."
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/1021.html",
        ],
    },
    "Referrer-Policy": {
        "cwe": {
            "id": "CWE-200",
            "name": "Exposure of Sensitive Information to an "
            "Unauthorized Actor",
        },
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "impact": (
            "An absent or weak Referrer-Policy may expose URL "
            "information to external origins through the Referer "
            "header."
        ),
        "remediation": (
            "Configure a restrictive Referrer-Policy such as "
            "strict-origin-when-cross-origin or stricter where "
            "appropriate."
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    },
    "Permissions-Policy": {
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "impact": (
            "Missing Permissions-Policy may allow browser features "
            "to remain available when they are not required by the "
            "application."
        ),
        "remediation": (
            "Define a restrictive Permissions-Policy that disables "
            "unnecessary browser capabilities."
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/693.html",
        ],
    },
}


def get_security_knowledge(
    finding_key: str,
) -> dict[str, Any]:
    """Return security knowledge for a finding key."""

    return SECURITY_KNOWLEDGE.get(
        finding_key,
        {
            "cwe": {
                "id": "CWE-693",
                "name": "Protection Mechanism Failure",
            },
            "owasp": {
                "id": "A05:2021",
                "name": "Security Misconfiguration",
            },
            "impact": (
                "The identified security control is not configured "
                "according to recommended security practices."
            ),
            "remediation": (
                "Review and implement the recommended security "
                "control according to the application's requirements."
            ),
            "references": [
                "https://owasp.org/Top10/",
                "https://cwe.mitre.org/",
            ],
        },
    )
