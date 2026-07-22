"""OWASP Top 10 mapping engine for Kongali Security."""

from __future__ import annotations

from typing import Any, Dict


OWASP_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "Content-Security-Policy": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "impact": (
            "Missing Content-Security-Policy may increase "
            "the risk of client-side injection and content "
            "execution attacks."
        ),
        "remediation": (
            "Implement a restrictive Content-Security-Policy "
            "appropriate for the application."
        ),
    },
    "Strict-Transport-Security": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-319",
            "name": "Cleartext Transmission of Sensitive Information",
        },
        "impact": (
            "Without HSTS, users may be exposed to protocol "
            "downgrade or insecure HTTP connections."
        ),
        "remediation": (
            "Enable HTTP Strict Transport Security with an "
            "appropriate max-age and HTTPS deployment."
        ),
    },
    "X-Content-Type-Options": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "impact": (
            "Missing X-Content-Type-Options may allow browsers "
            "to MIME-sniff responses unexpectedly."
        ),
        "remediation": (
            "Set the X-Content-Type-Options header to nosniff."
        ),
    },
    "X-Frame-Options": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "impact": (
            "Missing clickjacking protection may allow malicious "
            "sites to frame the application."
        ),
        "remediation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, "
            "or use an appropriate CSP frame-ancestors policy."
        ),
    },
    "Referrer-Policy": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-200",
            "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        },
        "impact": (
            "An overly permissive referrer policy may expose "
            "sensitive URL information to external origins."
        ),
        "remediation": (
            "Configure a restrictive Referrer-Policy such as "
            "strict-origin-when-cross-origin."
        ),
    },
    "Permissions-Policy": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "impact": (
            "Missing Permissions-Policy may allow unnecessary "
            "browser capabilities to remain available."
        ),
        "remediation": (
            "Configure Permissions-Policy to explicitly restrict "
            "unnecessary browser capabilities."
        ),
    },
}


def get_owasp_mapping(
    header: str,
) -> Dict[str, Any]:
    """Return OWASP, CWE, impact, and remediation metadata."""

    mapping = OWASP_MAPPINGS.get(
        header,
    )

    if mapping:
        return mapping.copy()

    return {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "impact": (
            "The security control is not configured according "
            "to recommended security practices."
        ),
        "remediation": (
            "Review and harden the affected security control "
            "according to application requirements."
        ),
    }
