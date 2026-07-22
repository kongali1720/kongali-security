"""Unified security assessment engine for Kongali Security."""

from __future__ import annotations

from typing import Any, Dict, List

from kongali_security.analysis.headers import analyze_headers
from kongali_security.analysis.tls import analyze_tls
from kongali_security.analysis.url import analyze_url


HEADER_KNOWLEDGE = {
    "Content-Security-Policy": {
        "owasp": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
        },
        "cwe": {
            "id": "CWE-693",
            "name": "Protection Mechanism Failure",
        },
        "cvss": {
            "version": "3.1",
            "score": 8.1,
            "severity": "HIGH",
            "vector": (
                "CVSS:3.1/"
                "AV:N/"
                "AC:L/"
                "PR:N/"
                "UI:N/"
                "S:U/"
                "C:H/"
                "I:L/"
                "A:N"
            ),
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
        "cvss": {
            "version": "3.1",
            "score": 8.1,
            "severity": "HIGH",
            "vector": (
                "CVSS:3.1/"
                "AV:N/"
                "AC:L/"
                "PR:N/"
                "UI:N/"
                "S:U/"
                "C:H/"
                "I:L/"
                "A:N"
            ),
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
        "cvss": {
            "version": "3.1",
            "score": 8.1,
            "severity": "HIGH",
            "vector": (
                "CVSS:3.1/"
                "AV:N/"
                "AC:L/"
                "PR:N/"
                "UI:N/"
                "S:U/"
                "C:H/"
                "I:L/"
                "A:N"
            ),
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
        "cvss": {
            "version": "3.1",
            "score": 8.1,
            "severity": "HIGH",
            "vector": (
                "CVSS:3.1/"
                "AV:N/"
                "AC:L/"
                "PR:N/"
                "UI:N/"
                "S:U/"
                "C:H/"
                "I:L/"
                "A:N"
            ),
        },
        "impact": (
            "Missing clickjacking protection may allow "
            "malicious sites to frame the application."
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
        "cvss": {
            "version": "3.1",
            "score": 6.4,
            "severity": "MEDIUM",
            "vector": (
                "CVSS:3.1/"
                "AV:N/"
                "AC:L/"
                "PR:N/"
                "UI:N/"
                "S:U/"
                "C:L/"
                "I:L/"
                "A:N"
            ),
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
        "cvss": {
            "version": "3.1",
            "score": 6.4,
            "severity": "MEDIUM",
            "vector": (
                "CVSS:3.1/"
                "AV:N/"
                "AC:L/"
                "PR:N/"
                "UI:N/"
                "S:U/"
                "C:L/"
                "I:L/"
                "A:N"
            ),
        },
        "impact": (
            "Missing Permissions-Policy may allow unnecessary "
            "browser capabilities to remain available."
        ),
        "remediation": (
            "Configure Permissions-Policy to explicitly "
            "restrict unnecessary browser capabilities."
        ),
    },
}


def _to_dict(
    result: Any,
) -> Dict[str, Any]:
    """Convert analysis result to dictionary."""

    if hasattr(
        result,
        "to_dict",
    ):
        data = result.to_dict()

        if isinstance(
            data,
            dict,
        ):
            return data

    if isinstance(
        result,
        dict,
    ):
        return result

    if hasattr(
        result,
        "__dict__",
    ):
        return dict(
            result.__dict__
        )

    return {
        "result": str(result),
    }


def _build_header_findings(
    headers_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Convert missing HTTP security headers into findings."""

    findings: List[Dict[str, Any]] = []

    missing = headers_result.get(
        "missing",
        [],
    )

    if not isinstance(
        missing,
        list,
    ):
        return findings

    for index, header in enumerate(
        missing,
        start=1,
    ):
        mapping = HEADER_KNOWLEDGE.get(
            header,
            {},
        )

        severity = (
            mapping.get(
                "cvss",
                {},
            ).get(
                "severity",
                "MEDIUM",
            )
        )

        findings.append(
            {
                "id": (
                    f"KONGALI-HEADERS-"
                    f"{index:04d}"
                ),
                "title": (
                    f"Missing security header: "
                    f"{header}"
                ),
                "severity": severity,
                "category": (
                    "HTTP Security Headers"
                ),
                "description": (
                    "The HTTP response does not "
                    f"include the {header} "
                    "security header."
                ),
                "owasp": mapping.get(
                    "owasp",
                    {
                        "id": "A05:2021",
                        "name": (
                            "Security Misconfiguration"
                        ),
                    },
                ),
                "cwe": mapping.get(
                    "cwe",
                    {
                        "id": "CWE-693",
                        "name": (
                            "Protection Mechanism Failure"
                        ),
                    },
                ),
                "cvss": mapping.get(
                    "cvss",
                    {},
                ),
                "impact": mapping.get(
                    "impact",
                    "",
                ),
                "remediation": mapping.get(
                    "remediation",
                    "",
                ),
                "evidence": {
                    "header": header,
                    "status": "missing",
                    "target": headers_result.get(
                        "url",
                        "",
                    ),
                },
                "references": [
                    (
                        "https://owasp.org/"
                        "Top10/A05_2021-"
                        "Security_Misconfiguration/"
                    ),
                ],
                "metadata": {
                    "source": "headers",
                },
            }
        )

    return findings


def _extract_findings(
    result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Extract existing findings."""

    findings = result.get(
        "findings",
        [],
    )

    if not isinstance(
        findings,
        list,
    ):
        return []

    return [
        finding
        for finding in findings
        if isinstance(
            finding,
            dict,
        )
    ]


def _build_severity_summary(
    findings: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Build severity counts."""

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "INFO",
            )
        ).upper()

        if severity in summary:
            summary[severity] += 1

    return summary


def run_unified_assessment(
    target: str,
) -> Dict[str, Any]:
    """Run a unified defensive security assessment."""

    url_result = _to_dict(
        analyze_url(
            target,
        )
    )

    headers_result = _to_dict(
        analyze_headers(
            target,
        )
    )

    tls_result = _to_dict(
        analyze_tls(
            target,
        )
    )

    findings: List[Dict[str, Any]] = []

    findings.extend(
        _build_header_findings(
            headers_result,
        )
    )

    findings.extend(
        _extract_findings(
            tls_result,
        )
    )

    findings.extend(
        _extract_findings(
            url_result,
        )
    )

    return {
        "target": target,
        "assessment": {
            "url": url_result,
            "headers": headers_result,
            "tls": tls_result,
        },
        "findings": findings,
        "summary": {
            "total_findings": len(
                findings
            ),
            "severity_counts": (
                _build_severity_summary(
                    findings
                )
            ),
        },
        "metadata": {
            "engine": (
                "Kongali Unified "
                "Assessment Engine"
            ),
            "version": "1.0.0",
            "sources": [
                "url",
                "headers",
                "tls",
            ],
        },
    }
