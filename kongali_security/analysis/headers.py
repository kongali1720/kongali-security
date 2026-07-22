"""HTTP Security Headers Analyzer for Kongali Security."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from kongali_security.schemas.finding import (
    CVSSScore,
    CWEReference,
    OWASPReference,
    SecurityFinding,
)

MODULE_NAME = "headers_analyzer"
MODULE_VERSION = "0.1.0"


SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


@dataclass
class HeadersResult:
    """Result produced by the HTTP Security Headers Analyzer."""

    url: str
    reachable: bool
    status_code: int | None
    headers: dict[str, Any]
    present: list[str]
    missing: list[str]
    security_score: int
    risk_level: str
    metadata: dict[str, Any]
    findings: list[SecurityFinding]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a dictionary."""

        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "headers": self.headers,
            "present": self.present,
            "missing": self.missing,
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "metadata": self.metadata,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
        }


HEADER_KNOWLEDGE = {
    "Content-Security-Policy": {
        "owasp": OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        "cwe": CWEReference(
            id="CWE-693",
            name="Protection Mechanism Failure",
        ),
        "cvss": CVSSScore(
            version="3.1",
            score=8.1,
            severity="HIGH",
            vector=(
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/S:U/"
                "C:H/I:L/A:N"
            ),
        ),
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
        "owasp": OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        "cwe": CWEReference(
            id="CWE-319",
            name="Cleartext Transmission of Sensitive Information",
        ),
        "cvss": CVSSScore(
            version="3.1",
            score=8.1,
            severity="HIGH",
            vector=(
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/S:U/"
                "C:H/I:L/A:N"
            ),
        ),
        "impact": (
            "Without HSTS, users may be exposed to "
            "protocol downgrade or insecure HTTP connections."
        ),
        "remediation": (
            "Enable HTTP Strict Transport Security with "
            "an appropriate max-age and HTTPS deployment."
        ),
    },
    "X-Content-Type-Options": {
        "owasp": OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        "cwe": CWEReference(
            id="CWE-693",
            name="Protection Mechanism Failure",
        ),
        "cvss": CVSSScore(
            version="3.1",
            score=8.1,
            severity="HIGH",
            vector=(
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/S:U/"
                "C:H/I:L/A:N"
            ),
        ),
        "impact": (
            "Missing X-Content-Type-Options may allow "
            "browsers to MIME-sniff responses unexpectedly."
        ),
        "remediation": (
            "Set X-Content-Type-Options to nosniff."
        ),
    },
    "X-Frame-Options": {
        "owasp": OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        "cwe": CWEReference(
            id="CWE-693",
            name="Protection Mechanism Failure",
        ),
        "cvss": CVSSScore(
            version="3.1",
            score=8.1,
            severity="HIGH",
            vector=(
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/S:U/"
                "C:H/I:L/A:N"
            ),
        ),
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
        "owasp": OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        "cwe": CWEReference(
            id="CWE-200",
            name="Exposure of Sensitive Information to an Unauthorized Actor",
        ),
        "cvss": CVSSScore(
            version="3.1",
            score=6.4,
            severity="MEDIUM",
            vector=(
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/S:U/"
                "C:L/I:L/A:N"
            ),
        ),
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
        "owasp": OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        "cwe": CWEReference(
            id="CWE-693",
            name="Protection Mechanism Failure",
        ),
        "cvss": CVSSScore(
            version="3.1",
            score=6.4,
            severity="MEDIUM",
            vector=(
                "CVSS:3.1/"
                "AV:N/AC:L/PR:N/UI:N/S:U/"
                "C:L/I:L/A:N"
            ),
        ),
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


def _build_security_findings(
    url: str,
    status_code: int | None,
    missing: list[str],
) -> list[SecurityFinding]:
    """Build canonical SecurityFinding objects for missing headers."""

    findings = []

    for index, header in enumerate(missing, start=1):
        mapping = HEADER_KNOWLEDGE.get(header)

        if mapping is None:
            mapping = {
                "owasp": OWASPReference(
                    id="A05:2021",
                    name="Security Misconfiguration",
                ),
                "cwe": CWEReference(
                    id="CWE-693",
                    name="Protection Mechanism Failure",
                ),
                "cvss": CVSSScore(
                    version="3.1",
                    score=5.3,
                    severity="MEDIUM",
                    vector=(
                        "CVSS:3.1/"
                        "AV:N/AC:L/PR:N/UI:N/S:U/"
                        "C:L/I:L/A:N"
                    ),
                ),
                "impact": (
                    "Missing security headers may weaken "
                    "browser-side security controls."
                ),
                "remediation": (
                    f"Configure the {header} security header."
                ),
            }

        cvss = mapping["cvss"]

        findings.append(
            SecurityFinding(
                id=f"KONGALI-HEADERS-{index:04d}",
                title=f"Missing security header: {header}",
                severity=cvss.severity,
                category="HTTP Security Headers",
                description=(
                    f"The HTTP response does not include "
                    f"the {header} security header."
                ),
                owasp=mapping["owasp"],
                cwe=mapping["cwe"],
                cvss=cvss,
                impact=mapping["impact"],
                remediation=mapping["remediation"],
                evidence={
                    "url": url,
                    "status_code": status_code,
                    "header": header,
                    "status": "missing",
                },
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                ],
                metadata={
                    "module": MODULE_NAME,
                    "module_version": MODULE_VERSION,
                },
            )
        )

    return findings



class HeadersAnalyzer:
    """Analyze HTTP security response headers."""

    def __init__(
        self,
        timeout: int = 10,
    ) -> None:
        """Initialize the analyzer."""

        self.timeout = timeout

    def analyze(
        self,
        url: str,
    ) -> HeadersResult:
        """Analyze HTTP security headers."""

        normalized_url = url.strip()

        if not normalized_url:
            return HeadersResult(
                url=url,
                reachable=False,
                status_code=None,
                headers={},
                present=[],
                missing=list(
                    SECURITY_HEADERS.values()
                ),
                security_score=0,
                risk_level="HIGH",
                metadata={
                    "error": "URL is empty.",
                },
                findings=[],
            )

        if not normalized_url.startswith(
            ("http://", "https://")
        ):
            normalized_url = (
                f"https://{normalized_url}"
            )

        parsed_url = urlparse(normalized_url)

        if parsed_url.scheme not in {"http", "https"}:
            return HeadersResult(
                url=url,
                reachable=False,
                status_code=None,
                headers={},
                present=[],
                missing=list(SECURITY_HEADERS.values()),
                security_score=0,
                risk_level="HIGH",
                metadata={
                    "error": (
                        "Unsupported URL scheme. "
                        "Only http and https are allowed."
                    ),
                    "scheme": parsed_url.scheme,
                },
                findings=[],
            )

        request = Request(  # noqa: S310
            normalized_url,
            method="HEAD",
            headers={
                "User-Agent": (
                    "Kongali-Security/"
                    f"{MODULE_VERSION}"
                ),
            },
        )

        try:
            with urlopen(  # noqa: S310
                request,
                timeout=self.timeout,
            ) as response:
                status_code = response.status
                response_headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                }

        except HTTPError as exc:
            status_code = exc.code
            response_headers = {
                key.lower(): value
                for key, value in exc.headers.items()
            }

        except (URLError, TimeoutError, OSError) as exc:
            return HeadersResult(
                url=normalized_url,
                reachable=False,
                status_code=None,
                headers={},
                present=[],
                missing=list(
                    SECURITY_HEADERS.values()
                ),
                security_score=0,
                risk_level="HIGH",
                metadata={
                    "error": str(exc),
                },
                findings=[],
            )

        present = []
        missing = []

        for key, display_name in SECURITY_HEADERS.items():
            if key in response_headers:
                present.append(display_name)
            else:
                missing.append(display_name)

        total = len(SECURITY_HEADERS)

        score = round(
            len(present) / total * 10
        )

        if score >= 8:
            risk_level = "LOW"
        elif score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        selected_headers = {
            display_name: response_headers[key]
            for key, display_name in SECURITY_HEADERS.items()
            if key in response_headers
        }

        return HeadersResult(
            url=normalized_url,
            reachable=True,
            status_code=status_code,
            headers=selected_headers,
            present=present,
            missing=missing,
            security_score=score,
            risk_level=risk_level,
            metadata={
                "total_security_headers": total,
                "headers_present": len(present),
                "headers_missing": len(missing),
            },
            findings=_build_security_findings(
                normalized_url,
                status_code,
                missing,
            ),
        )


def analyze_headers(
    url: str,
) -> HeadersResult:
    """Convenience function for HTTP header analysis."""

    analyzer = HeadersAnalyzer()

    return analyzer.analyze(url)
