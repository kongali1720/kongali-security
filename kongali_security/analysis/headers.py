"""HTTP Security Headers Analyzer for Kongali Security."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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
    headers: Dict[str, Any]
    present: list[str]
    missing: list[str]
    security_score: int
    risk_level: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
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
        }


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
            )

        if not normalized_url.startswith(
            ("http://", "https://")
        ):
            normalized_url = (
                f"https://{normalized_url}"
            )

        request = Request(
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
            with urlopen(
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
        )


def analyze_headers(
    url: str,
) -> HeadersResult:
    """Convenience function for HTTP header analysis."""

    analyzer = HeadersAnalyzer()

    return analyzer.analyze(url)
