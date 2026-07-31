"""URL analysis module for Kongali Security."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

MODULE_NAME = "url_analyzer"
MODULE_VERSION = "0.1.0"


class URLType:
    """Supported URL analysis types."""

    URL = "url"
    UNKNOWN = "unknown"


@dataclass
class URLResult:
    """Result produced by the URL Analyzer."""

    value: str
    url_type: str
    valid: bool
    scheme: str
    hostname: str | None
    port: int | None
    path: str
    query: str
    fragment: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert URL result to a dictionary."""
        return {
            "value": self.value,
            "type": self.url_type,
            "valid": self.valid,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
            "metadata": self.metadata,
        }


class URLAnalyzer:
    """Analyze and classify URLs using local parsing only."""

    ALLOWED_SCHEMES = {
        "http",
        "https",
        "ftp",
    }

    def analyze(self, value: str) -> URLResult:
        """Analyze a single URL."""

        normalized_value = value.strip()

        if not normalized_value:
            return URLResult(
                value=value,
                url_type=URLType.UNKNOWN,
                valid=False,
                scheme="",
                hostname=None,
                port=None,
                path="",
                query="",
                fragment="",
                metadata={
                    "reason": "Input is empty.",
                },
            )

        try:
            parsed = urlparse(normalized_value)

            scheme = parsed.scheme.lower()
            hostname = parsed.hostname
            port = parsed.port

        except ValueError as exc:
            return URLResult(
                value=normalized_value,
                url_type=URLType.UNKNOWN,
                valid=False,
                scheme="",
                hostname=None,
                port=None,
                path="",
                query="",
                fragment="",
                metadata={
                    "reason": str(exc),
                },
            )

        valid = bool(
            scheme
            and scheme in self.ALLOWED_SCHEMES
            and hostname
        )

        if not valid:
            return URLResult(
                value=normalized_value,
                url_type=URLType.UNKNOWN,
                valid=False,
                scheme=scheme,
                hostname=hostname,
                port=port,
                path=parsed.path,
                query=parsed.query,
                fragment=parsed.fragment,
                metadata={
                    "reason": (
                        "URL must contain a supported scheme "
                        "and hostname."
                    ),
                    "supported_schemes": sorted(
                        self.ALLOWED_SCHEMES
                    ),
                },
            )

        return URLResult(
            value=normalized_value,
            url_type=URLType.URL,
            valid=True,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
            metadata={
                "username_present": parsed.username is not None,
                "password_present": parsed.password is not None,
                "netloc": parsed.netloc,
            },
        )


def analyze_url(value: str) -> URLResult:
    """Convenience function for URL analysis."""
    analyzer = URLAnalyzer()
    return analyzer.analyze(value)
