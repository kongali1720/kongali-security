"""URL analysis module for Kongali Security."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
from typing import Any


MODULE_NAME = "url_analyzer"
MODULE_VERSION = "1.1.0"


def normalize_url(
    value: str,
) -> str:
    """
    Normalize URL input.

    Accept:
        example.com
        www.example.com
        https://example.com

    Return:
        https://example.com
    """

    value = value.strip()

    if not value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        value = (
            "https://"
            + value
        )

    return value


@dataclass
class URLResult:
    """URL analysis result."""

    value: str
    valid: bool
    scheme: str | None
    hostname: str | None
    port: int | None
    path: str
    query: str
    fragment: str

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "value": self.value,
            "valid": self.valid,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
        }


def analyze_url(
    target: str,
) -> URLResult:
    """
    Analyze and validate URL.
    """

    target = normalize_url(
        target
    )

    parsed = urlparse(
        target
    )

    valid = bool(
        parsed.hostname
    )

    return URLResult(
        value=target,
        valid=valid,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
    )
