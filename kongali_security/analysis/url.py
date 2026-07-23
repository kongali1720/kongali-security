"""URL analysis module for Kongali Security."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
from typing import Any


MODULE_NAME = "url_analyzer"
MODULE_VERSION = "1.1.0"


class URLType(Enum):
    """Supported URL classification."""

    URL = "url"
    UNKNOWN = "unknown"


def normalize_url(
    value: str,
) -> str:
    """
    Normalize URL input.

    Only used for operational commands.
    """

    value = value.strip()

    if not value:
        return value

    if not value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return value

    return value


@dataclass
class URLResult:
    """URL analysis result."""

    value: str
    url_type: URLType
    valid: bool
    scheme: str | None
    hostname: str | None
    port: int | None
    path: str
    query: str
    fragment: str

    @property
    def type(self) -> str:
        return self.url_type.value

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "value": self.value,
            "type": self.type,
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
    Analyze URL safely.

    Keeps backward compatibility with tests.
    """

    if not target or not target.strip():

        return URLResult(
            value=target,
            url_type=URLType.UNKNOWN,
            valid=False,
            scheme=None,
            hostname=None,
            port=None,
            path="",
            query="",
            fragment="",
        )


    target = target.strip()


    parsed = urlparse(
        target
    )


    allowed_schemes = (
        "http",
        "https",
        "ftp",
    )


    valid = bool(
        parsed.hostname
    ) and (
        parsed.scheme in allowed_schemes
    )


    if not valid:

        return URLResult(
            value=target,
            url_type=URLType.UNKNOWN,
            valid=False,
            scheme=parsed.scheme or None,
            hostname=parsed.hostname,
            port=parsed.port,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
        )


    return URLResult(
        value=target,
        url_type=URLType.URL,
        valid=True,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
    )
