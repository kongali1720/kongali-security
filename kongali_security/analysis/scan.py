"""Full security scan orchestration module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kongali_security.analysis.dns import analyze_dns
from kongali_security.analysis.headers import analyze_headers
from kongali_security.analysis.url import analyze_url
from kongali_security.analysis.whois import analyze_whois

MODULE_NAME = "security_scanner"
MODULE_VERSION = "0.1.0"


@dataclass
class ScanResult:
    """Combined result produced by the security scanner."""

    target: str
    url: Any
    dns: Any
    whois: Any
    headers: Any

    def to_dict(self) -> dict[str, Any]:
        """Convert the scan result to a dictionary."""

        def serialize(value: Any) -> Any:
            if hasattr(value, "to_dict"):
                return value.to_dict()

            if hasattr(value, "__dict__"):
                return dict(value.__dict__)

            if isinstance(value, dict):
                return value

            return value

        return {
            "target": self.target,
            "url": serialize(self.url),
            "dns": serialize(self.dns),
            "whois": serialize(self.whois),
            "headers": serialize(self.headers),
        }


def analyze_scan(target: str) -> ScanResult:
    """Run the full defensive security analysis pipeline."""

    url_result = analyze_url(target)

    hostname = getattr(
        url_result,
        "hostname",
        None,
    )

    if not hostname:
        raise ValueError(
            "Target must be a valid URL with a hostname."
        )

    dns_result = analyze_dns(hostname)

    whois_result = analyze_whois(hostname)

    headers_result = analyze_headers(target)

    return ScanResult(
        target=target,
        url=url_result,
        dns=dns_result,
        whois=whois_result,
        headers=headers_result,
    )
