"""Defensive DNS analysis module for Kongali Security."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any, cast

MODULE_NAME = "dns_analyzer"
MODULE_VERSION = "0.1.0"


@dataclass
class DNSResult:
    """Result produced by the DNS Analyzer."""

    domain: str
    valid: bool
    resolved: bool
    ipv4: list[str]
    ipv6: list[str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert the DNS result to a dictionary."""
        return {
            "domain": self.domain,
            "valid": self.valid,
            "resolved": self.resolved,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "metadata": self.metadata,
        }


class DNSAnalyzer:
    """Perform defensive DNS resolution analysis."""

    def analyze(self, domain: str) -> DNSResult:
        """Analyze and resolve a domain name."""

        normalized_domain = domain.strip().lower().rstrip(".")

        if not normalized_domain:
            return DNSResult(
                domain=domain,
                valid=False,
                resolved=False,
                ipv4=[],
                ipv6=[],
                metadata={
                    "reason": "Input is empty.",
                },
            )

        try:
            results = socket.getaddrinfo(
                normalized_domain,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )

        except socket.gaierror as exc:
            return DNSResult(
                domain=normalized_domain,
                valid=True,
                resolved=False,
                ipv4=[],
                ipv6=[],
                metadata={
                    "error": str(exc),
                },
            )

        ipv4 = sorted(
            {
                cast(str, result[4][0])
                for result in results
                if result[0] == socket.AF_INET
            }
        )

        ipv6 = sorted(
            {
                cast(str, result[4][0])
                for result in results
                if result[0] == socket.AF_INET6
            }
        )

        return DNSResult(
            domain=normalized_domain,
            valid=True,
            resolved=bool(ipv4 or ipv6),
            ipv4=ipv4,
            ipv6=ipv6,
            metadata={
                "record_count": len(ipv4) + len(ipv6),
            },
        )


def analyze_dns(domain: str) -> DNSResult:
    """Convenience function for DNS analysis."""
    analyzer = DNSAnalyzer()
    return analyzer.analyze(domain)
