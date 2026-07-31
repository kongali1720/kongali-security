"""
Kongali Security IOC Analyzer
=============================

Indicator of Compromise (IOC) detection and classification module.

Supported IOC types:

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
- SHA-512

This module is designed to work with the Kongali Security Core Engine.

Version:
    0.1.0
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

MODULE_NAME = "ioc_analyzer"
MODULE_VERSION = "0.1.0"


class IOCType(str, Enum):
    """Supported Indicator of Compromise types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    UNKNOWN = "unknown"


@dataclass
class IOCResult:
    """
    Result produced by the IOC Analyzer.

    Attributes:
        value:
            Original IOC value.

        ioc_type:
            Detected IOC type.

        confidence:
            Detection confidence between 0.0 and 1.0.

        valid:
            Whether the IOC is considered syntactically valid.

        metadata:
            Additional information about the IOC.
    """

    value: str
    ioc_type: IOCType
    confidence: float
    valid: bool
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert IOC result to a dictionary."""

        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "confidence": self.confidence,
            "valid": self.valid,
            "metadata": self.metadata,
        }


class IOCAnalyzer:
    """
    Detect and classify Indicators of Compromise.

    The analyzer performs local syntactic analysis only.

    It does not contact external threat intelligence services.

    Example:

        analyzer = IOCAnalyzer()

        result = analyzer.analyze(
            "8.8.8.8"
        )

        print(result)
    """

    DOMAIN_PATTERN = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    HASH_PATTERNS = {
        32: IOCType.MD5,
        40: IOCType.SHA1,
        64: IOCType.SHA256,
        128: IOCType.SHA512,
    }

    def __init__(
        self,
        allow_private_ips: bool = True,
        allow_localhost: bool = True,
    ) -> None:
        """
        Initialize the IOC Analyzer.

        Args:
            allow_private_ips:
                Whether private IP addresses are considered valid IOCs.

            allow_localhost:
                Whether localhost addresses are considered valid IOCs.
        """

        self.allow_private_ips = allow_private_ips
        self.allow_localhost = allow_localhost

    def analyze(
        self,
        value: str,
    ) -> IOCResult:
        """
        Analyze a single IOC value.

        Args:
            value:
                IOC value to analyze.

        Returns:
            IOCResult containing classification information.
        """

        normalized_value = value.strip()

        if not normalized_value:
            return IOCResult(
                value=value,
                ioc_type=IOCType.UNKNOWN,
                confidence=0.0,
                valid=False,
                metadata={
                    "reason": "Input is empty.",
                },
            )

        ip_result = self._analyze_ip(
            normalized_value
        )

        if ip_result is not None:
            return ip_result

        hash_result = self._analyze_hash(
            normalized_value
        )

        if hash_result is not None:
            return hash_result

        url_result = self._analyze_url(
            normalized_value
        )

        if url_result is not None:
            return url_result

        domain_result = self._analyze_domain(
            normalized_value
        )

        if domain_result is not None:
            return domain_result

        return IOCResult(
            value=normalized_value,
            ioc_type=IOCType.UNKNOWN,
            confidence=0.0,
            valid=False,
            metadata={
                "reason": "Unable to classify input as a supported IOC type.",
            },
        )

    def analyze_many(
        self,
        values: list[str],
    ) -> list[IOCResult]:
        """
        Analyze multiple IOC values.

        Args:
            values:
                List of IOC values.

        Returns:
            List of IOCResult objects.
        """

        return [
            self.analyze(value)
            for value in values
        ]

    def _analyze_ip(
        self,
        value: str,
    ) -> IOCResult | None:
        """
        Analyze IPv4 and IPv6 addresses.

        Args:
            value:
                Candidate IP address.

        Returns:
            IOCResult or None.
        """

        try:
            ip = ipaddress.ip_address(value)

        except ValueError:
            return None

        ioc_type = IOCType.IPV4 if ip.version == 4 else IOCType.IPV6

        is_private = ip.is_private
        is_loopback = ip.is_loopback
        is_reserved = ip.is_reserved
        is_multicast = ip.is_multicast
        is_global = ip.is_global

        valid = True

        if is_private and not self.allow_private_ips:
            valid = False

        if is_loopback and not self.allow_localhost:
            valid = False

        return IOCResult(
            value=value,
            ioc_type=ioc_type,
            confidence=1.0,
            valid=valid,
            metadata={
                "version": ip.version,
                "is_private": is_private,
                "is_loopback": is_loopback,
                "is_reserved": is_reserved,
                "is_multicast": is_multicast,
                "is_global": is_global,
            },
        )

    def _analyze_hash(
        self,
        value: str,
    ) -> IOCResult | None:
        """
        Analyze cryptographic hash candidates.

        Args:
            value:
                Candidate hash.

        Returns:
            IOCResult or None.
        """

        if not value:
            return None

        if not re.fullmatch(
            r"[a-fA-F0-9]+",
            value,
        ):
            return None

        hash_type = self.HASH_PATTERNS.get(
            len(value)
        )

        if hash_type is None:
            return None

        algorithm_map = {
            IOCType.MD5: hashlib.md5,
            IOCType.SHA1: hashlib.sha1,
            IOCType.SHA256: hashlib.sha256,
            IOCType.SHA512: hashlib.sha512,
        }

        algorithm = algorithm_map[hash_type]

        return IOCResult(
            value=value.lower(),
            ioc_type=hash_type,
            confidence=1.0,
            valid=True,
            metadata={
                "length": len(value),
                "algorithm": algorithm.__name__,
                "hexadecimal": True,
            },
        )

    def _analyze_url(
        self,
        value: str,
    ) -> IOCResult | None:
        """
        Analyze URL candidates.

        Args:
            value:
                Candidate URL.

        Returns:
            IOCResult or None.
        """

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            value,
        ):
            return None

        try:
            parsed = urlparse(
                value
            )

        except ValueError:
            return None

        if not parsed.scheme or not parsed.netloc:
            return None

        hostname = parsed.hostname

        if not hostname:
            return None

        return IOCResult(
            value=value,
            ioc_type=IOCType.URL,
            confidence=1.0,
            valid=True,
            metadata={
                "scheme": parsed.scheme.lower(),
                "hostname": hostname,
                "port": parsed.port,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
            },
        )

    def _analyze_domain(
        self,
        value: str,
    ) -> IOCResult | None:
        """
        Analyze domain name candidates.

        Args:
            value:
                Candidate domain.

        Returns:
            IOCResult or None.
        """

        normalized_value = value.lower().rstrip(
            "."
        )

        if not self.DOMAIN_PATTERN.fullmatch(
            normalized_value
        ):
            return None

        labels = normalized_value.split(
            "."
        )

        return IOCResult(
            value=normalized_value,
            ioc_type=IOCType.DOMAIN,
            confidence=0.95,
            valid=True,
            metadata={
                "tld": labels[-1],
                "label_count": len(labels),
                "length": len(normalized_value),
            },
        )


def analyze_ioc(
    value: str,
    allow_private_ips: bool = True,
    allow_localhost: bool = True,
) -> dict[str, Any]:
    """
    Convenience function for analyzing a single IOC.

    Args:
        value:
            IOC value.

        allow_private_ips:
            Whether private IPs are allowed.

        allow_localhost:
            Whether localhost addresses are allowed.

    Returns:
        Dictionary representation of IOC analysis result.
    """

    analyzer = IOCAnalyzer(
        allow_private_ips=allow_private_ips,
        allow_localhost=allow_localhost,
    )

    result = analyzer.analyze(
        value
    )

    return result.to_dict()


__all__ = [
    "MODULE_NAME",
    "MODULE_VERSION",
    "IOCType",
    "IOCResult",
    "IOCAnalyzer",
    "analyze_ioc",
]
