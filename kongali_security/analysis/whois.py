"""WHOIS analysis module for Kongali Security.

This module performs defensive WHOIS analysis for domain names.

The analyzer uses the local ``whois`` command when available.
It does not perform active scanning or exploitation.

Version:
    0.1.0
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

MODULE_NAME = "whois_analyzer"
MODULE_VERSION = "0.1.0"


@dataclass
class WHOISResult:
    """Result produced by the WHOIS Analyzer."""

    domain: str
    valid: bool
    queried: bool
    registrar: str | None
    creation_date: str | None
    expiration_date: str | None
    updated_date: str | None
    name_servers: list[str]
    statuses: list[str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert WHOIS result to a dictionary."""
        return {
            "domain": self.domain,
            "valid": self.valid,
            "queried": self.queried,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "name_servers": self.name_servers,
            "statuses": self.statuses,
            "metadata": self.metadata,
        }


class WHOISAnalyzer:
    """Perform defensive WHOIS analysis."""

    DOMAIN_PATTERN = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    def analyze(self, domain: str) -> WHOISResult:
        """Analyze a domain using the local WHOIS client."""

        normalized_domain = domain.strip().lower().rstrip(".")

        if not normalized_domain:
            return WHOISResult(
                domain=domain,
                valid=False,
                queried=False,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                updated_date=None,
                name_servers=[],
                statuses=[],
                metadata={
                    "error": "Input is empty.",
                },
            )

        if not self.DOMAIN_PATTERN.fullmatch(
            normalized_domain
        ):
            return WHOISResult(
                domain=normalized_domain,
                valid=False,
                queried=False,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                updated_date=None,
                name_servers=[],
                statuses=[],
                metadata={
                    "error": "Invalid domain format.",
                },
            )

        whois_binary = shutil.which("whois")

        if whois_binary is None:
            return WHOISResult(
                domain=normalized_domain,
                valid=True,
                queried=False,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                updated_date=None,
                name_servers=[],
                statuses=[],
                metadata={
                    "error": (
                        "WHOIS client is not installed."
                    ),
                },
            )

        try:
            process = subprocess.run(
                [
                    whois_binary,
                    normalized_domain,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

        except subprocess.TimeoutExpired:
            return WHOISResult(
                domain=normalized_domain,
                valid=True,
                queried=False,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                updated_date=None,
                name_servers=[],
                statuses=[],
                metadata={
                    "error": "WHOIS query timed out.",
                },
            )

        except OSError as exc:
            return WHOISResult(
                domain=normalized_domain,
                valid=True,
                queried=False,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                updated_date=None,
                name_servers=[],
                statuses=[],
                metadata={
                    "error": str(exc),
                },
            )

        output = (
            process.stdout
            + "\n"
            + process.stderr
        )

        registrar = self._extract_first(
            output,
            [
                r"^Registrar:\s*(.+)$",
                r"^Sponsoring Registrar:\s*(.+)$",
                r"^registrar:\s*(.+)$",
            ],
        )

        creation_date = self._extract_first(
            output,
            [
                r"^Creation Date:\s*(.+)$",
                r"^Created:\s*(.+)$",
                r"^created:\s*(.+)$",
            ],
        )

        expiration_date = self._extract_first(
            output,
            [
                r"^Registry Expiry Date:\s*(.+)$",
                r"^Registrar Registration Expiration Date:\s*(.+)$",
                r"^Expiration Date:\s*(.+)$",
                r"^Expires:\s*(.+)$",
            ],
        )

        updated_date = self._extract_first(
            output,
            [
                r"^Updated Date:\s*(.+)$",
                r"^Updated:\s*(.+)$",
                r"^updated:\s*(.+)$",
            ],
        )

        name_servers = self._extract_all(
            output,
            [
                r"^Name Server:\s*(.+)$",
                r"^Name Servers:\s*(.+)$",
                r"^nserver:\s*(.+)$",
            ],
        )

        statuses = self._extract_all(
            output,
            [
                r"^Domain Status:\s*(.+)$",
                r"^status:\s*(.+)$",
            ],
        )

        return WHOISResult(
            domain=normalized_domain,
            valid=True,
            queried=True,
            registrar=registrar,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            name_servers=name_servers,
            statuses=statuses,
            metadata={
                "return_code": process.returncode,
                "output_length": len(output),
            },
        )

    @staticmethod
    def _extract_first(
        text: str,
        patterns: list[str],
    ) -> str | None:
        """Extract the first matching value."""
        for pattern in patterns:
            match = re.search(
                pattern,
                text,
                flags=re.IGNORECASE
                | re.MULTILINE,
            )

            if match:
                return match.group(1).strip()

        return None

    @staticmethod
    def _extract_all(
        text: str,
        patterns: list[str],
    ) -> list[str]:
        """Extract all unique matching values."""
        values: list[str] = []

        for pattern in patterns:
            matches = re.findall(
                pattern,
                text,
                flags=re.IGNORECASE
                | re.MULTILINE,
            )

            for value in matches:
                normalized = value.strip()

                if normalized and normalized not in values:
                    values.append(normalized)

        return values


def analyze_whois(
    domain: str,
) -> WHOISResult:
    """Convenience function for WHOIS analysis."""
    analyzer = WHOISAnalyzer()
    return analyzer.analyze(domain)
