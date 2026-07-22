"""Cryptographic hash analysis module for Kongali Security."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict


MODULE_NAME = "hash_analyzer"
MODULE_VERSION = "0.1.0"


class HashType(str, Enum):
    """Supported cryptographic hash types."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    UNKNOWN = "unknown"


@dataclass
class HashResult:
    """Result produced by the Hash Analyzer."""

    value: str
    hash_type: HashType
    length: int
    valid: bool
    algorithm: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert the hash result to a dictionary."""
        return {
            "value": self.value,
            "type": self.hash_type.value,
            "length": self.length,
            "valid": self.valid,
            "algorithm": self.algorithm,
            "metadata": self.metadata,
        }


class HashAnalyzer:
    """Detect and classify common cryptographic hash formats."""

    HASH_PATTERNS = {
        32: HashType.MD5,
        40: HashType.SHA1,
        64: HashType.SHA256,
        128: HashType.SHA512,
    }

    def analyze(self, value: str) -> HashResult:
        """Analyze a single cryptographic hash."""

        normalized_value = value.strip().lower()
        length = len(normalized_value)

        if not normalized_value:
            return HashResult(
                value=value,
                hash_type=HashType.UNKNOWN,
                length=0,
                valid=False,
                algorithm="unknown",
                metadata={
                    "reason": "Input is empty.",
                    "hexadecimal": False,
                },
            )

        hash_type = self.HASH_PATTERNS.get(
            length,
            HashType.UNKNOWN,
        )

        hexadecimal = bool(
            re.fullmatch(
                r"[0-9a-f]+",
                normalized_value,
            )
        )

        valid = (
            hash_type != HashType.UNKNOWN
            and hexadecimal
        )

        algorithm = (
            hash_type.value
            if valid
            else "unknown"
        )

        return HashResult(
            value=normalized_value,
            hash_type=(
                hash_type
                if valid
                else HashType.UNKNOWN
            ),
            length=length,
            valid=valid,
            algorithm=algorithm,
            metadata={
                "hexadecimal": hexadecimal,
            },
        )


def analyze_hash(value: str) -> HashResult:
    """Convenience function for hash analysis."""
    analyzer = HashAnalyzer()
    return analyzer.analyze(value)
