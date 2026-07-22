"""Unified security finding schema for Kongali Security."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


SEVERITIES = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
)


@dataclass
class OWASPReference:
    """OWASP classification metadata."""

    id: str
    name: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert OWASP metadata to a dictionary."""

        return asdict(self)


@dataclass
class CWEReference:
    """CWE classification metadata."""

    id: str
    name: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert CWE metadata to a dictionary."""

        return asdict(self)


@dataclass
class CVSSScore:
    """CVSS scoring metadata."""

    version: str
    score: float
    severity: str
    vector: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert CVSS metadata to a dictionary."""

        return asdict(self)


@dataclass
class SecurityFinding:
    """Unified security finding representation."""

    id: str
    title: str
    severity: str
    category: str
    description: str

    owasp: Optional[OWASPReference] = None
    cwe: Optional[CWEReference] = None
    cvss: Optional[CVSSScore] = None

    impact: str = ""
    remediation: str = ""

    evidence: Dict[str, Any] = field(
        default_factory=dict,
    )

    references: List[str] = field(
        default_factory=list,
    )

    metadata: Dict[str, Any] = field(
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        """Validate the security finding."""

        self.severity = self.severity.upper()

        if self.severity not in SEVERITIES:
            raise ValueError(
                "Invalid severity: "
                f"{self.severity}. "
                f"Expected one of: {', '.join(SEVERITIES)}"
            )

        if not self.id.strip():
            raise ValueError(
                "Finding ID cannot be empty."
            )

        if not self.title.strip():
            raise ValueError(
                "Finding title cannot be empty."
            )

        if not self.category.strip():
            raise ValueError(
                "Finding category cannot be empty."
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a JSON-compatible dictionary."""

        data = asdict(self)

        if self.owasp is not None:
            data["owasp"] = (
                self.owasp.to_dict()
            )

        if self.cwe is not None:
            data["cwe"] = (
                self.cwe.to_dict()
            )

        if self.cvss is not None:
            data["cvss"] = (
                self.cvss.to_dict()
            )

        return data

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
    ) -> "SecurityFinding":
        """Create a SecurityFinding from a dictionary."""

        owasp_data = data.get(
            "owasp",
        )

        cwe_data = data.get(
            "cwe",
        )

        cvss_data = data.get(
            "cvss",
        )

        owasp = None

        if isinstance(
            owasp_data,
            dict,
        ):
            owasp = OWASPReference(
                id=str(
                    owasp_data.get(
                        "id",
                        "",
                    )
                ),
                name=str(
                    owasp_data.get(
                        "name",
                        "",
                    )
                ),
            )

        cwe = None

        if isinstance(
            cwe_data,
            dict,
        ):
            cwe = CWEReference(
                id=str(
                    cwe_data.get(
                        "id",
                        "",
                    )
                ),
                name=str(
                    cwe_data.get(
                        "name",
                        "",
                    )
                ),
            )

        cvss = None

        if isinstance(
            cvss_data,
            dict,
        ):
            cvss = CVSSScore(
                version=str(
                    cvss_data.get(
                        "version",
                        "",
                    )
                ),
                score=float(
                    cvss_data.get(
                        "score",
                        0.0,
                    )
                ),
                severity=str(
                    cvss_data.get(
                        "severity",
                        "",
                    )
                ),
                vector=str(
                    cvss_data.get(
                        "vector",
                        "",
                    )
                ),
            )

        return cls(
            id=str(
                data.get(
                    "id",
                    "",
                )
            ),
            title=str(
                data.get(
                    "title",
                    "",
                )
            ),
            severity=str(
                data.get(
                    "severity",
                    "INFO",
                )
            ),
            category=str(
                data.get(
                    "category",
                    "",
                )
            ),
            description=str(
                data.get(
                    "description",
                    "",
                )
            ),
            owasp=owasp,
            cwe=cwe,
            cvss=cvss,
            impact=str(
                data.get(
                    "impact",
                    "",
                )
            ),
            remediation=str(
                data.get(
                    "remediation",
                    "",
                )
            ),
            evidence=dict(
                data.get(
                    "evidence",
                    {},
                )
                or {}
            ),
            references=list(
                data.get(
                    "references",
                    [],
                )
                or []
            ),
            metadata=dict(
                data.get(
                    "metadata",
                    {},
                )
                or {}
            ),
        )
