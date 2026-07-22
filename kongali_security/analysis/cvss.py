"""CVSS 3.1 scoring utilities for Kongali Security."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CVSSMetrics:
    """CVSS 3.1 base metrics."""

    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str


# CVSS 3.1 metric weights.
AV_VALUES: dict[str, float] = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

AC_VALUES: dict[str, float] = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

PR_VALUES_UNCHANGED: dict[str, float] = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27,
}

PR_VALUES_CHANGED: dict[str, float] = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50,
}

UI_VALUES: dict[str, float] = {
    "N": 0.85,
    "R": 0.62,
}

CIA_VALUES: dict[str, float] = {
    "N": 0.00,
    "L": 0.22,
    "H": 0.56,
}


def _round_up(value: float) -> float:
    """Round a CVSS value upward to one decimal place."""

    return float(
        f"{value + 1e-10:.1f}"
    )


def calculate_cvss_base_score(
    metrics: CVSSMetrics,
) -> float:
    """Calculate a CVSS 3.1 base score."""

    av = AV_VALUES[metrics.attack_vector]
    ac = AC_VALUES[metrics.attack_complexity]

    if metrics.scope == "U":
        pr = PR_VALUES_UNCHANGED[
            metrics.privileges_required
        ]
    else:
        pr = PR_VALUES_CHANGED[
            metrics.privileges_required
        ]

    ui = UI_VALUES[
        metrics.user_interaction
    ]

    confidentiality = CIA_VALUES[
        metrics.confidentiality
    ]

    integrity = CIA_VALUES[
        metrics.integrity
    ]

    availability = CIA_VALUES[
        metrics.availability
    ]

    exploitability = (
        8.22
        * av
        * ac
        * pr
        * ui
    )

    impact_sub_score = (
        1
        - (
            (1 - confidentiality)
            * (1 - integrity)
            * (1 - availability)
        )
    )

    if metrics.scope == "U":
        impact = (
            6.42
            * impact_sub_score
        )
    else:
        impact = (
            7.52
            * (
                impact_sub_score
                - 0.029
            )
            - 3.25
            * (
                impact_sub_score
                - 0.02
            ) ** 15
        )

    if impact <= 0:
        return 0.0

    if metrics.scope == "U":
        base_score = min(
            impact + exploitability,
            10,
        )
    else:
        base_score = min(
            1.08
            * (
                impact
                + exploitability
            ),
            10,
        )

    return _round_up(
        base_score
    )


def cvss_severity(
    score: float,
) -> str:
    """Convert a CVSS score to a severity rating."""

    if score == 0:
        return "NONE"

    if score <= 3.9:
        return "LOW"

    if score <= 6.9:
        return "MEDIUM"

    if score <= 8.9:
        return "HIGH"

    return "CRITICAL"


def build_cvss_vector(
    metrics: CVSSMetrics,
) -> str:
    """Build a CVSS 3.1 vector string."""

    return (
        "CVSS:3.1/"
        f"AV:{metrics.attack_vector}/"
        f"AC:{metrics.attack_complexity}/"
        f"PR:{metrics.privileges_required}/"
        f"UI:{metrics.user_interaction}/"
        f"S:{metrics.scope}/"
        f"C:{metrics.confidentiality}/"
        f"I:{metrics.integrity}/"
        f"A:{metrics.availability}"
    )


def build_cvss(
    metrics: CVSSMetrics,
) -> dict[str, object]:
    """Build a complete CVSS result."""

    score = calculate_cvss_base_score(
        metrics
    )

    return {
        "version": "3.1",
        "score": score,
        "severity": cvss_severity(
            score
        ),
        "vector": build_cvss_vector(
            metrics
        ),
    }


def default_cvss_for_finding(
    finding: dict[str, object],
) -> dict[str, object]:
    """Generate a conservative default CVSS assessment.

    The current Kongali Security findings are primarily
    remotely observable HTTP security configuration issues.
    """

    severity = str(
        finding.get(
            "severity",
            "LOW",
        )
    ).upper()

    if severity == "CRITICAL":
        metrics = CVSSMetrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

    elif severity == "HIGH":
        metrics = CVSSMetrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="L",
            availability="N",
        )

    elif severity == "MEDIUM":
        metrics = CVSSMetrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="N",
        )

    else:
        metrics = CVSSMetrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="L",
            availability="N",
        )

    return build_cvss(
        metrics
    )
