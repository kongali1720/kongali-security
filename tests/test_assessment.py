"""Contract tests for the Kongali Unified Assessment Engine."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from kongali_security.analysis.assessment import (
    _build_header_findings,
    _build_severity_summary,
    _extract_findings,
    run_unified_assessment,
)
from kongali_security.schemas.finding import (
    CVSSScore,
    CWEReference,
    OWASPReference,
    SecurityFinding,
)

TARGET = "https://example.com"


def make_finding(
    *,
    finding_id: str = "TEST-001",
    severity: str = "HIGH",
) -> SecurityFinding:
    """Create a representative SecurityFinding for contract tests."""

    return SecurityFinding(
        id=finding_id,
        title="Test security finding",
        severity=severity,
        category="Test",
        description="Test security finding description.",
        owasp=OWASPReference(
            id="A05:2021",
            name="Security Misconfiguration",
        ),
        cwe=CWEReference(
            id="CWE-693",
            name="Protection Mechanism Failure",
        ),
        cvss=CVSSScore(
            version="3.1",
            score=7.5,
            severity=severity,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
        impact="Test impact.",
        remediation="Test remediation.",
        evidence={
            "target": TARGET,
        },
        references=[
            "https://owasp.org/www-project-top-ten/",
        ],
        metadata={
            "source": "test",
        },
    )


def make_headers_result(
    missing: list[str],
) -> dict:
    """Create a minimal Headers Analyzer result."""

    return {
        "url": TARGET,
        "reachable": True,
        "status_code": 200,
        "headers": {},
        "present": [],
        "missing": missing,
        "security_score": 0,
        "risk_level": "HIGH",
        "metadata": {},
    }


# ============================================================================
# Header Finding Contract Tests
# ============================================================================


def test_header_findings_returns_security_finding_objects() -> None:
    """Header findings must use the unified SecurityFinding schema."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert len(findings) == 1
    assert isinstance(
        findings[0],
        SecurityFinding,
    )


def test_header_finding_id_is_stable() -> None:
    """Header finding IDs must follow the expected contract."""

    findings = _build_header_findings(
        make_headers_result(
            [
                "Content-Security-Policy",
                "Strict-Transport-Security",
            ]
        )
    )

    assert findings[0].id == "KONGALI-HEADERS-0001"
    assert findings[1].id == "KONGALI-HEADERS-0002"


def test_header_finding_title_contains_header_name() -> None:
    """Header finding title must identify the missing header."""

    findings = _build_header_findings(
        make_headers_result(
            ["X-Frame-Options"],
        )
    )

    assert (
        findings[0].title
        == "Missing security header: X-Frame-Options"
    )


def test_header_finding_category_is_http_security_headers() -> None:
    """Header findings must use the expected category."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert findings[0].category == "HTTP Security Headers"


def test_header_finding_severity_matches_knowledge_mapping() -> None:
    """Header severity must follow HEADER_KNOWLEDGE."""

    findings = _build_header_findings(
        make_headers_result(
            [
                "Content-Security-Policy",
                "Referrer-Policy",
            ]
        )
    )

    assert findings[0].severity == "HIGH"
    assert findings[1].severity == "MEDIUM"


def test_header_finding_contains_owasp_reference() -> None:
    """Header findings must preserve OWASP metadata."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert findings[0].owasp is not None
    assert findings[0].owasp.id == "A05:2021"
    assert (
        findings[0].owasp.name
        == "Security Misconfiguration"
    )


def test_header_finding_contains_cwe_reference() -> None:
    """Header findings must preserve CWE metadata."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert findings[0].cwe is not None
    assert findings[0].cwe.id == "CWE-693"


def test_header_finding_contains_cvss_metadata() -> None:
    """Header findings must preserve CVSS metadata."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert findings[0].cvss is not None
    assert findings[0].cvss.version == "3.1"
    assert findings[0].cvss.score == 8.1
    assert findings[0].cvss.severity == "HIGH"


def test_header_finding_evidence_contains_target() -> None:
    """Header finding evidence must identify the scanned target."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert findings[0].evidence["header"] == (
        "Content-Security-Policy"
    )
    assert findings[0].evidence["status"] == "missing"
    assert findings[0].evidence["target"] == TARGET


def test_header_finding_metadata_identifies_headers_source() -> None:
    """Header finding metadata must identify its source module."""

    findings = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    assert findings[0].metadata["source"] == "headers"
    assert findings[0].metadata["module"] == "headers_analyzer"


def test_header_findings_empty_when_missing_is_not_list() -> None:
    """Invalid missing-header data must produce no findings."""

    result = make_headers_result([])
    result["missing"] = "Content-Security-Policy"

    findings = _build_header_findings(result)

    assert findings == []


def test_header_findings_empty_when_no_headers_are_missing() -> None:
    """No missing headers must produce no findings."""

    findings = _build_header_findings(
        make_headers_result([])
    )

    assert findings == []


# ============================================================================
# Finding Extraction Contract Tests
# ============================================================================


def test_extract_findings_normalizes_dict_to_security_finding() -> None:
    """Dictionary findings must become SecurityFinding objects."""

    finding = make_finding()

    result = {
        "findings": [
            finding.to_dict(),
        ]
    }

    extracted = _extract_findings(result)

    assert len(extracted) == 1
    assert isinstance(
        extracted[0],
        SecurityFinding,
    )
    assert extracted[0].id == "TEST-001"


def test_extract_findings_preserves_security_finding_object() -> None:
    """Existing SecurityFinding objects must remain unchanged."""

    finding = make_finding()

    extracted = _extract_findings(
        {
            "findings": [
                finding,
            ]
        }
    )

    assert len(extracted) == 1
    assert extracted[0] is finding


def test_extract_findings_ignores_invalid_entries() -> None:
    """Invalid finding entries must not enter the unified pipeline."""

    extracted = _extract_findings(
        {
            "findings": [
                make_finding().to_dict(),
                "invalid",
                None,
                123,
                {},
            ]
        }
    )

    assert len(extracted) == 1
    assert extracted[0].id == "TEST-001"


def test_extract_findings_returns_empty_for_missing_findings() -> None:
    """Missing findings key must produce an empty list."""

    assert _extract_findings({}) == []


def test_extract_findings_returns_empty_for_invalid_findings_container() -> None:
    """Non-list findings containers must produce an empty list."""

    assert (
        _extract_findings(
            {
                "findings": "invalid",
            }
        )
        == []
    )


# ============================================================================
# Severity Summary Contract Tests
# ============================================================================


def test_severity_summary_counts_all_supported_severities() -> None:
    """Severity summary must count every supported severity."""

    findings = [
        make_finding(
            finding_id="CRITICAL-001",
            severity="CRITICAL",
        ),
        make_finding(
            finding_id="HIGH-001",
            severity="HIGH",
        ),
        make_finding(
            finding_id="HIGH-002",
            severity="HIGH",
        ),
        make_finding(
            finding_id="MEDIUM-001",
            severity="MEDIUM",
        ),
        make_finding(
            finding_id="LOW-001",
            severity="LOW",
        ),
        make_finding(
            finding_id="INFO-001",
            severity="INFO",
        ),
    ]

    summary = _build_severity_summary(findings)

    assert summary == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
    }


def test_severity_summary_returns_zero_for_empty_findings() -> None:
    """Empty findings must produce zero counts."""

    assert _build_severity_summary([]) == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }


def test_severity_summary_counts_normalized_severity() -> None:
    """SecurityFinding severity must be normalized to uppercase."""

    finding = make_finding(
        severity="high",
    )

    assert finding.severity == "HIGH"

    summary = _build_severity_summary(
        [finding],
    )

    assert summary["HIGH"] == 1
    assert set(summary) == {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }


# ============================================================================
# Unified Assessment Contract Tests
# ============================================================================


@patch(
    "kongali_security.analysis.assessment.analyze_url"
)
@patch(
    "kongali_security.analysis.assessment.analyze_headers"
)
@patch(
    "kongali_security.analysis.assessment.analyze_tls"
)
def test_unified_assessment_merges_all_finding_sources(
    mock_tls,
    mock_headers,
    mock_url,
) -> None:
    """Unified Assessment must merge URL, Headers, and TLS findings."""

    header_finding = _build_header_findings(
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )[0]

    tls_finding = make_finding(
        finding_id="KONGALI-TLS-001",
        severity="HIGH",
    )

    url_finding = make_finding(
        finding_id="KONGALI-URL-001",
        severity="MEDIUM",
    )

    mock_headers.return_value = (
        make_headers_result(
            ["Content-Security-Policy"],
        )
    )

    mock_tls.return_value = {
        "findings": [
            tls_finding.to_dict(),
        ]
    }

    mock_url.return_value = {
        "findings": [
            url_finding.to_dict(),
        ]
    }

    result = run_unified_assessment(TARGET)

    finding_ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert finding_ids == {
        header_finding.id,
        tls_finding.id,
        url_finding.id,
    }


@patch(
    "kongali_security.analysis.assessment.analyze_url"
)
@patch(
    "kongali_security.analysis.assessment.analyze_headers"
)
@patch(
    "kongali_security.analysis.assessment.analyze_tls"
)
def test_unified_assessment_serializes_findings_as_dicts(
    mock_tls,
    mock_headers,
    mock_url,
) -> None:
    """Unified Assessment output must be JSON-compatible dictionaries."""

    mock_headers.return_value = make_headers_result(
        ["Content-Security-Policy"],
    )
    mock_tls.return_value = {
        "findings": [],
    }
    mock_url.return_value = {
        "findings": [],
    }

    result = run_unified_assessment(TARGET)

    assert result["findings"]
    assert all(
        isinstance(
            finding,
            dict,
        )
        for finding in result["findings"]
    )


@patch(
    "kongali_security.analysis.assessment.analyze_url"
)
@patch(
    "kongali_security.analysis.assessment.analyze_headers"
)
@patch(
    "kongali_security.analysis.assessment.analyze_tls"
)
def test_unified_assessment_summary_matches_findings(
    mock_tls,
    mock_headers,
    mock_url,
) -> None:
    """Assessment summary must match the unified findings collection."""

    mock_headers.return_value = make_headers_result(
        [
            "Content-Security-Policy",
            "Referrer-Policy",
        ]
    )
    mock_tls.return_value = {
        "findings": [
            make_finding(
                finding_id="TLS-001",
                severity="HIGH",
            ).to_dict(),
        ]
    }
    mock_url.return_value = {
        "findings": [],
    }

    result = run_unified_assessment(TARGET)

    findings = result["findings"]
    summary = result["summary"]

    assert summary["total_findings"] == len(
        findings
    )

    assert (
        summary["severity_counts"]["HIGH"]
        == 2
    )

    assert (
        summary["severity_counts"]["MEDIUM"]
        == 1
    )


@patch(
    "kongali_security.analysis.assessment.analyze_url"
)
@patch(
    "kongali_security.analysis.assessment.analyze_headers"
)
@patch(
    "kongali_security.analysis.assessment.analyze_tls"
)
def test_unified_assessment_contains_expected_top_level_keys(
    mock_tls,
    mock_headers,
    mock_url,
) -> None:
    """Assessment output must preserve its public top-level contract."""

    mock_headers.return_value = make_headers_result([])
    mock_tls.return_value = {
        "findings": [],
    }
    mock_url.return_value = {
        "findings": [],
    }

    result = run_unified_assessment(TARGET)

    assert set(result) == {
        "target",
        "assessment",
        "findings",
        "summary",
        "metadata",
    }


@patch(
    "kongali_security.analysis.assessment.analyze_url"
)
@patch(
    "kongali_security.analysis.assessment.analyze_headers"
)
@patch(
    "kongali_security.analysis.assessment.analyze_tls"
)
def test_unified_assessment_preserves_target(
    mock_tls,
    mock_headers,
    mock_url,
) -> None:
    """Assessment output must preserve the requested target."""

    mock_headers.return_value = make_headers_result([])
    mock_tls.return_value = {
        "findings": [],
    }
    mock_url.return_value = {
        "findings": [],
    }

    result = run_unified_assessment(TARGET)

    assert result["target"] == TARGET


@patch(
    "kongali_security.analysis.assessment.analyze_url"
)
@patch(
    "kongali_security.analysis.assessment.analyze_headers"
)
@patch(
    "kongali_security.analysis.assessment.analyze_tls"
)
def test_unified_assessment_metadata_contract(
    mock_tls,
    mock_headers,
    mock_url,
) -> None:
    """Assessment metadata must identify engine, version, and sources."""

    mock_headers.return_value = make_headers_result([])
    mock_tls.return_value = {
        "findings": [],
    }
    mock_url.return_value = {
        "findings": [],
    }

    result = run_unified_assessment(TARGET)

    assert result["metadata"]["engine"] == (
        "Kongali Unified Assessment Engine"
    )

    assert result["metadata"]["version"] == "1.0.0"

    assert result["metadata"]["sources"] == [
        "url",
        "headers",
        "tls",
    ]


def test_security_finding_round_trip_preserves_nested_metadata() -> None:
    """SecurityFinding dict serialization must support round trips."""

    original = make_finding()

    serialized = original.to_dict()
    restored = SecurityFinding.from_dict(
        serialized
    )

    assert restored.id == original.id
    assert restored.title == original.title
    assert restored.severity == original.severity
    assert restored.category == original.category
    assert restored.description == original.description

    assert restored.owasp is not None
    assert restored.owasp.id == "A05:2021"

    assert restored.cwe is not None
    assert restored.cwe.id == "CWE-693"

    assert restored.cvss is not None
    assert restored.cvss.score == 7.5

    assert restored.evidence == original.evidence
    assert restored.metadata == original.metadata


@pytest.mark.parametrize(
    "missing_header",
    [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ],
)
def test_each_supported_missing_header_generates_one_finding(
    missing_header: str,
) -> None:
    """Every supported security header must produce one finding."""

    findings = _build_header_findings(
        make_headers_result(
            [missing_header],
        )
    )

    assert len(findings) == 1
    assert isinstance(
        findings[0],
        SecurityFinding,
    )
    assert (
        findings[0].evidence["header"]
        == missing_header
    )


@pytest.mark.parametrize(
    "severity",
    [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ],
)
def test_supported_severities_are_accepted(
    severity: str,
) -> None:
    """SecurityFinding must accept every supported severity."""

    finding = make_finding(
        severity=severity,
    )

    assert finding.severity == severity
