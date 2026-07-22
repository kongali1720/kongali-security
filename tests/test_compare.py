"""Tests for security baseline comparison utilities."""

from __future__ import annotations

import json

import pytest

from kongali_security.analysis.compare import (
    _finding_key,
    compare_reports,
    load_json,
)


def make_finding(
    *,
    category: str = "HTTP Security Headers",
    title: str = "Missing security header",
    severity: str = "HIGH",
) -> dict:
    """Build a deterministic finding dictionary."""

    return {
        "category": category,
        "title": title,
        "severity": severity,
    }


def make_report(
    *,
    target: str = "https://example.com",
    score: float = 80,
    risk: str = "MEDIUM",
    findings: list[dict] | None = None,
) -> dict:
    """Build a deterministic security report."""

    return {
        "target": target,
        "overall_score": score,
        "overall_risk": risk,
        "findings": (
            findings
            if findings is not None
            else []
        ),
    }


# ============================================================
# load_json
# ============================================================


def test_load_json_returns_dictionary(tmp_path) -> None:
    """load_json must return JSON objects as dictionaries."""

    path = tmp_path / "report.json"

    path.write_text(
        json.dumps(
            {
                "target": "https://example.com",
                "overall_score": 90,
            }
        ),
        encoding="utf-8",
    )

    result = load_json(path)

    assert isinstance(result, dict)
    assert result["target"] == "https://example.com"
    assert result["overall_score"] == 90


def test_load_json_accepts_string_path(tmp_path) -> None:
    """load_json must accept string paths."""

    path = tmp_path / "report.json"

    path.write_text(
        '{"target": "https://example.com"}',
        encoding="utf-8",
    )

    result = load_json(str(path))

    assert result["target"] == "https://example.com"


def test_load_json_accepts_path_object(tmp_path) -> None:
    """load_json must accept pathlib.Path objects."""

    path = tmp_path / "report.json"

    path.write_text(
        '{"overall_score": 75}',
        encoding="utf-8",
    )

    result = load_json(path)

    assert result["overall_score"] == 75


def test_load_json_preserves_nested_json_data(tmp_path) -> None:
    """load_json must preserve nested JSON structures."""

    path = tmp_path / "report.json"

    payload = {
        "target": "https://example.com",
        "metadata": {
            "engine": "Kongali Unified Assessment Engine",
            "version": "1.0.0",
        },
    }

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    result = load_json(path)

    assert result == payload


def test_load_json_raises_for_missing_file(tmp_path) -> None:
    """load_json must raise when the file does not exist."""

    path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_json(path)


def test_load_json_raises_for_invalid_json(tmp_path) -> None:
    """load_json must reject malformed JSON."""

    path = tmp_path / "invalid.json"

    path.write_text(
        "{invalid-json",
        encoding="utf-8",
    )

    with pytest.raises(json.JSONDecodeError):
        load_json(path)


def test_load_json_rejects_json_list(tmp_path) -> None:
    """load_json must reject a JSON array root."""

    path = tmp_path / "list.json"

    path.write_text(
        json.dumps(
            [
                {"finding": "test"},
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="JSON root must be an object"):
        load_json(path)


def test_load_json_rejects_json_string(tmp_path) -> None:
    """load_json must reject a JSON string root."""

    path = tmp_path / "string.json"

    path.write_text(
        json.dumps("hello"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="JSON root must be an object"):
        load_json(path)


# ============================================================
# _finding_key
# ============================================================


def test_finding_key_returns_expected_tuple() -> None:
    """_finding_key must produce a stable three-field tuple."""

    finding = make_finding()

    result = _finding_key(finding)

    assert result == (
        "HTTP Security Headers",
        "Missing security header",
        "HIGH",
    )


def test_finding_key_uses_category_title_and_severity() -> None:
    """Finding identity must include category, title, and severity."""

    finding = make_finding(
        category="TLS Configuration",
        title="Weak TLS Protocol",
        severity="HIGH",
    )

    assert _finding_key(finding) == (
        "TLS Configuration",
        "Weak TLS Protocol",
        "HIGH",
    )


def test_finding_key_defaults_missing_values_to_empty_strings() -> None:
    """Missing finding fields must normalize to empty strings."""

    assert _finding_key({}) == (
        "",
        "",
        "",
    )


def test_finding_key_converts_values_to_strings() -> None:
    """Finding key values must be string-compatible."""

    finding = {
        "category": 123,
        "title": True,
        "severity": None,
    }

    assert _finding_key(finding) == (
        "123",
        "True",
        "None",
    )


def test_finding_key_changes_when_category_changes() -> None:
    """Changing category must produce a different key."""

    first = make_finding(
        category="Headers",
    )

    second = make_finding(
        category="TLS",
    )

    assert _finding_key(first) != _finding_key(second)


def test_finding_key_changes_when_title_changes() -> None:
    """Changing title must produce a different key."""

    first = make_finding(
        title="Finding A",
    )

    second = make_finding(
        title="Finding B",
    )

    assert _finding_key(first) != _finding_key(second)


def test_finding_key_changes_when_severity_changes() -> None:
    """Changing severity must produce a different key."""

    first = make_finding(
        severity="HIGH",
    )

    second = make_finding(
        severity="MEDIUM",
    )

    assert _finding_key(first) != _finding_key(second)


# ============================================================
# compare_reports - basic contract
# ============================================================


def test_compare_reports_returns_dictionary() -> None:
    """compare_reports must return a dictionary."""

    result = compare_reports(
        make_report(),
        make_report(),
    )

    assert isinstance(result, dict)


def test_compare_reports_contains_expected_top_level_keys() -> None:
    """Comparison result must contain the complete contract."""

    result = compare_reports(
        make_report(),
        make_report(),
    )

    expected_keys = {
        "target",
        "baseline_risk",
        "current_risk",
        "baseline_score",
        "current_score",
        "score_change",
        "new_findings",
        "resolved_findings",
        "new_findings_count",
        "resolved_findings_count",
        "security_trend",
        "regression",
    }

    assert set(result) == expected_keys


def test_compare_reports_preserves_current_target() -> None:
    """Current report target must take precedence."""

    baseline = make_report(
        target="https://baseline.example.com",
    )

    current = make_report(
        target="https://current.example.com",
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["target"] == (
        "https://current.example.com"
    )


def test_compare_reports_falls_back_to_baseline_target() -> None:
    """Baseline target must be used when current target is absent."""

    baseline = make_report(
        target="https://baseline.example.com",
    )

    current = {
        "overall_score": 80,
        "overall_risk": "MEDIUM",
        "findings": [],
    }

    result = compare_reports(
        baseline,
        current,
    )

    assert result["target"] == (
        "https://baseline.example.com"
    )


def test_compare_reports_uses_empty_target_when_both_missing() -> None:
    """Missing targets must resolve to an empty string."""

    result = compare_reports(
        {},
        {},
    )

    assert result["target"] == ""


def test_compare_reports_preserves_risk_values() -> None:
    """Baseline and current risk values must be preserved."""

    baseline = make_report(
        risk="HIGH",
    )

    current = make_report(
        risk="LOW",
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["baseline_risk"] == "HIGH"
    assert result["current_risk"] == "LOW"


def test_compare_reports_preserves_scores() -> None:
    """Baseline and current scores must be preserved."""

    baseline = make_report(
        score=70,
    )

    current = make_report(
        score=90,
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["baseline_score"] == 70
    assert result["current_score"] == 90


# ============================================================
# Finding comparison
# ============================================================


def test_compare_reports_detects_new_findings() -> None:
    """Findings present only in current report are new."""

    baseline = make_report(
        findings=[],
    )

    current = make_report(
        findings=[
            make_finding(
                title="New Finding",
            ),
        ],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings"] == [
        {
            "category": "HTTP Security Headers",
            "title": "New Finding",
            "severity": "HIGH",
        }
    ]

    assert result["new_findings_count"] == 1


def test_compare_reports_detects_resolved_findings() -> None:
    """Findings present only in baseline are resolved."""

    baseline = make_report(
        findings=[
            make_finding(
                title="Resolved Finding",
            ),
        ],
    )

    current = make_report(
        findings=[],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["resolved_findings"] == [
        {
            "category": "HTTP Security Headers",
            "title": "Resolved Finding",
            "severity": "HIGH",
        }
    ]

    assert result["resolved_findings_count"] == 1


def test_compare_reports_identical_findings_have_no_changes() -> None:
    """Identical findings must produce no new or resolved findings."""

    finding = make_finding()

    baseline = make_report(
        findings=[finding],
    )

    current = make_report(
        findings=[finding],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings"] == []
    assert result["resolved_findings"] == []
    assert result["new_findings_count"] == 0
    assert result["resolved_findings_count"] == 0


def test_compare_reports_handles_multiple_new_findings() -> None:
    """Multiple current-only findings must all be reported."""

    baseline = make_report()

    current = make_report(
        findings=[
            make_finding(
                title="Finding A",
            ),
            make_finding(
                title="Finding B",
                severity="MEDIUM",
            ),
        ],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings_count"] == 2
    assert len(result["new_findings"]) == 2


def test_compare_reports_handles_multiple_resolved_findings() -> None:
    """Multiple baseline-only findings must all be reported."""

    baseline = make_report(
        findings=[
            make_finding(
                title="Finding A",
            ),
            make_finding(
                title="Finding B",
                severity="MEDIUM",
            ),
        ],
    )

    current = make_report()

    result = compare_reports(
        baseline,
        current,
    )

    assert result["resolved_findings_count"] == 2
    assert len(result["resolved_findings"]) == 2


def test_compare_reports_ignores_non_dictionary_findings() -> None:
    """Non-dictionary finding entries must be ignored."""

    baseline = {
        "findings": [
            "invalid",
            None,
            123,
        ],
    }

    current = {
        "findings": [
            make_finding(),
        ],
    }

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings_count"] == 1
    assert result["resolved_findings_count"] == 0


def test_compare_reports_deduplicates_identical_findings() -> None:
    """Duplicate findings with the same identity must count once."""

    finding = make_finding()

    baseline = make_report(
        findings=[],
    )

    current = make_report(
        findings=[
            finding,
            finding.copy(),
            finding.copy(),
        ],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings_count"] == 1
    assert len(result["new_findings"]) == 1


def test_compare_reports_sorts_new_findings() -> None:
    """New findings must be returned in deterministic sorted order."""

    baseline = make_report()

    current = make_report(
        findings=[
            make_finding(
                category="Z Category",
                title="Z Finding",
            ),
            make_finding(
                category="A Category",
                title="A Finding",
            ),
        ],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings"][0]["category"] == (
        "A Category"
    )

    assert result["new_findings"][1]["category"] == (
        "Z Category"
    )


# ============================================================
# Score and trend
# ============================================================


def test_compare_reports_improved_when_score_increases() -> None:
    """Higher current score must produce IMPROVED trend."""

    result = compare_reports(
        make_report(score=70),
        make_report(score=90),
    )

    assert result["security_trend"] == "IMPROVED"
    assert result["regression"] is False


def test_compare_reports_regressed_when_score_decreases() -> None:
    """Lower current score must produce REGRESSED trend."""

    result = compare_reports(
        make_report(score=90),
        make_report(score=70),
    )

    assert result["security_trend"] == "REGRESSED"
    assert result["regression"] is True


def test_compare_reports_unchanged_when_scores_equal() -> None:
    """Equal scores must produce UNCHANGED trend."""

    result = compare_reports(
        make_report(score=80),
        make_report(score=80),
    )

    assert result["security_trend"] == "UNCHANGED"
    assert result["regression"] is False


def test_compare_reports_calculates_positive_score_change() -> None:
    """Positive score changes must be calculated correctly."""

    result = compare_reports(
        make_report(score=60),
        make_report(score=85),
    )

    assert result["score_change"] == 25


def test_compare_reports_calculates_negative_score_change() -> None:
    """Negative score changes must be calculated correctly."""

    result = compare_reports(
        make_report(score=85),
        make_report(score=60),
    )

    assert result["score_change"] == -25


def test_compare_reports_calculates_zero_score_change() -> None:
    """Equal scores must produce zero score change."""

    result = compare_reports(
        make_report(score=80),
        make_report(score=80),
    )

    assert result["score_change"] == 0


# ============================================================
# Defaults and edge cases
# ============================================================


def test_compare_reports_defaults_missing_findings_to_empty() -> None:
    """Missing findings keys must be treated as empty lists."""

    result = compare_reports(
        {},
        {},
    )

    assert result["new_findings"] == []
    assert result["resolved_findings"] == []
    assert result["new_findings_count"] == 0
    assert result["resolved_findings_count"] == 0


def test_compare_reports_defaults_missing_scores_to_zero() -> None:
    """Missing scores must default to zero."""

    result = compare_reports(
        {},
        {},
    )

    assert result["baseline_score"] == 0
    assert result["current_score"] == 0
    assert result["score_change"] == 0


def test_compare_reports_defaults_missing_risk_to_unknown() -> None:
    """Missing risk values must default to UNKNOWN."""

    result = compare_reports(
        {},
        {},
    )

    assert result["baseline_risk"] == "UNKNOWN"
    assert result["current_risk"] == "UNKNOWN"


def test_compare_reports_empty_reports_are_unchanged() -> None:
    """Two empty reports must compare as unchanged."""

    result = compare_reports(
        {},
        {},
    )

    assert result["security_trend"] == "UNCHANGED"
    assert result["regression"] is False


def test_compare_reports_finding_identity_includes_severity() -> None:
    """Same finding title with different severity is a change."""

    baseline = make_report(
        findings=[
            make_finding(
                title="Same Finding",
                severity="HIGH",
            ),
        ],
    )

    current = make_report(
        findings=[
            make_finding(
                title="Same Finding",
                severity="MEDIUM",
            ),
        ],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings_count"] == 1
    assert result["resolved_findings_count"] == 1


def test_compare_reports_result_counts_match_result_lists() -> None:
    """Finding counts must match their corresponding result lists."""

    baseline = make_report(
        findings=[
            make_finding(
                title="Resolved",
            ),
        ],
    )

    current = make_report(
        findings=[
            make_finding(
                title="New",
            ),
        ],
    )

    result = compare_reports(
        baseline,
        current,
    )

    assert result["new_findings_count"] == len(
        result["new_findings"]
    )

    assert result["resolved_findings_count"] == len(
        result["resolved_findings"]
    )
