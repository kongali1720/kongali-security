from kongali_security.analysis.cvss import (
    CVSSMetrics,
    build_cvss,
    calculate_cvss_base_score,
    cvss_severity,
)


def test_cvss_high_score():
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

    result = build_cvss(metrics)

    assert result["version"] == "3.1"
    assert result["score"] == 8.1
    assert result["severity"] == "HIGH"
    assert result["vector"].startswith(
        "CVSS:3.1/"
    )


def test_cvss_medium_score():
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

    score = calculate_cvss_base_score(
        metrics
    )

    assert score == 6.4
    assert cvss_severity(score) == "MEDIUM"


def test_cvss_zero_score():
    metrics = CVSSMetrics(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="N",
        integrity="N",
        availability="N",
    )

    score = calculate_cvss_base_score(
        metrics
    )

    assert score == 0.0
    assert cvss_severity(score) == "NONE"
