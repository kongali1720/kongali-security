from kongali_security.analysis.audit import analyze_audit


def test_analyze_audit(monkeypatch):
    fake_scan = {
        "target": "https://example.com",
    }

    fake_report = {
        "target": "https://example.com",
        "overall_risk": "HIGH",
        "overall_score": 50,
        "findings": [
            {
                "severity": "HIGH",
                "category": "HTTP Security Headers",
                "title": "Missing security header",
                "description": "A security header is missing.",
            }
        ],
        "summary": {
            "total_findings": 1,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 0,
                "LOW": 0,
            },
        },
        "scan": fake_scan,
    }

    monkeypatch.setattr(
        "kongali_security.analysis.audit.analyze_scan",
        lambda target: fake_scan,
    )

    monkeypatch.setattr(
        "kongali_security.analysis.audit.generate_report",
        lambda scan: fake_report,
    )

    result = analyze_audit(
        "https://example.com"
    )

    assert result["target"] == "https://example.com"
    assert result["audit_type"] == "security_assessment"

    assert result["risk"]["overall_risk"] == "HIGH"
    assert result["risk"]["overall_score"] == 50

    assert "executive_summary" in result
    assert "findings" in result
    assert "summary" in result
    assert "scan" in result
    assert "recommendations" in result

    assert len(result["findings"]) == 1
    assert len(result["recommendations"]) == 1


def test_audit_recommendation():
    from kongali_security.analysis.audit import (
        _build_recommendations,
    )

    report = {
        "findings": [
            {
                "severity": "HIGH",
                "category": "HTTP Security Headers",
                "title": "Missing CSP",
            }
        ]
    }

    recommendations = _build_recommendations(
        report
    )

    assert len(recommendations) == 1
    assert recommendations[0]["severity"] == "HIGH"
    assert "recommendation" in recommendations[0]
