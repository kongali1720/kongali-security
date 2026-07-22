"""Tests for the Kongali Security report module."""

from kongali_security.analysis.report import (
    generate_report,
    render_html,
    render_markdown,
)


def test_generate_report() -> None:
    """Test report generation from a scan result."""

    scan = {
        "target": "https://example.com",
        "url": {
            "valid": True,
            "hostname": "example.com",
        },
        "dns": {
            "resolved": True,
        },
        "whois": {
            "queried": True,
        },
        "headers": {
            "security_score": 50,
            "risk_level": "MEDIUM",
            "missing": [
                "Content-Security-Policy",
            ],
        },
    }

    result = generate_report(scan)

    assert result["target"] == "https://example.com"
    assert "overall_risk" in result
    assert "overall_score" in result
    assert "findings" in result
    assert "summary" in result
    assert "scan" in result


def test_render_markdown() -> None:
    """Test Markdown report rendering."""

    report = {
        "target": "https://example.com",
        "overall_risk": "MEDIUM",
        "overall_score": 50,
        "findings": [],
        "summary": {
            "total_findings": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
        },
        "scan": {},
    }

    output = render_markdown(report)

    assert "# Kongali Security Report" in output
    assert "https://example.com" in output
    assert "MEDIUM" in output
    assert "50" in output


def test_render_html() -> None:
    """Test HTML report rendering."""

    report = {
        "target": "https://example.com",
        "overall_risk": "MEDIUM",
        "overall_score": 50,
        "findings": [],
        "summary": {
            "total_findings": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
        },
        "scan": {},
    }

    output = render_html(report)

    assert "<!DOCTYPE html>" in output
    assert "Kongali Security Report" in output
    assert "https://example.com" in output
    assert "MEDIUM" in output


def test_render_markdown_findings() -> None:
    """Test Markdown rendering of security findings."""

    report = {
        "target": "https://example.com",
        "overall_risk": "HIGH",
        "overall_score": 25,
        "findings": [
            {
                "severity": "HIGH",
                "category": "HTTP Security Headers",
                "title": "Missing security header",
                "description": "CSP header is missing.",
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
        "scan": {},
    }

    output = render_markdown(report)

    assert "Missing security header" in output
    assert "CSP header is missing." in output
