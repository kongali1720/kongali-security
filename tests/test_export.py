import json

from kongali_security.analysis.report import (
    render_html,
    render_markdown,
)


def sample_report():
    return {
        "target": "https://example.com",
        "overall_risk": "HIGH",
        "overall_score": 50,
        "findings": [
            {
                "severity": "HIGH",
                "category": "HTTP Security Headers",
                "title": "Missing security header",
                "description": "A required security header is missing.",
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
    }


def test_export_json_structure(tmp_path):
    report = sample_report()

    output = tmp_path / "report.json"

    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    loaded = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert loaded["target"] == "https://example.com"
    assert loaded["overall_risk"] == "HIGH"
    assert "findings" in loaded
    assert "summary" in loaded


def test_export_markdown():
    report = sample_report()

    output = render_markdown(report)

    assert isinstance(output, str)
    assert "Kongali Security Report" in output
    assert "https://example.com" in output
    assert "HIGH" in output
    assert "Missing security header" in output


def test_export_html():
    report = sample_report()

    output = render_html(report)

    assert isinstance(output, str)
    assert "<html" in output.lower()
    assert "https://example.com" in output
    assert "Missing security header" in output


def test_export_report_files(tmp_path):
    report = sample_report()

    json_file = tmp_path / "report.json"
    markdown_file = tmp_path / "report.md"
    html_file = tmp_path / "report.html"

    json_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    markdown_file.write_text(
        render_markdown(report),
        encoding="utf-8",
    )

    html_file.write_text(
        render_html(report),
        encoding="utf-8",
    )

    assert json_file.exists()
    assert markdown_file.exists()
    assert html_file.exists()

    assert json_file.stat().st_size > 0
    assert markdown_file.stat().st_size > 0
    assert html_file.stat().st_size > 0
