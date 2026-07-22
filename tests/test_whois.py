from __future__ import annotations

from kongali_security.analysis.whois import (
    WHOISAnalyzer,
    WHOISResult,
    analyze_whois,
)


class TestWHOISAnalyzer:
    """Test WHOIS Analyzer."""

    def test_empty_input(self) -> None:
        result = analyze_whois("")

        assert result.valid is False
        assert result.queried is False

    def test_invalid_domain(self) -> None:
        result = analyze_whois(
            "not a valid domain"
        )

        assert result.valid is False
        assert result.queried is False

    def test_domain_normalization(self) -> None:
        result = analyze_whois(
            "Example.COM."
        )

        assert result.domain == "example.com"

    def test_result_to_dict(self) -> None:
        result = WHOISResult(
            domain="example.com",
            valid=True,
            queried=False,
            registrar=None,
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            name_servers=[],
            statuses=[],
            metadata={},
        )

        data = result.to_dict()

        assert data["domain"] == "example.com"
        assert data["valid"] is True
        assert data["queried"] is False

    def test_missing_whois_client(
        self,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            "shutil.which",
            lambda _: None,
        )

        result = analyze_whois(
            "example.com"
        )

        assert result.valid is True
        assert result.queried is False
        assert "error" in result.metadata

    def test_parse_whois_output(self) -> None:
        analyzer = WHOISAnalyzer()

        output = """
Registrar: Example Registrar
Creation Date: 2020-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Updated Date: 2025-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Domain Status: clientTransferProhibited
"""

        assert analyzer._extract_first(
            output,
            [r"^Registrar:\s*(.+)$"],
        ) == "Example Registrar"

        assert analyzer._extract_first(
            output,
            [r"^Creation Date:\s*(.+)$"],
        ) == "2020-01-01T00:00:00Z"

        assert analyzer._extract_all(
            output,
            [r"^Name Server:\s*(.+)$"],
        ) == [
            "ns1.example.com",
            "ns2.example.com",
        ]

        assert analyzer._extract_all(
            output,
            [r"^Domain Status:\s*(.+)$"],
        ) == [
            "clientTransferProhibited",
        ]

    def test_analyze_whois_convenience_function(
        self,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            "shutil.which",
            lambda _: None,
        )

        result = analyze_whois(
            "example.com"
        )

        assert result.domain == "example.com"
        assert result.valid is True
