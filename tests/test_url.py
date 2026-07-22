"""Tests for the URL Analyzer."""

from kongali_security.analysis.url import (
    URLAnalyzer,
    URLType,
    analyze_url,
)


class TestURLAnalyzer:
    """Test URL analysis functionality."""

    def test_https_url(self) -> None:
        result = analyze_url(
            "https://example.com/login"
        )

        assert result.valid is True
        assert result.url_type == URLType.URL
        assert result.scheme == "https"
        assert result.hostname == "example.com"
        assert result.path == "/login"

    def test_http_url(self) -> None:
        result = analyze_url(
            "http://example.com"
        )

        assert result.valid is True
        assert result.scheme == "http"
        assert result.hostname == "example.com"

    def test_url_with_port(self) -> None:
        result = analyze_url(
            "https://example.com:8443/login"
        )

        assert result.valid is True
        assert result.port == 8443

    def test_url_with_query(self) -> None:
        result = analyze_url(
            "https://example.com/search?q=kongali"
        )

        assert result.valid is True
        assert result.query == "q=kongali"

    def test_url_with_fragment(self) -> None:
        result = analyze_url(
            "https://example.com/page#section"
        )

        assert result.valid is True
        assert result.fragment == "section"

    def test_ftp_url(self) -> None:
        result = analyze_url(
            "ftp://example.com/file.txt"
        )

        assert result.valid is True
        assert result.scheme == "ftp"

    def test_invalid_url_without_scheme(self) -> None:
        result = analyze_url(
            "example.com/login"
        )

        assert result.valid is False
        assert result.url_type == URLType.UNKNOWN

    def test_invalid_url_without_hostname(self) -> None:
        result = analyze_url(
            "https:///login"
        )

        assert result.valid is False

    def test_unsupported_scheme(self) -> None:
        result = analyze_url(
            "javascript:alert(1)"
        )

        assert result.valid is False

    def test_empty_input(self) -> None:
        result = analyze_url("")

        assert result.valid is False

    def test_whitespace_input(self) -> None:
        result = analyze_url("   ")

        assert result.valid is False

    def test_to_dict(self) -> None:
        result = analyze_url(
            "https://example.com/login"
        )

        data = result.to_dict()

        assert data["value"] == (
            "https://example.com/login"
        )
        assert data["type"] == "url"
        assert data["valid"] is True
        assert data["hostname"] == "example.com"
