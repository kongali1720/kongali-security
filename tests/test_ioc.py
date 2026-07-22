"""
Kongali Security IOC Analyzer Tests
====================================

Test suite for the Kongali Security IOC Analyzer.

Covered IOC types:

- IPv4
- IPv6
- Domain
- URL
- MD5
- SHA-1
- SHA-256
- SHA-512
- Unknown input
- Empty input
- Multiple IOC analysis
- Private IP configuration
- Localhost configuration
"""

from kongali_security.analysis.ioc import (
    IOCAnalyzer,
    IOCType,
    analyze_ioc,
)


class TestIOCAnalyzer:
    """Test suite for IOCAnalyzer."""

    def setup_method(self) -> None:
        """Create a fresh IOCAnalyzer for every test."""

        self.analyzer = IOCAnalyzer()

    def test_ipv4_detection(self) -> None:
        """Test valid IPv4 detection."""

        result = self.analyzer.analyze(
            "8.8.8.8"
        )

        assert result.ioc_type == IOCType.IPV4
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["version"] == 4
        assert result.metadata["is_global"] is True

    def test_ipv6_detection(self) -> None:
        """Test valid IPv6 detection."""

        result = self.analyzer.analyze(
            "2001:4860:4860::8888"
        )

        assert result.ioc_type == IOCType.IPV6
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["version"] == 6

    def test_private_ipv4_detection(self) -> None:
        """Test private IPv4 detection."""

        result = self.analyzer.analyze(
            "192.168.1.1"
        )

        assert result.ioc_type == IOCType.IPV4
        assert result.valid is True
        assert result.metadata["is_private"] is True

    def test_private_ipv4_can_be_rejected(self) -> None:
        """Test private IPv4 rejection when disabled."""

        analyzer = IOCAnalyzer(
            allow_private_ips=False
        )

        result = analyzer.analyze(
            "192.168.1.1"
        )

        assert result.ioc_type == IOCType.IPV4
        assert result.valid is False

    def test_localhost_detection(self) -> None:
        """Test localhost IPv4 detection."""

        result = self.analyzer.analyze(
            "127.0.0.1"
        )

        assert result.ioc_type == IOCType.IPV4
        assert result.valid is True
        assert result.metadata["is_loopback"] is True

    def test_localhost_can_be_rejected(self) -> None:
        """Test localhost rejection when disabled."""

        analyzer = IOCAnalyzer(
            allow_localhost=False
        )

        result = analyzer.analyze(
            "127.0.0.1"
        )

        assert result.ioc_type == IOCType.IPV4
        assert result.valid is False

    def test_md5_detection(self) -> None:
        """Test MD5 hash detection."""

        result = self.analyzer.analyze(
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        assert result.ioc_type == IOCType.MD5
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["algorithm"] == "openssl_md5"

    def test_sha1_detection(self) -> None:
        """Test SHA-1 hash detection."""

        result = self.analyzer.analyze(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )

        assert result.ioc_type == IOCType.SHA1
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["algorithm"] == "openssl_sha1"

    def test_sha256_detection(self) -> None:
        """Test SHA-256 hash detection."""

        result = self.analyzer.analyze(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )

        assert result.ioc_type == IOCType.SHA256
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["algorithm"] == "openssl_sha256"

    def test_sha512_detection(self) -> None:
        """Test SHA-512 hash detection."""

        result = self.analyzer.analyze(
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e"
        )

        assert result.ioc_type == IOCType.SHA512
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["algorithm"] == "openssl_sha512"

    def test_domain_detection(self) -> None:
        """Test domain detection."""

        result = self.analyzer.analyze(
            "example.com"
        )

        assert result.ioc_type == IOCType.DOMAIN
        assert result.valid is True
        assert result.confidence == 0.95
        assert result.metadata["tld"] == "com"

    def test_subdomain_detection(self) -> None:
        """Test subdomain detection."""

        result = self.analyzer.analyze(
            "api.example.com"
        )

        assert result.ioc_type == IOCType.DOMAIN
        assert result.valid is True
        assert result.metadata["label_count"] == 3

    def test_domain_case_normalization(self) -> None:
        """Test domain normalization to lowercase."""

        result = self.analyzer.analyze(
            "EXAMPLE.COM"
        )

        assert result.ioc_type == IOCType.DOMAIN
        assert result.valid is True
        assert result.value == "example.com"

    def test_domain_trailing_dot(self) -> None:
        """Test fully qualified domain with trailing dot."""

        result = self.analyzer.analyze(
            "example.com."
        )

        assert result.ioc_type == IOCType.DOMAIN
        assert result.valid is True
        assert result.value == "example.com"

    def test_url_detection(self) -> None:
        """Test HTTP URL detection."""

        result = self.analyzer.analyze(
            "https://example.com"
        )

        assert result.ioc_type == IOCType.URL
        assert result.valid is True
        assert result.confidence == 1.0
        assert result.metadata["scheme"] == "https"
        assert result.metadata["hostname"] == "example.com"

    def test_url_with_path(self) -> None:
        """Test URL containing a path."""

        result = self.analyzer.analyze(
            "https://example.com/security/report"
        )

        assert result.ioc_type == IOCType.URL
        assert result.valid is True
        assert result.metadata["path"] == "/security/report"

    def test_url_with_query(self) -> None:
        """Test URL containing query parameters."""

        result = self.analyzer.analyze(
            "https://example.com/search?q=security"
        )

        assert result.ioc_type == IOCType.URL
        assert result.valid is True
        assert result.metadata["query"] == "q=security"

    def test_empty_input(self) -> None:
        """Test empty input handling."""

        result = self.analyzer.analyze(
            ""
        )

        assert result.ioc_type == IOCType.UNKNOWN
        assert result.valid is False
        assert result.confidence == 0.0

    def test_whitespace_input(self) -> None:
        """Test whitespace input handling."""

        result = self.analyzer.analyze(
            "   "
        )

        assert result.ioc_type == IOCType.UNKNOWN
        assert result.valid is False

    def test_unknown_input(self) -> None:
        """Test unsupported IOC input."""

        result = self.analyzer.analyze(
            "not-a-valid-ioc"
        )

        assert result.ioc_type == IOCType.UNKNOWN
        assert result.valid is False
        assert result.confidence == 0.0

    def test_analyze_many(self) -> None:
        """Test multiple IOC analysis."""

        values = [
            "8.8.8.8",
            "example.com",
            "https://example.com",
            "d41d8cd98f00b204e9800998ecf8427e",
        ]

        results = self.analyzer.analyze_many(
            values
        )

        assert len(results) == 4

        assert results[0].ioc_type == IOCType.IPV4
        assert results[1].ioc_type == IOCType.DOMAIN
        assert results[2].ioc_type == IOCType.URL
        assert results[3].ioc_type == IOCType.MD5

    def test_result_to_dict(self) -> None:
        """Test IOCResult dictionary serialization."""

        result = self.analyzer.analyze(
            "8.8.8.8"
        )

        data = result.to_dict()

        assert isinstance(data, dict)
        assert data["value"] == "8.8.8.8"
        assert data["type"] == "ipv4"
        assert data["valid"] is True
        assert data["confidence"] == 1.0

    def test_convenience_function(self) -> None:
        """Test analyze_ioc convenience function."""

        result = analyze_ioc(
            "example.com"
        )

        assert isinstance(result, dict)
        assert result["value"] == "example.com"
        assert result["type"] == "domain"
        assert result["valid"] is True

    def test_hash_is_case_insensitive(self) -> None:
        """Test uppercase hexadecimal hashes."""

        result = self.analyzer.analyze(
            "D41D8CD98F00B204E9800998ECF8427E"
        )

        assert result.ioc_type == IOCType.MD5
        assert result.valid is True
        assert result.value == (
            "d41d8cd98f00b204e9800998ecf8427e"
        )
