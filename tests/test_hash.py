"""Tests for the Kongali Security Hash Analyzer."""

from kongali_security.analysis.hash import (
    HashAnalyzer,
    HashType,
    analyze_hash,
)


class TestHashAnalyzer:
    """Test cryptographic hash detection and validation."""

    def setup_method(self) -> None:
        """Create a fresh analyzer for each test."""
        self.analyzer = HashAnalyzer()

    def test_md5_detection(self) -> None:
        """Test MD5 hash detection."""
        result = self.analyzer.analyze(
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        assert result.hash_type == HashType.MD5
        assert result.length == 32
        assert result.valid is True
        assert result.algorithm == "md5"
        assert result.metadata["hexadecimal"] is True

    def test_sha1_detection(self) -> None:
        """Test SHA-1 hash detection."""
        result = self.analyzer.analyze(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )

        assert result.hash_type == HashType.SHA1
        assert result.length == 40
        assert result.valid is True
        assert result.algorithm == "sha1"

    def test_sha256_detection(self) -> None:
        """Test SHA-256 hash detection."""
        result = self.analyzer.analyze(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )

        assert result.hash_type == HashType.SHA256
        assert result.length == 64
        assert result.valid is True
        assert result.algorithm == "sha256"

    def test_sha512_detection(self) -> None:
        """Test SHA-512 hash detection."""
        result = self.analyzer.analyze(
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e"
        )

        assert result.hash_type == HashType.SHA512
        assert result.length == 128
        assert result.valid is True
        assert result.algorithm == "sha512"

    def test_hash_is_case_insensitive(self) -> None:
        """Test uppercase hash normalization."""
        result = self.analyzer.analyze(
            "D41D8CD98F00B204E9800998ECF8427E"
        )

        assert result.hash_type == HashType.MD5
        assert result.valid is True
        assert result.value == (
            "d41d8cd98f00b204e9800998ecf8427e"
        )

    def test_invalid_hexadecimal_hash(self) -> None:
        """Test invalid hexadecimal characters."""
        result = self.analyzer.analyze(
            "g41d8cd98f00b204e9800998ecf8427e"
        )

        assert result.hash_type == HashType.UNKNOWN
        assert result.valid is False
        assert result.algorithm == "unknown"
        assert result.metadata["hexadecimal"] is False

    def test_invalid_hash_length(self) -> None:
        """Test unsupported hash length."""
        result = self.analyzer.analyze(
            "1234567890"
        )

        assert result.hash_type == HashType.UNKNOWN
        assert result.valid is False
        assert result.algorithm == "unknown"

    def test_empty_hash(self) -> None:
        """Test empty input."""
        result = self.analyzer.analyze("")

        assert result.hash_type == HashType.UNKNOWN
        assert result.length == 0
        assert result.valid is False
        assert result.algorithm == "unknown"
        assert result.metadata["hexadecimal"] is False

    def test_whitespace_hash(self) -> None:
        """Test whitespace input."""
        result = self.analyzer.analyze("   ")

        assert result.hash_type == HashType.UNKNOWN
        assert result.length == 0
        assert result.valid is False

    def test_result_to_dict(self) -> None:
        """Test HashResult serialization."""
        result = self.analyzer.analyze(
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        data = result.to_dict()

        assert data["value"] == (
            "d41d8cd98f00b204e9800998ecf8427e"
        )
        assert data["type"] == "md5"
        assert data["length"] == 32
        assert data["valid"] is True
        assert data["algorithm"] == "md5"

    def test_convenience_function(self) -> None:
        """Test the analyze_hash convenience function."""
        result = analyze_hash(
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        assert result.hash_type == HashType.MD5
        assert result.valid is True
