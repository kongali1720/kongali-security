"""Contract tests for the Kongali Security TLS analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from kongali_security.analysis.tls import (
    _parse_certificate_date,
    _parse_target,
    analyze_tls,
)


def make_certificate(
    *,
    days_remaining: int = 365,
) -> dict:
    """Build a deterministic TLS certificate dictionary."""

    now = datetime.now(timezone.utc)

    not_before = (
        now - timedelta(days=30)
    ).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )

    not_after = (
        now + timedelta(days=days_remaining)
    ).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )

    return {
        "subject": (
            (
                (
                    ("commonName", "example.com"),
                ),
            ),
        ),
        "issuer": (
            (
                (
                    ("commonName", "Test CA"),
                ),
            ),
        ),
        "serialNumber": "TEST-123456",
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": (
            ("DNS", "example.com"),
        ),
    }


def make_tls_socket(
    *,
    version: str = "TLSv1.3",
    cipher_name: str = "TLS_AES_256_GCM_SHA384",
    cipher_protocol: str = "TLSv1.3",
    cipher_bits: int = 256,
    days_remaining: int = 365,
) -> MagicMock:
    """Create a deterministic mocked TLS socket."""

    tls_socket = MagicMock()

    tls_socket.version.return_value = version

    tls_socket.cipher.return_value = (
        cipher_name,
        cipher_protocol,
        cipher_bits,
    )

    tls_socket.getpeercert.return_value = (
        make_certificate(
            days_remaining=days_remaining,
        )
    )

    return tls_socket


def run_mocked_tls(
    tls_socket: MagicMock,
    *,
    target: str = "https://example.com",
) -> dict:
    """Run analyze_tls with network and TLS context mocked."""

    mock_context = MagicMock()

    mock_context.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    with patch(
        "kongali_security.analysis.tls.socket.create_connection"
    ) as create_connection, patch(
        "kongali_security.analysis.tls.ssl.create_default_context"
    ) as create_default_context:

        create_connection.return_value.__enter__.return_value = (
            MagicMock()
        )

        create_default_context.return_value = (
            mock_context
        )

        return analyze_tls(target)


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------


def test_parse_target_https_defaults_to_port_443() -> None:
    """HTTPS targets without ports must default to 443."""

    hostname, port = _parse_target(
        "https://example.com"
    )

    assert hostname == "example.com"
    assert port == 443


def test_parse_target_http_defaults_to_port_443() -> None:
    """HTTP-style input still uses the TLS analyzer default port."""

    hostname, port = _parse_target(
        "http://example.com"
    )

    assert hostname == "example.com"
    assert port == 443


def test_parse_target_accepts_explicit_port() -> None:
    """Explicit TLS ports must be preserved."""

    hostname, port = _parse_target(
        "example.com:8443"
    )

    assert hostname == "example.com"
    assert port == 8443


def test_parse_target_strips_path() -> None:
    """URL paths must not become part of the hostname."""

    hostname, port = _parse_target(
        "https://example.com/security/login"
    )

    assert hostname == "example.com"
    assert port == 443


# ---------------------------------------------------------------------------
# Certificate date parsing
# ---------------------------------------------------------------------------


def test_parse_certificate_date_returns_utc_datetime() -> None:
    """OpenSSL certificate dates must become timezone-aware UTC values."""

    result = _parse_certificate_date(
        "Jan 01 00:00:00 2030 GMT"
    )

    assert isinstance(
        result,
        datetime,
    )

    assert result.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Secure TLS connection contract
# ---------------------------------------------------------------------------


def test_secure_tls_result_contains_expected_top_level_keys() -> None:
    """TLS analysis must expose the stable result structure."""

    result = run_mocked_tls(
        make_tls_socket()
    )

    assert "target" in result
    assert "hostname" in result
    assert "port" in result
    assert "tls" in result
    assert "findings" in result


def test_secure_tls_connection_reports_secure_status() -> None:
    """Modern TLS connections must report secure_connection."""

    result = run_mocked_tls(
        make_tls_socket()
    )

    assert (
        result["tls"]["status"]
        == "secure_connection"
    )


def test_secure_tls_connection_reports_tls_version() -> None:
    """Negotiated TLS version must be preserved."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1.3"
        )
    )

    assert (
        result["tls"]["version"]
        == "TLSv1.3"
    )


def test_secure_tls_connection_reports_cipher_metadata() -> None:
    """Cipher metadata must be exposed in the result."""

    result = run_mocked_tls(
        make_tls_socket(
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_protocol="TLSv1.3",
            cipher_bits=256,
        )
    )

    cipher = result["tls"]["cipher"]

    assert (
        cipher["name"]
        == "TLS_AES_256_GCM_SHA384"
    )

    assert (
        cipher["protocol"]
        == "TLSv1.3"
    )

    assert cipher["bits"] == 256


def test_secure_tls_connection_reports_certificate_metadata() -> None:
    """Certificate metadata must be included."""

    result = run_mocked_tls(
        make_tls_socket()
    )

    certificate = (
        result["tls"]["certificate"]
    )

    assert (
        certificate["serial_number"]
        == "TEST-123456"
    )

    assert (
        certificate["not_after"]
    )

    assert (
        certificate["days_remaining"]
        is not None
    )


def test_modern_tls_has_no_weak_protocol_finding() -> None:
    """TLS 1.2+ must not trigger TLS-001."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1.3"
        )
    )

    ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert (
        "KONGALI-TLS-001"
        not in ids
    )


def test_strong_cipher_has_no_weak_cipher_finding() -> None:
    """Strong cipher strength must not trigger TLS-002."""

    result = run_mocked_tls(
        make_tls_socket(
            cipher_bits=256
        )
    )

    ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert (
        "KONGALI-TLS-002"
        not in ids
    )


# ---------------------------------------------------------------------------
# TLS-001 Weak Protocol
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version",
    [
        "TLSv1",
        "TLSv1.1",
        "SSLv2",
        "SSLv3",
    ],
)
def test_weak_tls_protocol_generates_tls_001(
    version: str,
) -> None:
    """Obsolete TLS protocols must generate TLS-001."""

    result = run_mocked_tls(
        make_tls_socket(
            version=version
        )
    )

    finding = next(
        finding
        for finding in result["findings"]
        if finding["id"]
        == "KONGALI-TLS-001"
    )

    assert (
        finding["title"]
        == "Weak TLS Protocol"
    )

    assert (
        finding["severity"]
        == "HIGH"
    )

    assert (
        finding["category"]
        == "TLS Configuration"
    )

    assert (
        finding["evidence"]["tls_version"]
        == version
    )


# ---------------------------------------------------------------------------
# TLS-002 Weak Cipher
# ---------------------------------------------------------------------------


def test_weak_cipher_generates_tls_002() -> None:
    """Cipher strength below 128 bits must generate TLS-002."""

    result = run_mocked_tls(
        make_tls_socket(
            cipher_bits=64
        )
    )

    finding = next(
        finding
        for finding in result["findings"]
        if finding["id"]
        == "KONGALI-TLS-002"
    )

    assert (
        finding["title"]
        == "Weak TLS Cipher Strength"
    )

    assert (
        finding["severity"]
        == "HIGH"
    )

    assert (
        finding["cvss"]["score"]
        == 7.5
    )

    assert (
        finding["evidence"]["cipher"]["bits"]
        == 64
    )


def test_128_bit_cipher_does_not_trigger_tls_002() -> None:
    """128-bit cipher strength is the minimum accepted threshold."""

    result = run_mocked_tls(
        make_tls_socket(
            cipher_bits=128
        )
    )

    ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert (
        "KONGALI-TLS-002"
        not in ids
    )


# ---------------------------------------------------------------------------
# TLS-003 Certificate Expiry
# ---------------------------------------------------------------------------


def test_certificate_expiring_in_less_than_seven_days_is_high() -> None:
    """Certificates expiring within seven days must be HIGH."""

    result = run_mocked_tls(
        make_tls_socket(
            days_remaining=3
        )
    )

    finding = next(
        finding
        for finding in result["findings"]
        if finding["id"]
        == "KONGALI-TLS-003"
    )

    assert (
        finding["severity"]
        == "HIGH"
    )

    assert (
        finding["cvss"]["score"]
        == 7.4
    )


def test_certificate_expiring_within_thirty_days_is_medium() -> None:
    """Certificates expiring within 30 days must be MEDIUM."""

    result = run_mocked_tls(
        make_tls_socket(
            days_remaining=15
        )
    )

    finding = next(
        finding
        for finding in result["findings"]
        if finding["id"]
        == "KONGALI-TLS-003"
    )

    assert (
        finding["severity"]
        == "MEDIUM"
    )

    assert (
        finding["cvss"]["score"]
        == 5.3
    )


def test_certificate_with_more_than_thirty_days_has_no_tls_003() -> None:
    """Healthy certificate lifetime must not trigger TLS-003."""

    result = run_mocked_tls(
        make_tls_socket(
            days_remaining=365
        )
    )

    ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert (
        "KONGALI-TLS-003"
        not in ids
    )


# ---------------------------------------------------------------------------
# Finding schema contract
# ---------------------------------------------------------------------------


def test_tls_findings_contain_required_contract_fields() -> None:
    """Every TLS finding must contain the unified finding fields."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1",
            cipher_bits=64,
            days_remaining=3,
        )
    )

    required_fields = {
        "id",
        "title",
        "severity",
        "category",
        "description",
        "owasp",
        "cwe",
        "cvss",
        "impact",
        "remediation",
        "evidence",
        "references",
        "metadata",
    }

    assert result["findings"]

    for finding in result["findings"]:
        assert required_fields.issubset(
            finding.keys()
        )


def test_tls_findings_have_tls_configuration_category() -> None:
    """All TLS findings must use the unified TLS category."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1",
            cipher_bits=64,
            days_remaining=3,
        )
    )

    assert result["findings"]

    assert all(
        finding["category"]
        == "TLS Configuration"
        for finding in result["findings"]
    )


def test_tls_findings_have_scanner_metadata() -> None:
    """TLS findings must identify the TLS analyzer."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1",
            cipher_bits=64,
            days_remaining=3,
        )
    )

    assert result["findings"]

    assert all(
        finding["metadata"]["scanner"]
        == "tls"
        for finding in result["findings"]
    )


def test_all_three_tls_conditions_can_be_detected_together() -> None:
    """Multiple TLS weaknesses must be reported independently."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1",
            cipher_bits=64,
            days_remaining=3,
        )
    )

    ids = {
        finding["id"]
        for finding in result["findings"]
    }

    assert (
        "KONGALI-TLS-001"
        in ids
    )

    assert (
        "KONGALI-TLS-002"
        in ids
    )

    assert (
        "KONGALI-TLS-003"
        in ids
    )


def test_secure_tls_configuration_returns_empty_findings() -> None:
    """A modern TLS configuration must return no findings."""

    result = run_mocked_tls(
        make_tls_socket(
            version="TLSv1.3",
            cipher_bits=256,
            days_remaining=365,
        )
    )

    assert result["findings"] == []
