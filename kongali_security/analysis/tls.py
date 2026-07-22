"""TLS security analysis module for Kongali Security."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from kongali_security.schemas.finding import (
    CVSSScore,
    CWEReference,
    OWASPReference,
    SecurityFinding,
)

TLS_OWASP = OWASPReference(
    id="A02:2021",
    name="Cryptographic Failures",
)

TLS_CWE = CWEReference(
    id="CWE-326",
    name="Inadequate Encryption Strength",
)


def _parse_target(target: str) -> tuple[str, int]:
    """Parse a TLS target into hostname and port."""

    target = target.strip()

    if "://" in target:
        target = target.split("://", 1)[1]

    target = target.split("/", 1)[0]

    if ":" in target:
        hostname, port = target.rsplit(":", 1)

        try:
            return hostname, int(port)
        except ValueError:
            pass

    return target, 443


def _parse_certificate_date(
    value: str,
) -> datetime:
    """Parse an OpenSSL certificate date."""

    return datetime.strptime(
        value,
        "%b %d %H:%M:%S %Y %Z",
    ).replace(
        tzinfo=timezone.utc,
    )


def _build_finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    impact: str,
    remediation: str,
    evidence: dict[str, Any],
    cvss_score: float,
    cvss_severity: str,
    cvss_vector: str,
    cwe: CWEReference = TLS_CWE,
    owasp: OWASPReference = TLS_OWASP,
) -> dict[str, Any]:
    """Build a unified security finding."""

    finding = SecurityFinding(
        id=finding_id,
        title=title,
        severity=severity,
        category="TLS Configuration",
        description=description,
        owasp=owasp,
        cwe=cwe,
        cvss=CVSSScore(
            version="3.1",
            score=cvss_score,
            severity=cvss_severity,
            vector=cvss_vector,
        ),
        impact=impact,
        remediation=remediation,
        evidence=evidence,
        references=[
            "https://owasp.org/www-project-top-ten/",
        ],
        metadata={
            "scanner": "tls",
        },
    )

    return finding.to_dict()


def analyze_tls(
    target: str,
) -> dict[str, Any]:
    """Analyze TLS configuration of a remote target."""

    hostname, port = _parse_target(target)

    result: dict[str, Any] = {
        "target": target,
        "hostname": hostname,
        "port": port,
        "tls": {},
        "findings": [],
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=10,
        ) as sock, context.wrap_socket(
            sock,
            server_hostname=hostname,
        ) as tls_socket:

            cipher = tls_socket.cipher()
            certificate = tls_socket.getpeercert()

            tls_version = (
                tls_socket.version()
                or "UNKNOWN"
            )

            certificate_data: dict[str, Any] = {}

            if certificate:
                subject = certificate.get(
                    "subject",
                    (),
                )

                issuer = certificate.get(
                    "issuer",
                    (),
                )

                serial_number = certificate.get(
                    "serialNumber",
                    "",
                )

                not_before = certificate.get(
                    "notBefore",
                    "",
                )

                not_after = certificate.get(
                    "notAfter",
                    "",
                )

                subject_alt_name = certificate.get(
                    "subjectAltName",
                    (),
                )

                days_remaining = None

                if not_after:
                    try:
                        expiry = _parse_certificate_date(
                            not_after,
                        )

                        now = datetime.now(
                            timezone.utc,
                        )

                        days_remaining = (
                            expiry - now
                        ).days

                    except ValueError:
                        days_remaining = None

                certificate_data = {
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": serial_number,
                    "not_before": not_before,
                    "not_after": not_after,
                    "subject_alt_name": subject_alt_name,
                    "days_remaining": days_remaining,
                }

            cipher_data = {
                "name": (
                    cipher[0]
                    if cipher
                    else None
                ),
                "protocol": (
                    cipher[1]
                    if cipher
                    else None
                ),
                "bits": (
                    cipher[2]
                    if cipher
                    else None
                ),
            }

            result["tls"] = {
                "status": "secure_connection",
                "version": tls_version,
                "cipher": cipher_data,
                "certificate": certificate_data,
            }

            findings: list[dict[str, Any]] = []

            # Weak TLS protocol detection.
            if tls_version in {
                "TLSv1",
                "TLSv1.1",
                "SSLv2",
                "SSLv3",
            }:
                findings.append(
                    _build_finding(
                        finding_id=(
                            "KONGALI-TLS-001"
                        ),
                        title=(
                            "Weak TLS Protocol"
                        ),
                        severity="HIGH",
                        description=(
                            "The server uses an "
                            "obsolete or weak TLS "
                            "protocol version."
                        ),
                        impact=(
                            "Weak cryptographic "
                            "protocols may expose "
                            "communications to "
                            "downgrade or "
                            "cryptographic attacks."
                        ),
                        remediation=(
                            "Disable obsolete TLS "
                            "protocol versions and "
                            "require TLS 1.2 or newer."
                        ),
                        evidence={
                            "tls_version": (
                                tls_version
                            ),
                            "hostname": hostname,
                            "port": port,
                        },
                        cvss_score=8.1,
                        cvss_severity="HIGH",
                        cvss_vector=(
                            "CVSS:3.1/"
                            "AV:N/"
                            "AC:L/"
                            "PR:N/"
                            "UI:N/"
                            "S:U/"
                            "C:H/"
                            "I:L/"
                            "A:N"
                        ),
                    )
                )

            # Weak cipher detection.
            cipher_bits = (
                cipher[2]
                if cipher
                else 0
            )

            if (
                isinstance(
                    cipher_bits,
                    int,
                )
                and cipher_bits < 128
            ):
                findings.append(
                    _build_finding(
                        finding_id=(
                            "KONGALI-TLS-002"
                        ),
                        title=(
                            "Weak TLS Cipher Strength"
                        ),
                        severity="HIGH",
                        description=(
                            "The TLS connection "
                            "uses a cipher with "
                            "insufficient key strength."
                        ),
                        impact=(
                            "Weak cipher strength "
                            "may reduce the "
                            "confidentiality of "
                            "encrypted communications."
                        ),
                        remediation=(
                            "Disable weak cipher "
                            "suites and require "
                            "modern ciphers with "
                            "at least 128-bit strength."
                        ),
                        evidence={
                            "cipher": cipher_data,
                            "hostname": hostname,
                            "port": port,
                        },
                        cvss_score=7.5,
                        cvss_severity="HIGH",
                        cvss_vector=(
                            "CVSS:3.1/"
                            "AV:N/"
                            "AC:L/"
                            "PR:N/"
                            "UI:N/"
                            "S:U/"
                            "C:H/"
                            "I:N/"
                            "A:N"
                        ),
                    )
                )

            # Certificate expiry detection.
            days_remaining = certificate_data.get(
                "days_remaining",
            )

            if (
                isinstance(
                    days_remaining,
                    int,
                )
                and days_remaining < 30
            ):
                severity = (
                    "HIGH"
                    if days_remaining < 7
                    else "MEDIUM"
                )

                cvss_score = (
                    7.4
                    if days_remaining < 7
                    else 5.3
                )

                findings.append(
                    _build_finding(
                        finding_id=(
                            "KONGALI-TLS-003"
                        ),
                        title=(
                            "TLS Certificate "
                            "Expiring Soon"
                        ),
                        severity=severity,
                        description=(
                            "The TLS certificate "
                            "is approaching its "
                            "expiration date."
                        ),
                        impact=(
                            "An expired certificate "
                            "may cause service "
                            "disruption and browser "
                            "trust warnings."
                        ),
                        remediation=(
                            "Renew the TLS "
                            "certificate before "
                            "expiration and ensure "
                            "automated certificate "
                            "renewal is configured."
                        ),
                        evidence={
                            "days_remaining": (
                                days_remaining
                            ),
                            "not_after": (
                                certificate_data.get(
                                    "not_after",
                                )
                            ),
                            "hostname": hostname,
                        },
                        cvss_score=cvss_score,
                        cvss_severity=severity,
                        cvss_vector=(
                            "CVSS:3.1/"
                            "AV:N/"
                            "AC:L/"
                            "PR:N/"
                            "UI:R/"
                            "S:U/"
                            "C:N/"
                            "I:H/"
                            "A:N"
                        ),
                    )
                )

            result["findings"] = findings

            return result

    except (TimeoutError, socket.gaierror, ConnectionError, ssl.SSLError, OSError) as exc:

        result["tls"] = {
            "status": "connection_error",
            "error": str(exc),
        }

        result["findings"] = [
            _build_finding(
                finding_id="KONGALI-TLS-004",
                title="TLS Connection Failure",
                severity="HIGH",
                description=(
                    "The target could not establish "
                    "a valid TLS connection."
                ),
                impact=(
                    "The inability to establish a "
                    "trusted TLS connection may expose "
                    "the service to availability or "
                    "transport security risks."
                ),
                remediation=(
                    "Verify TLS configuration, certificate "
                    "validity, hostname configuration, "
                    "and server availability."
                ),
                evidence={
                    "hostname": hostname,
                    "port": port,
                    "error": str(exc),
                },
                cvss_score=7.5,
                cvss_severity="HIGH",
                cvss_vector=(
                    "CVSS:3.1/"
                    "AV:N/"
                    "AC:L/"
                    "PR:N/"
                    "UI:N/"
                    "S:U/"
                    "C:N/"
                    "I:N/"
                    "A:H"
                ),
            )
        ]

        return result
