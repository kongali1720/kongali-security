"""TLS/SSL security analysis module for Kongali Security."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import urlparse


MODULE_NAME = "tls_security"
MODULE_VERSION = "0.1.0"


def _parse_target(target: str) -> tuple[str, int]:
    """Parse a target URL into hostname and port."""

    parsed = urlparse(target)

    if parsed.scheme and parsed.hostname:
        hostname = parsed.hostname
        port = parsed.port or 443
        return hostname, port

    hostname = target
    return hostname, 443


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


def analyze_tls(
    target: str,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Perform a defensive TLS security assessment."""

    hostname, port = _parse_target(target)

    result: Dict[str, Any] = {
        "target": target,
        "hostname": hostname,
        "port": port,
        "tls": {
            "status": "unknown",
            "version": None,
            "cipher": None,
            "certificate": {},
            "findings": [],
        },
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                tls_version = tls_socket.version()
                cipher = tls_socket.cipher()

                not_before = certificate.get(
                    "notBefore",
                )

                not_after = certificate.get(
                    "notAfter",
                )

                certificate_data = {
                    "subject": certificate.get(
                        "subject",
                    ),
                    "issuer": certificate.get(
                        "issuer",
                    ),
                    "serial_number": certificate.get(
                        "serialNumber",
                    ),
                    "not_before": not_before,
                    "not_after": not_after,
                    "subject_alt_name": certificate.get(
                        "subjectAltName",
                    ),
                }

                result["tls"].update(
                    {
                        "status": "secure_connection",
                        "version": tls_version,
                        "cipher": {
                            "name": cipher[0]
                            if cipher
                            else None,
                            "protocol": cipher[1]
                            if cipher
                            else None,
                            "bits": cipher[2]
                            if cipher
                            else None,
                        },
                        "certificate": certificate_data,
                    }
                )

                findings = []

                if tls_version in {
                    "TLSv1",
                    "TLSv1.1",
                }:
                    findings.append(
                        {
                            "severity": "HIGH",
                            "category": "TLS Configuration",
                            "title": (
                                f"Weak TLS protocol version: "
                                f"{tls_version}"
                            ),
                            "description": (
                                "The server negotiated an outdated "
                                "TLS protocol version."
                            ),
                            "evidence": {
                                "tls_version": tls_version,
                            },
                        }
                    )

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

                        result["tls"][
                            "certificate"
                        ][
                            "days_remaining"
                        ] = days_remaining

                        if days_remaining < 0:
                            findings.append(
                                {
                                    "severity": "CRITICAL",
                                    "category": (
                                        "TLS Certificate"
                                    ),
                                    "title": (
                                        "TLS certificate expired"
                                    ),
                                    "description": (
                                        "The TLS certificate "
                                        "has expired."
                                    ),
                                    "evidence": {
                                        "not_after": (
                                            not_after
                                        ),
                                        "days_remaining": (
                                            days_remaining
                                        ),
                                    },
                                }
                            )

                        elif days_remaining <= 30:
                            findings.append(
                                {
                                    "severity": "HIGH",
                                    "category": (
                                        "TLS Certificate"
                                    ),
                                    "title": (
                                        "TLS certificate "
                                        "expires soon"
                                    ),
                                    "description": (
                                        "The TLS certificate "
                                        "expires within "
                                        "30 days."
                                    ),
                                    "evidence": {
                                        "not_after": (
                                            not_after
                                        ),
                                        "days_remaining": (
                                            days_remaining
                                        ),
                                    },
                                }
                            )

                    except ValueError:
                        pass

                result["tls"][
                    "findings"
                ] = findings

                return result

    except ssl.SSLCertVerificationError as exc:
        result["tls"].update(
            {
                "status": "certificate_verification_failed",
                "findings": [
                    {
                        "severity": "HIGH",
                        "category": "TLS Certificate",
                        "title": (
                            "TLS certificate verification failed"
                        ),
                        "description": (
                            "The server certificate could not "
                            "be verified by the trusted CA store."
                        ),
                        "evidence": {
                            "error": str(exc),
                        },
                    }
                ],
            }
        )

        return result

    except (
        socket.timeout,
        TimeoutError,
    ) as exc:

        result["tls"].update(
            {
                "status": "timeout",
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "category": "TLS Connectivity",
                        "title": "TLS connection timeout",
                        "description": (
                            "The TLS connection attempt "
                            "timed out."
                        ),
                        "evidence": {
                            "error": str(exc),
                        },
                    }
                ],
            }
        )

        return result

    except OSError as exc:

        result["tls"].update(
            {
                "status": "connection_failed",
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "category": "TLS Connectivity",
                        "title": "TLS connection failed",
                        "description": (
                            "The target could not be reached "
                            "over TLS."
                        ),
                        "evidence": {
                            "error": str(exc),
                        },
                    }
                ],
            }
        )

        return result
