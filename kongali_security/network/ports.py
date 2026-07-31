"""
Remote port intelligence analyzer.

Defensive network visibility module.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
}


@dataclass
class PortFinding:

    port: int
    service: str
    state: str


@dataclass
class PortScanResult:

    target: str
    findings: list[PortFinding]


    def to_dict(self) -> dict[str, Any]:

        return {
            "target": self.target,
            "ports": [
                {
                    "port": item.port,
                    "service": item.service,
                    "state": item.state,
                }
                for item in self.findings
            ],
        }



def analyze_ports(
    target: str,
) -> PortScanResult:

    findings = []

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(1)

        result = sock.connect_ex(
            (
                target,
                port,
            )
        )

        sock.close()


        if result == 0:

            findings.append(
                PortFinding(
                    port=port,
                    service=service,
                    state="OPEN",
                )
            )


    return PortScanResult(
        target=target,
        findings=findings,
    )
