"""
Network connection intelligence analyzer.

Defensive network visibility module.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class NetworkConnection:
    local: str
    remote: str
    state: str


@dataclass
class NetstatResult:
    connections: list[NetworkConnection]
    findings: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:

        return {
            "connections": [
                {
                    "local": c.local,
                    "remote": c.remote,
                    "state": c.state,
                }
                for c in self.connections
            ],
            "findings": self.findings,
        }


def analyze_netstat() -> NetstatResult:
    """
    Analyze active network connections.
    """

    connections = []
    findings = []


    try:

        output = subprocess.check_output(
            [
                "ss",
                "-tunap",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        )


    except Exception:

        return NetstatResult(
            connections=[],
            findings=[
                {
                    "severity": "INFO",
                    "title": "Network socket information unavailable",
                }
            ],
        )


    lines = output.splitlines()


    for line in lines[1:]:

        parts = line.split()


        if len(parts) >= 5:

            connection = NetworkConnection(
                local=parts[4],
                remote=parts[5] if len(parts) > 5 else "",
                state=parts[1],
            )

            connections.append(
                connection
            )


    if len(connections) > 100:

        findings.append(
            {
                "severity": "MEDIUM",
                "title": "Large number of active connections detected",
                "count": len(connections),
            }
        )


    return NetstatResult(
        connections=connections,
        findings=findings,
    )
