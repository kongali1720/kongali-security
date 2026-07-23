"""Full security scan orchestration module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kongali_security.analysis.dns import analyze_dns
from kongali_security.analysis.headers import analyze_headers
from kongali_security.analysis.url import analyze_url
from kongali_security.analysis.whois import analyze_whois

from kongali_security.analysis.methods import analyze_methods
from kongali_security.analysis.redirect import analyze_redirect
from kongali_security.analysis.robots import analyze_robots
from kongali_security.analysis.securitytxt import analyze_securitytxt
from kongali_security.analysis.cookies import analyze_cookies
from kongali_security.analysis.cors import analyze_cors
from kongali_security.analysis.csp import analyze_csp
from kongali_security.analysis.tech import analyze_tech
from kongali_security.analysis.waf import analyze_waf


MODULE_NAME = "security_scanner"
MODULE_VERSION = "0.2.0"


@dataclass
class ScanResult:
    """Combined result produced by the security scanner."""

    target: str
    url: Any
    dns: Any
    whois: Any
    headers: Any
    methods: Any
    redirect: Any
    robots: Any
    securitytxt: Any
    cookies: Any
    cors: Any
    csp: Any
    tech: Any
    waf: Any

    def to_dict(self) -> dict[str, Any]:
        """Convert the scan result to dictionary."""

        def serialize(value: Any) -> Any:
            if hasattr(value, "to_dict"):
                return value.to_dict()

            if hasattr(value, "__dict__"):
                return dict(value.__dict__)

            if isinstance(value, dict):
                return value

            return value

        return {
            "target": self.target,
            "url": serialize(self.url),
            "dns": serialize(self.dns),
            "whois": serialize(self.whois),
            "headers": serialize(self.headers),
            "methods": serialize(self.methods),
            "redirect": serialize(self.redirect),
            "robots": serialize(self.robots),
            "securitytxt": serialize(self.securitytxt),
            "cookies": serialize(self.cookies),
            "cors": serialize(self.cors),
            "csp": serialize(self.csp),
            "tech": serialize(self.tech),
            "waf": serialize(self.waf),
        }


def analyze_scan(
    target: str,
) -> ScanResult:
    """Run the full defensive security analysis pipeline."""

    url_result = analyze_url(
        target
    )

    hostname = getattr(
        url_result,
        "hostname",
        None,
    )

    if not hostname:
        raise ValueError(
            "Target must be a valid URL with a hostname."
        )

    dns_result = analyze_dns(
        hostname
    )

    whois_result = analyze_whois(
        hostname
    )

    headers_result = analyze_headers(
        target
    )

    methods_result = analyze_methods(
        target
    )

    redirect_result = analyze_redirect(
        target
    )

    robots_result = analyze_robots(
        target
    )

    securitytxt_result = analyze_securitytxt(
        target
    )

    cookies_result = analyze_cookies(
        target
    )

    cors_result = analyze_cors(
        target
    )

    csp_result = analyze_csp(
        target
    )

    tech_result = analyze_tech(
        target
    )

    waf_result = analyze_waf(
        target
    )

    return ScanResult(
        target=target,
        url=url_result,
        dns=dns_result,
        whois=whois_result,
        headers=headers_result,
        methods=methods_result,
        redirect=redirect_result,
        robots=robots_result,
        securitytxt=securitytxt_result,
        cookies=cookies_result,
        cors=cors_result,
        csp=csp_result,
        tech=tech_result,
        waf=waf_result,
    )
