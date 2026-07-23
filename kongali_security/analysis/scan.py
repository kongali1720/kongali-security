"""Full security scan orchestration module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kongali_security.analysis.dns import analyze_dns
from kongali_security.analysis.headers import analyze_headers
from kongali_security.analysis.url import analyze_url
from kongali_security.analysis.whois import analyze_whois

from kongali_security.analysis.ip import analyze_ip

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
MODULE_VERSION = "1.0.0"


@dataclass
class ScanResult:
    """Combined security scan result."""

    target: str
    url: Any
    dns: Any
    ip: Any
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


    def to_dict(
        self,
    ) -> dict[str, Any]:
        """Convert result into dictionary."""

        def serialize(
            value: Any,
        ) -> Any:

            if hasattr(
                value,
                "to_dict",
            ):
                return value.to_dict()

            if hasattr(
                value,
                "__dict__",
            ):
                return dict(
                    value.__dict__
                )

            return value


        return {
            "target": self.target,
            "url": serialize(self.url),
            "dns": serialize(self.dns),
            "ip": serialize(self.ip),
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
    """
    Run complete defensive security pipeline.
    """


    if not target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        target = "https://" + target


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


    # IP Intelligence Integration

    ip_result = {
        "ips": [],
        "analysis": [],
    }


    resolved_ips = []

    if hasattr(
        dns_result,
        "ipv4",
    ):
        resolved_ips = dns_result.ipv4

    elif isinstance(
        dns_result,
        dict,
    ):
        resolved_ips = dns_result.get(
            "ipv4",
            [],
        )


    for address in resolved_ips:

        ip_result["ips"].append(
            address
        )

        ip_result["analysis"].append(
            analyze_ip(
                address
            )
        )


    whois_result = analyze_whois(
        hostname
    )


    headers_result = analyze_headers(
        url_result.value
    )


    methods_result = analyze_methods(
        url_result.value
    )


    redirect_result = analyze_redirect(
        url_result.value
    )


    robots_result = analyze_robots(
        url_result.value
    )


    securitytxt_result = analyze_securitytxt(
        url_result.value
    )


    cookies_result = analyze_cookies(
        url_result.value
    )


    cors_result = analyze_cors(
        url_result.value
    )


    csp_result = analyze_csp(
        url_result.value
    )


    tech_result = analyze_tech(
        url_result.value
    )


    waf_result = analyze_waf(
        url_result.value
    )


    return ScanResult(
        target=url_result.value,
        url=url_result,
        dns=dns_result,
        ip=ip_result,
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
