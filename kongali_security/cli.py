"""Command-line interface for Kongali Security."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from kongali_security.analysis.audit import analyze_audit
from kongali_security.analysis.compare import compare_reports, load_json
from kongali_security.analysis.baseline import (
    create_baseline,
    save_baseline,
)
from kongali_security.analysis.dns import analyze_dns
from kongali_security.analysis.hash import analyze_hash
from kongali_security.analysis.headers import analyze_headers
from kongali_security.analysis.ioc import analyze_ioc
from kongali_security.analysis.report import (
    generate_report,
    render_html,
    render_markdown,
    render_sarif,
    save_report,
)
from kongali_security.analysis.scan import analyze_scan
from kongali_security.analysis.url import analyze_url
from kongali_security.analysis.whois import analyze_whois


VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    """Build the Kongali Security CLI parser."""

    parser = argparse.ArgumentParser(
        prog="kongali-security",
        description=(
            "Kongali Security - Defensive Security "
            "Automation Framework"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
    )

    # IOC
    ioc_parser = subparsers.add_parser(
        "ioc",
        help="Analyze an Indicator of Compromise (IOC).",
    )

    ioc_parser.add_argument(
        "input",
        help="IOC value to analyze.",
    )

    ioc_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # Hash
    hash_parser = subparsers.add_parser(
        "hash",
        help="Analyze a cryptographic hash.",
    )

    hash_parser.add_argument(
        "input",
        help="Cryptographic hash value to analyze.",
    )

    hash_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # DNS
    dns_parser = subparsers.add_parser(
        "dns",
        help="Perform defensive DNS analysis.",
    )

    dns_parser.add_argument(
        "domain",
        help="Domain name to analyze.",
    )

    dns_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # WHOIS
    whois_parser = subparsers.add_parser(
        "whois",
        help="Perform defensive WHOIS analysis.",
    )

    whois_parser.add_argument(
        "domain",
        help="Domain name to query.",
    )

    whois_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # URL
    url_parser = subparsers.add_parser(
        "url",
        help="Analyze and validate a URL.",
    )

    url_parser.add_argument(
        "url",
        help="URL to analyze.",
    )

    url_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # HTTP Headers
    headers_parser = subparsers.add_parser(
        "headers",
        help="Analyze HTTP security headers.",
    )

    headers_parser.add_argument(
        "url",
        help="HTTP or HTTPS URL to analyze.",
    )

    headers_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # Full Scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a full defensive security scan.",
    )

    scan_parser.add_argument(
        "target",
        help="Target URL to scan.",
    )

    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )

    # Security Audit
    audit_parser = subparsers.add_parser(
        "audit",
        help="Run a complete security assessment.",
    )

    audit_parser.add_argument(
        "target",
        help="Target URL to assess.",
    )

    audit_parser.add_argument(
        "--format",
        choices=(
            "text",
            "json",
        ),
        default="text",
        help="Audit output format.",
    )

    # Security Baseline
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Create a security baseline.",
    )

    baseline_parser.add_argument(
        "target",
        help="Target URL to baseline.",
    )

    baseline_parser.add_argument(
        "--output",
        default="baseline.json",
        help="Output baseline JSON file.",
    )

    # Security Report
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a complete security assessment report.",
    )

    report_parser.add_argument(
        "target",
        help="Target URL to assess.",
    )

    report_parser.add_argument(
        "--format",
        choices=(
            "text",
            "json",
            "markdown",
            "html",
            "sarif",
        ),
        default="text",
        help="Report output format.",
    )

    report_parser.add_argument(
        "--output",
        help="Write the report to a file.",
    )

    # Compare Security Reports
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare a security baseline with a current report.",
    )

    compare_parser.add_argument(
        "baseline",
        help="Baseline JSON file.",
    )

    compare_parser.add_argument(
        "current",
        help="Current security report JSON file.",
    )

    compare_parser.add_argument(
        "--format",
        choices=(
            "text",
            "json",
        ),
        default="text",
        help="Comparison output format.",
    )

    # Export Report
    export_parser = subparsers.add_parser(
        "export",
        help="Convert an existing security report.",
    )

    export_parser.add_argument(
        "input",
        help="Input report file, currently JSON format.",
    )

    export_parser.add_argument(
        "--format",
        choices=(
            "text",
            "json",
            "markdown",
            "html",
        ),
        required=True,
        help="Output report format.",
    )

    export_parser.add_argument(
        "--output",
        required=True,
        help="Output file path.",
    )

    return parser


def _result_to_dict(
    result: Any,
) -> dict[str, Any]:
    """Convert an analysis result into a dictionary."""

    if hasattr(
        result,
        "to_dict",
    ):
        data = result.to_dict()

        if isinstance(
            data,
            dict,
        ):
            return data

    if isinstance(
        result,
        dict,
    ):
        return result

    if hasattr(
        result,
        "__dict__",
    ):
        return dict(
            result.__dict__
        )

    return {
        "result": str(result)
    }


def _print_result(
    result: Any,
    output_format: str,
    title: str,
) -> None:
    """Print an analysis result."""

    data = _result_to_dict(
        result
    )

    if output_format == "json":
        print(
            json.dumps(
                data,
                indent=2,
                default=str,
            )
        )
        return

    print(title)
    print(
        "─────────────────────────────"
    )

    for key, value in data.items():
        label = key.replace(
            "_",
            " ",
        ).title()

        print(
            f"{label:<18}: {value}"
        )


def _run_standard_analysis(
    analyzer: Any,
    value: str,
    output_format: str,
    title: str,
    error_name: str,
) -> int:
    """Run a standard analyzer."""

    try:
        result = analyzer(
            value
        )

        _print_result(
            result,
            output_format,
            title,
        )

        return 0

    except Exception as exc:
        print(
            f"Error: {error_name} analysis failed: {exc}",
            file=sys.stderr,
        )

        return 1


def _build_text_report(
    report: dict[str, Any],
) -> str:
    """Build a plain-text security report."""

    lines = [
        "Kongali Security Security Report",
        "─────────────────────────────",
    ]

    for key, value in report.items():
        label = key.replace(
            "_",
            " ",
        ).title()

        lines.append(
            f"{label:<18}: {value}"
        )

    return "\n".join(lines) + "\n"


def _write_output(
    output: str,
    output_path: str,
) -> None:
    """Write generated output to a file."""

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            output
        )


def main() -> int:
    """Run the Kongali Security CLI."""

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    # IOC
    if args.command == "ioc":
        return _run_standard_analysis(
            analyze_ioc,
            args.input,
            args.format,
            "Kongali Security IOC Analyzer",
            "IOC",
        )

    # Hash
    if args.command == "hash":
        return _run_standard_analysis(
            analyze_hash,
            args.input,
            args.format,
            "Kongali Security Hash Analyzer",
            "Hash",
        )

    # DNS
    if args.command == "dns":
        return _run_standard_analysis(
            analyze_dns,
            args.domain,
            args.format,
            "Kongali Security DNS Analyzer",
            "DNS",
        )

    # WHOIS
    if args.command == "whois":
        return _run_standard_analysis(
            analyze_whois,
            args.domain,
            args.format,
            "Kongali Security WHOIS Analyzer",
            "WHOIS",
        )

    # URL
    if args.command == "url":
        return _run_standard_analysis(
            analyze_url,
            args.url,
            args.format,
            "Kongali Security URL Analyzer",
            "URL",
        )

    # HTTP Headers
    if args.command == "headers":
        return _run_standard_analysis(
            analyze_headers,
            args.url,
            args.format,
            "Kongali Security HTTP Headers Analyzer",
            "HTTP headers",
        )

    # Full Scan
    if args.command == "scan":
        return _run_standard_analysis(
            analyze_scan,
            args.target,
            args.format,
            "Kongali Security Full Scan",
            "Full scan",
        )

    # Security Compare
    if args.command == "compare":
        try:
            baseline = load_json(
                args.baseline
            )

            current = load_json(
                args.current
            )

            comparison = compare_reports(
                baseline,
                current,
            )

            if args.format == "json":
                print(
                    json.dumps(
                        comparison,
                        indent=2,
                        default=str,
                    )
                )
            else:
                print(
                    "Kongali Security Baseline Comparison"
                )
                print(
                    "─────────────────────────────"
                )

                if isinstance(
                    comparison,
                    dict,
                ):
                    for key, value in comparison.items():
                        label = key.replace(
                            "_",
                            " ",
                        ).title()

                        print(
                            f"{label:<18}: {value}"
                        )
                else:
                    print(
                        comparison
                    )

            return 0

        except Exception as exc:
            print(
                f"Error: Security comparison failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # Export Report
    if args.command == "export":
        try:
            with open(
                args.input,
                "r",
                encoding="utf-8",
            ) as file:
                report = json.load(file)

            if args.format == "json":
                output = json.dumps(
                    report,
                    indent=2,
                    default=str,
                )

                with open(
                    args.output,
                    "w",
                    encoding="utf-8",
                ) as file:
                    file.write(output)

            elif args.format == "markdown":
                output = render_markdown(report)

                with open(
                    args.output,
                    "w",
                    encoding="utf-8",
                ) as file:
                    file.write(output)

            elif args.format == "html":
                output = render_html(report)

                with open(
                    args.output,
                    "w",
                    encoding="utf-8",
                ) as file:
                    file.write(output)

            elif args.format == "text":
                lines = []

                lines.append(
                    "Kongali Security Security Report"
                )
                lines.append(
                    "─────────────────────────────"
                )

                for key, value in report.items():
                    label = key.replace(
                        "_",
                        " ",
                    ).title()

                    lines.append(
                        f"{label:<18}: {value}"
                    )

                output = "\n".join(lines) + "\n"

                with open(
                    args.output,
                    "w",
                    encoding="utf-8",
                ) as file:
                    file.write(output)

            print(
                f"Report exported to: {args.output}"
            )

            return 0

        except Exception as exc:
            print(
                f"Error: Report export failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # Security Audit
    if args.command == "audit":
        try:
            result = analyze_audit(
                args.target
            )

            _print_result(
                result,
                args.format,
                "Kongali Security Security Audit",
            )

            return 0

        except Exception as exc:
            print(
                f"Error: Security audit failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # Security Baseline
    if args.command == "baseline":
        try:
            baseline = create_baseline(
                args.target
            )

            save_baseline(
                baseline,
                args.output,
            )

            print(
                "Kongali Security Baseline"
            )
            print(
                "─────────────────────────────"
            )
            print(
                f"Target       : {args.target}"
            )
            print(
                f"Risk         : "
                f"{baseline['overall_risk']}"
            )
            print(
                f"Score        : "
                f"{baseline['overall_score']}"
            )
            print(
                f"Findings     : "
                f"{len(baseline['findings'])}"
            )
            print(
                f"Baseline     : "
                f"{args.output}"
            )

            return 0

        except Exception as exc:
            print(
                f"Error: Baseline creation failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # Security Report
    if args.command == "report":
        try:
            scan_result = analyze_scan(
                args.target
            )

            report = generate_report(
                scan_result
            )

            if args.format == "json":
                output = json.dumps(
                    report,
                    indent=2,
                    default=str,
                )

            elif args.format == "markdown":
                output = render_markdown(
                    report
                )

            elif args.format == "html":
                output = render_html(
                    report
                )

            elif args.format == "sarif":
                output = render_sarif(
                    report
                )

            else:
                output = _build_text_report(
                    report
                )

            if args.output:
                if args.format in (
                    "markdown",
                    "html",
                ):
                    save_report(
                        report,
                        args.format,
                        args.output,
                    )
                else:
                    _write_output(
                        output,
                        args.output,
                    )

                print(
                    f"Report written to: "
                    f"{args.output}"
                )

            else:
                print(
                    output,
                    end=""
                    if output.endswith("\n")
                    else "\n",
                )

            return 0

        except Exception as exc:
            print(
                f"Error: Security report generation failed: {exc}",
                file=sys.stderr,
            )

            return 1

    parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
