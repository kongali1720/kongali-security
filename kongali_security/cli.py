"""Command-line interface for Kongali Security."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from kongali_security.analysis.dns import analyze_dns
from kongali_security.analysis.hash import analyze_hash
from kongali_security.analysis.ioc import analyze_ioc


VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    """Build the Kongali Security command-line parser."""

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

    # ==========================================================
    # IOC COMMAND
    # ==========================================================

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
        help="Output format (default: text).",
    )

    # ==========================================================
    # HASH COMMAND
    # ==========================================================

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
        help="Output format (default: text).",
    )

    # ==========================================================
    # DNS COMMAND
    # ==========================================================

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
        help="Output format (default: text).",
    )

    return parser


def _result_to_dict(
    result: Any,
) -> dict[str, Any]:
    """Convert an analysis result to a dictionary."""

    if hasattr(result, "to_dict"):
        data = result.to_dict()

        if isinstance(data, dict):
            return data

    if isinstance(result, dict):
        return result

    if hasattr(result, "__dict__"):
        return dict(result.__dict__)

    return {
        "result": str(result),
    }


def _print_result(
    result: Any,
    output_format: str,
    title: str,
) -> None:
    """Print an analysis result."""

    data = _result_to_dict(result)

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
    print("─────────────────────────────")

    for key, value in data.items():
        label = key.replace(
            "_",
            " ",
        ).title()

        print(
            f"{label:<12}: {value}"
        )


def main() -> int:
    """Run the Kongali Security CLI."""

    parser = build_parser()
    args = parser.parse_args()

    # ==========================================================
    # NO COMMAND
    # ==========================================================

    if args.command is None:
        parser.print_help()
        return 0

    # ==========================================================
    # IOC ANALYSIS
    # ==========================================================

    if args.command == "ioc":
        try:
            result = analyze_ioc(
                args.input
            )

            _print_result(
                result,
                args.format,
                "Kongali Security IOC Analyzer",
            )

            return 0

        except Exception as exc:
            print(
                f"Error: IOC analysis failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # ==========================================================
    # HASH ANALYSIS
    # ==========================================================

    if args.command == "hash":
        try:
            result = analyze_hash(
                args.input
            )

            _print_result(
                result,
                args.format,
                "Kongali Security Hash Analyzer",
            )

            return 0

        except Exception as exc:
            print(
                f"Error: Hash analysis failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # ==========================================================
    # DNS ANALYSIS
    # ==========================================================

    if args.command == "dns":
        try:
            result = analyze_dns(
                args.domain
            )

            _print_result(
                result,
                args.format,
                "Kongali Security DNS Analyzer",
            )

            return 0

        except Exception as exc:
            print(
                f"Error: DNS analysis failed: {exc}",
                file=sys.stderr,
            )

            return 1

    # ==========================================================
    # FALLBACK
    # ==========================================================

    parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
