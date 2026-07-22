"""Command-line interface for Kongali Security."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

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

    # IOC command
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

    # Hash command
    subparsers.add_parser(
        "hash",
        help="Analyze a cryptographic hash.",
    )

    # DNS command
    subparsers.add_parser(
        "dns",
        help="Perform defensive DNS analysis.",
    )

    return parser


def _result_to_dict(result: Any) -> dict[str, Any]:
    """Convert an IOC analysis result to a dictionary."""
    if hasattr(result, "to_dict"):
        data = result.to_dict()
        if isinstance(data, dict):
            return data

    if isinstance(result, dict):
        return result

    if hasattr(result, "__dict__"):
        return dict(result.__dict__)

    return {"result": str(result)}


def _print_ioc_result(result: Any, output_format: str) -> None:
    """Print an IOC analysis result."""
    data = _result_to_dict(result)

    if output_format == "json":
        print(json.dumps(data, indent=2, default=str))
        return

    print("Kongali Security IOC Analyzer")
    print("─────────────────────────────")

    for key, value in data.items():
        label = key.replace("_", " ").title()
        print(f"{label:<12}: {value}")


def main() -> int:
    """Run the Kongali Security CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "ioc":
        try:
            result = analyze_ioc(args.input)
            _print_ioc_result(result, args.format)
            return 0
        except Exception as exc:
            print(
                f"Error: IOC analysis failed: {exc}",
                file=sys.stderr,
            )
            return 1

    if args.command == "hash":
        print(
            "Hash analysis is not yet implemented.",
            file=sys.stderr,
        )
        return 2

    if args.command == "dns":
        print(
            "DNS analysis is not yet implemented.",
            file=sys.stderr,
        )
        return 2

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
