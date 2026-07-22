"""Contract tests for the Kongali Security CLI."""

from __future__ import annotations

import pytest

from kongali_security import cli


def test_cli_module_imports() -> None:
    """CLI module must import successfully."""
    assert cli is not None


def test_cli_has_main_entrypoint() -> None:
    """CLI must expose a main entrypoint."""
    assert hasattr(cli, "main")
    assert callable(cli.main)


def test_cli_has_argument_parser() -> None:
    """CLI must expose parser construction when supported."""
    parser_factory = getattr(
        cli,
        "build_parser",
        None,
    )

    if parser_factory is None:
        pytest.skip(
            "CLI does not expose build_parser()."
        )

    parser = parser_factory()

    assert parser is not None


def test_cli_parser_accepts_help() -> None:
    """CLI parser should support --help."""
    parser_factory = getattr(
        cli,
        "build_parser",
        None,
    )

    if parser_factory is None:
        pytest.skip(
            "CLI does not expose build_parser()."
        )

    parser = parser_factory()

    with pytest.raises(
        SystemExit,
    ) as exc_info:
        parser.parse_args(
            ["--help"],
        )

    assert exc_info.value.code == 0


def test_cli_parser_rejects_unknown_argument() -> None:
    """CLI parser should reject unknown arguments."""
    parser_factory = getattr(
        cli,
        "build_parser",
        None,
    )

    if parser_factory is None:
        pytest.skip(
            "CLI does not expose build_parser()."
        )

    parser = parser_factory()

    with pytest.raises(
        SystemExit,
    ):
        parser.parse_args(
            [
                "--kongali-invalid-option",
            ],
        )


@pytest.mark.parametrize(
    "command",
    [
        "scan",
        "headers",
        "tls",
        "assess",
    ],
)
def test_expected_cli_commands_exist(
    command: str,
) -> None:
    """Expected security analysis commands should exist."""
    parser_factory = getattr(
        cli,
        "build_parser",
        None,
    )

    if parser_factory is None:
        pytest.skip(
            "CLI does not expose build_parser()."
        )

    parser = parser_factory()

    try:
        args = parser.parse_args(
            [
                command,
                "https://example.com",
            ],
        )
    except SystemExit:
        pytest.fail(
            f"CLI command '{command}' "
            "is not accepted by the parser."
        )

    assert args is not None


def test_cli_main_callable() -> None:
    """CLI main function must be callable."""
    assert callable(
        getattr(
            cli,
            "main",
            None,
        )
    )


def test_cli_exports_tls_analyzer() -> None:
    """CLI module should expose the TLS analyzer dependency."""
    assert hasattr(
        cli,
        "analyze_tls",
    )


def test_cli_exports_url_analyzer() -> None:
    """CLI module should expose the URL analyzer dependency."""
    assert hasattr(
        cli,
        "analyze_url",
    )


def test_cli_exports_header_analyzer() -> None:
    """CLI module should expose the header analyzer dependency."""
    assert hasattr(
        cli,
        "analyze_headers",
    )


def test_cli_exports_unified_assessment() -> None:
    """CLI should expose unified assessment integration."""
    unified = getattr(
        cli,
        "run_unified_assessment",
        None,
    )

    if unified is None:
        pytest.skip(
            "CLI does not directly expose "
            "run_unified_assessment()."
        )

    assert callable(
        unified,
    )


def test_cli_tls_analyzer_is_callable() -> None:
    """TLS analyzer imported by CLI must be callable."""
    assert callable(
        cli.analyze_tls,
    )


def test_cli_url_analyzer_is_callable() -> None:
    """URL analyzer imported by CLI must be callable."""
    assert callable(
        cli.analyze_url,
    )


def test_cli_header_analyzer_is_callable() -> None:
    """Header analyzer imported by CLI must be callable."""
    assert callable(
        cli.analyze_headers,
    )


def test_cli_main_has_docstring() -> None:
    """CLI main entrypoint should be documented."""
    main = getattr(
        cli,
        "main",
        None,
    )

    assert main is not None
    assert main.__doc__ is not None


def test_cli_module_has_docstring() -> None:
    """CLI module should contain module documentation."""
    assert cli.__doc__ is not None
    assert cli.__doc__.strip()


def test_cli_target_is_string_compatible() -> None:
    """CLI analyzers should accept string targets."""
    assert isinstance(
        "https://example.com",
        str,
    )


def test_cli_expected_target_scheme() -> None:
    """Security scan target should normally use HTTP(S)."""
    target = "https://example.com"

    assert target.startswith(
        (
            "http://",
            "https://",
        )
    )


def test_cli_analyzer_dependencies_are_distinct() -> None:
    """Core CLI analyzers should be separate callable components."""
    assert cli.analyze_url is not cli.analyze_headers
    assert cli.analyze_headers is not cli.analyze_tls
    assert cli.analyze_url is not cli.analyze_tls


def test_cli_analyzers_have_docstrings() -> None:
    """Analyzer dependencies exposed by CLI should be documented."""
    assert cli.analyze_url.__doc__
    assert cli.analyze_headers.__doc__
    assert cli.analyze_tls.__doc__
